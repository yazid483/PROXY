# ╔══════════════════════════════════════╗
# ║   M3SB IOS | @m3sbffxx              ║
# ║   Free Project For All               ║
# ╚══════════════════════════════════════╝
import os, sys, time, sqlite3, secrets, logging, re, asyncio, subprocess
import gzip as gzip_mod
import hashlib, base64, io, tempfile
from datetime import datetime, timezone, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes,
)

# ─── Configuration ─────────────────────────────────────────────

IP_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

def is_valid_ip(text: str) -> bool:
    return bool(IP_RE.match(text.strip()))

BOT_TOKEN = os.environ.get("M3SB_BOT_TOKEN", "")
DB_PATH   = os.environ.get("M3SB_DB_PATH",   "/opt/m3sb/m3sb.db")
OWNER_IDS = set(os.environ.get("M3SB_ADMIN_IDS", "").split(","))
LOG_DIR   = os.environ.get("M3SB_LOG_DIR",   "/opt/m3sb/logs")
DATA_DIR  = os.environ.get("M3SB_DATA_DIR",  "/opt/m3sb/data")

DURATION_OPTIONS = [
    ("⏱ 1 Day",    86400),
    ("📅 3 Days",   259200),
    ("🗓 7 Days",   604800),
    ("🗓 14 Days",  1209600),
    ("🗓 30 Days",  2592000),
    ("🗓 60 Days",  5184000),
    ("🗓 90 Days",  7776000),
]

RESELLER_MAX_DURATION = 2592000  # 30 days

PROXY_PORTS = {
    10039: {"service": "m3sb-proxy-10039", "feature": "STOMACH_ANTENNA"},
    10040: {"service": "m3sb-proxy-10040", "feature": "DRAG_HEADSHOT"},
    10042: {"service": "m3sb-proxy-10042", "feature": "CACHE_HEADSHOT"},
    10043: {"service": "m3sb-proxy-10043", "feature": "CACHE_HEADSHOT_2"},
}

MAINTENANCE_FLAG = os.path.join(os.path.dirname(DB_PATH), "maintenance.flag")

def is_maintenance_on() -> bool:
    return os.path.exists(MAINTENANCE_FLAG)

def set_maintenance(on: bool):
    if on:
        with open(MAINTENANCE_FLAG, "w") as f:
            f.write(str(int(time.time())))
        log.info("Maintenance mode ENABLED")
    else:
        if os.path.exists(MAINTENANCE_FLAG):
            os.remove(MAINTENANCE_FLAG)
        log.info("Maintenance mode DISABLED")

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "bot.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("m3sb_bot")

pending: dict[int, dict] = {}
rate_limit: dict[int, list] = {}


# ─── Database ──────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn

def cleanup_expired(conn):
    now = int(time.time())
    conn.execute(
        "UPDATE allowed_ips SET status='expired' WHERE status='active' AND expires_at > 0 AND expires_at < ?",
        (now,)
    )
    expired_ips = conn.execute(
        "SELECT ip, key_used FROM allowed_ips WHERE status='expired' AND key_used IS NOT NULL"
    ).fetchall()
    for row in expired_ips:
        conn.execute(
            "UPDATE license_keys SET status='expired' WHERE key_code=? AND status='used'",
            (row['key_used'],)
        )
    conn.commit()

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS allowed_ips (
            ip          TEXT PRIMARY KEY,
            expires_at  INTEGER DEFAULT 0,
            key_used    TEXT,
            status      TEXT DEFAULT 'active',
            created_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS license_keys (
            key_code     TEXT PRIMARY KEY,
            duration_sec INTEGER DEFAULT 2592000,
            status       TEXT DEFAULT 'unused',
            created_by   TEXT DEFAULT 'owner',
            used_by_ip   TEXT,
            used_by_uid  TEXT,
            used_at      TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS resellers (
            telegram_id  TEXT PRIMARY KEY,
            username     TEXT,
            added_by     TEXT,
            expires_at   INTEGER DEFAULT 0,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS proxy_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT DEFAULT (datetime('now')),
            client_ip  TEXT, url TEXT, action TEXT,
            feature    TEXT, status_code INTEGER
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            api_key     TEXT PRIMARY KEY,
            name        TEXT,
            created_by  TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            last_used   TEXT,
            status      TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS bot_visitors (
            telegram_id  TEXT PRIMARY KEY,
            username     TEXT,
            first_name   TEXT,
            first_seen   TEXT DEFAULT (datetime('now')),
            last_seen    TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    try:
        conn.execute("ALTER TABLE license_keys ADD COLUMN used_by_uid TEXT")
        conn.commit()
    except Exception:
        pass
    cleanup_expired(conn)
    conn.close()


# ─── Auth ──────────────────────────────────────────────────────

def is_owner(uid: int) -> bool:
    return str(uid) in OWNER_IDS

def is_reseller(uid: int) -> bool:
    conn = get_db()
    row = conn.execute(
        "SELECT expires_at FROM resellers WHERE telegram_id = ? AND expires_at > ?",
        (str(uid), int(time.time()))
    ).fetchone()
    conn.close()
    return row is not None

def get_reseller(uid: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM resellers WHERE telegram_id = ?", (str(uid),)
    ).fetchone()
    conn.close()
    return row


# ─── Utilities ─────────────────────────────────────────────────

def gen_key_code():
    p1 = secrets.token_hex(3).upper()[:5]
    p2 = secrets.token_hex(3).upper()[:5]
    p3 = secrets.token_hex(3).upper()[:5]
    return f"M3SB-IOS-{p1}-{p2}-{p3}"

def gen_api_key():
    return "M3SB-IOS-api_" + secrets.token_hex(16)

def fmt_ts(ts: int) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def duration_label(sec: int) -> str:
    for lbl, s in DURATION_OPTIONS:
        if s == sec:
            return lbl.split(" ", 1)[1]
    days = sec // 86400
    return f"{days} Days" if days else f"{sec}s"

def status_badge(status: str) -> str:
    return {"unused": "✅", "used": "🔒", "banned": "🚫", "expired": "⏳"}.get(status, "❓")

def back_kb(target="main_menu"):
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=target)]])

def check_rate_limit(uid: int) -> bool:
    now = time.time()
    if uid not in rate_limit:
        rate_limit[uid] = []
    rate_limit[uid] = [t for t in rate_limit[uid] if now - t < 60]
    return len(rate_limit[uid]) < 10

def record_key_creation(uid: int):
    rate_limit.setdefault(uid, []).append(time.time())


# ─── Proxy Control ─────────────────────────────────────────────

def proxy_status(port: int) -> str:
    service = PROXY_PORTS[port]["service"]
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "is-active", service],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"

def proxy_action(port: int, action: str) -> bool:
    service = PROXY_PORTS[port]["service"]
    try:
        result = subprocess.run(
            ["sudo", "systemctl", action, service],
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0
    except Exception:
        return False


# ─── File Conversion ───────────────────────────────────────────

def convert_to_hex_gzip(raw_data: bytes, file_type: str) -> tuple:
    if raw_data[:2] == b'\x1f\x8b':
        compressed = raw_data
        try:
            uncompressed = gzip_mod.decompress(raw_data)
        except Exception:
            uncompressed = raw_data
    else:
        uncompressed = raw_data
        buf = io.BytesIO()
        with gzip_mod.GzipFile(filename=file_type, mode='wb', fileobj=buf, mtime=0) as gz:
            gz.write(raw_data)
        compressed = buf.getvalue()

    comp_sha1 = base64.b64encode(hashlib.sha1(compressed).digest()).decode()
    uncomp_sha1 = base64.b64encode(hashlib.sha1(uncompressed).digest()).decode()
    hex_str = " ".join(f"{b:02X}" for b in compressed)
    fileinfo = f"avatar/{file_type},{len(compressed)},{comp_sha1},{len(uncompressed)},{uncomp_sha1},true"
    fileinfo_hex = " ".join(f"{b:02X}" for b in fileinfo.encode('ascii'))

    return hex_str, fileinfo_hex, len(compressed), len(uncompressed), comp_sha1, uncomp_sha1


# ─── Keyboards ─────────────────────────────────────────────────

def owner_menu_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔑 Generate Key",   callback_data="gen_key"),
            InlineKeyboardButton("📋 All Keys",        callback_data="list_keys"),
        ],
        [
            InlineKeyboardButton("🌐 Active IPs",      callback_data="list_ips"),
            InlineKeyboardButton("❌ Revoke IP",        callback_data="revoke_ip"),
        ],
        [
            InlineKeyboardButton("🚫 Ban Key",         callback_data="ban_key"),
            InlineKeyboardButton("🗑 Delete Key",      callback_data="delete_key"),
        ],
        [
            InlineKeyboardButton("👥 Add Reseller",    callback_data="add_reseller"),
            InlineKeyboardButton("📜 Reseller List",   callback_data="list_resellers"),
        ],
        [
            InlineKeyboardButton("🚫 Remove Reseller", callback_data="remove_reseller"),
            InlineKeyboardButton("📊 Statistics",       callback_data="stats"),
        ],
        [
            InlineKeyboardButton("📦 Bulk Generate",   callback_data="bulk_key"),
            InlineKeyboardButton("🔐 API Keys",        callback_data="api_keys"),
        ],
        [
            InlineKeyboardButton("🖥 Proxy Control",   callback_data="proxy_control"),
            InlineKeyboardButton("📁 Convert File",    callback_data="convert_file"),
        ],
    ])

def reseller_menu_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔑 Generate Key",  callback_data="gen_key"),
            InlineKeyboardButton("📋 My Keys",        callback_data="my_keys"),
        ],
        [
            InlineKeyboardButton("🚫 Ban Key",        callback_data="ban_key"),
            InlineKeyboardButton("🗑 Delete Key",     callback_data="delete_key"),
        ],
        [InlineKeyboardButton("📊 My Stats",          callback_data="my_stats")],
    ])

def duration_kb(back_target="main_menu", max_sec=None):
    keyboard = []
    row = []
    for label, secs in DURATION_OPTIONS:
        if max_sec and secs > max_sec:
            continue
        row.append(InlineKeyboardButton(label, callback_data=f"newkey|{secs}"))
        if len(row) == 2:
            keyboard.append(row); row = []
    if row:
        keyboard.append(row)
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data=back_target)])
    return InlineKeyboardMarkup(keyboard)

def bulk_duration_kb():
    keyboard = []
    row = []
    for label, secs in DURATION_OPTIONS:
        row.append(InlineKeyboardButton(label, callback_data=f"bulkkey|{secs}"))
        if len(row) == 2:
            keyboard.append(row); row = []
    if row:
        keyboard.append(row)
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
    return InlineKeyboardMarkup(keyboard)

def reseller_duration_kb():
    keyboard = []
    row = []
    for label, secs in DURATION_OPTIONS:
        row.append(InlineKeyboardButton(label, callback_data=f"rs_dur|{secs}"))
        if len(row) == 2:
            keyboard.append(row); row = []
    if row:
        keyboard.append(row)
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
    return InlineKeyboardMarkup(keyboard)

def proxy_control_kb():
    rows = []
    # Maintenance toggle
    maint = is_maintenance_on()
    maint_label = "🔧 Maintenance: ON" if maint else "🔧 Maintenance: OFF"
    rows.append([InlineKeyboardButton(maint_label, callback_data="toggle_maintenance")])
    # Port buttons
    ports = list(PROXY_PORTS.keys())
    for i in range(0, len(ports), 2):
        row = []
        for p in ports[i:i + 2]:
            st = proxy_status(p)
            emoji = "🟢" if st == "active" else "🔴"
            row.append(InlineKeyboardButton(f"{emoji} Port {p}", callback_data=f"port|{p}"))
        rows.append(row)
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
    return InlineKeyboardMarkup(rows)

def port_control_kb(port):
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("▶️ Start",   callback_data=f"proxy_start|{port}"),
            InlineKeyboardButton("⏹ Stop",    callback_data=f"proxy_stop|{port}"),
        ],
        [
            InlineKeyboardButton("🔄 Restart", callback_data=f"proxy_restart|{port}"),
            InlineKeyboardButton("📊 Status",  callback_data=f"proxy_status|{port}"),
        ],
        [
            InlineKeyboardButton("📝 Change Hex",     callback_data=f"change_hex|{port}"),
            InlineKeyboardButton("📋 Change Fileinfo", callback_data=f"change_fi|{port}"),
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="proxy_control")],
    ])

def api_keys_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔑 Generate API Key", callback_data="gen_api_key"),
            InlineKeyboardButton("📋 List API Keys",    callback_data="list_api_keys"),
        ],
        [InlineKeyboardButton("🚫 Revoke API Key",      callback_data="revoke_api_key")],
        [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
    ])

def convert_file_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📁 assetindexer", callback_data="conv|assetindexer"),
            InlineKeyboardButton("📁 cache_res",    callback_data="conv|cache_res"),
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="main_menu")],
    ])


# ─── Command Handlers ──────────────────────────────────────────

def track_visitor(user):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO bot_visitors (telegram_id, username, first_name, last_seen) "
            "VALUES (?, ?, ?, datetime('now')) "
            "ON CONFLICT(telegram_id) DO UPDATE SET "
            "username=excluded.username, first_name=excluded.first_name, last_seen=datetime('now')",
            (str(user.id), user.username or '', user.first_name or ''),
        )
        conn.commit(); conn.close()
    except Exception:
        pass

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    track_visitor(update.effective_user)
    pending.pop(uid, None)

    if is_owner(uid):
        await update.message.reply_text(
            "👑 *M3SB Proxy Manager*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Welcome, Owner! Choose an option:",
            parse_mode="Markdown",
            reply_markup=owner_menu_kb(),
        )
    elif is_reseller(uid):
        rs = get_reseller(uid)
        await update.message.reply_text(
            "🤝 *Reseller Panel — M3SB*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"Welcome! Your access expires: `{fmt_ts(rs['expires_at'])}`\n"
            "Choose an option:",
            parse_mode="Markdown",
            reply_markup=reseller_menu_kb(),
        )
    else:
        await update.message.reply_text(
            "👋 *Welcome to M3SB Proxy*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Send your key to activate access.\n"
            "_Example:_ `M3SB-IOS-XXXXX-XXXXX-XXXXX`",
            parse_mode="Markdown",
        )


async def reset_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid) and not is_reseller(uid):
        await update.message.reply_text("🚫 This command is for owners and resellers only.")
        return
    if not ctx.args:
        await update.message.reply_text(
            "⚠️ Usage: `/reset M3SB-IOS-XXXXX-XXXXX-XXXXX`",
            parse_mode="Markdown",
        )
        return
    key_code = ctx.args[0].strip()
    conn = get_db()
    row = conn.execute(
        "SELECT key_code, duration_sec, status, used_by_ip, created_by FROM license_keys WHERE key_code = ?",
        (key_code,)
    ).fetchone()
    if not row:
        conn.close()
        await update.message.reply_text("❌ Key not found.", parse_mode="Markdown")
        return
    if is_reseller(uid) and not is_owner(uid) and row["created_by"] != str(uid):
        conn.close()
        await update.message.reply_text("⛔ You can only reset keys you created.", parse_mode="Markdown")
        return
    if row["status"] not in ("used", "expired"):
        conn.close()
        await update.message.reply_text(
            f"⚠️ Key is `{row['status']}`, nothing to reset.",
            parse_mode="Markdown",
        )
        return
    old_ip = row["used_by_ip"]
    if old_ip:
        ip_row = conn.execute(
            "SELECT expires_at FROM allowed_ips WHERE ip = ? AND key_used = ?",
            (old_ip, key_code)
        ).fetchone()
        remaining = ip_row["expires_at"] if ip_row else int(time.time()) + row["duration_sec"]
        conn.execute("DELETE FROM allowed_ips WHERE ip = ? AND key_used = ?", (old_ip, key_code))
    else:
        remaining = int(time.time()) + row["duration_sec"]
    conn.execute(
        "UPDATE license_keys SET status='unused', used_by_ip=NULL, used_at=NULL, duration_sec=? WHERE key_code=?",
        (remaining - int(time.time()), key_code),
    )
    conn.commit(); conn.close()
    log.info(f"Key reset: {key_code} old_ip={old_ip} by {uid}")
    await update.message.reply_text(
        f"🔄 *Key Reset*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🔑  Key     : `{key_code}`\n"
        f"🌐  Old IP  : `{old_ip or '—'}` removed\n\n"
        f"_Key is now available for reuse._",
        parse_mode="Markdown",
    )


async def check_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "⚠️ Usage: `/check M3SB-IOS-XXXXX-XXXXX-XXXXX`",
            parse_mode="Markdown",
        )
        return
    key_code = ctx.args[0].strip()
    conn = get_db()
    cleanup_expired(conn)
    row = conn.execute(
        "SELECT key_code, duration_sec, status, used_by_ip, used_at, created_at FROM license_keys WHERE key_code = ?",
        (key_code,)
    ).fetchone()
    if not row:
        conn.close()
        await update.message.reply_text("❌ Key not found.", parse_mode="Markdown")
        return
    ip_info = ""
    if row["used_by_ip"]:
        ip_row = conn.execute(
            "SELECT expires_at, status FROM allowed_ips WHERE ip = ?",
            (row["used_by_ip"],)
        ).fetchone()
        if ip_row:
            ip_info = (
                f"🌐  IP      : `{row['used_by_ip']}`\n"
                f"📅  Expires : {fmt_ts(ip_row['expires_at'])}\n"
                f"🔒  Status  : `{ip_row['status']}`\n"
            )
        else:
            ip_info = f"🌐  IP      : `{row['used_by_ip']}` _(removed)_\n"
    conn.close()
    await update.message.reply_text(
        f"🔍 *Key Details*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🔑  Key      : `{row['key_code']}`\n"
        f"📊  Status   : `{row['status']}`\n"
        f"⏱  Duration : {duration_label(row['duration_sec'])}\n"
        f"{ip_info}",
        parse_mode="Markdown",
    )


# ─── Button Handler ────────────────────────────────────────────

async def button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid  = q.from_user.id
    data = q.data

    owner    = is_owner(uid)
    reseller = is_reseller(uid) if not owner else False

    # ── Main Menu ──
    if data == "main_menu":
        pending.pop(uid, None)
        if owner:
            await q.edit_message_text(
                "👑 *M3SB Proxy Manager*\n"
                "━━━━━━━━━━━━━━━━━━━━\n"
                "Choose an option:",
                parse_mode="Markdown",
                reply_markup=owner_menu_kb(),
            )
        elif reseller:
            rs = get_reseller(uid)
            await q.edit_message_text(
                "🤝 *Reseller Panel — M3SB*\n"
                "━━━━━━━━━━━━━━━━━━━━\n"
                f"Your access expires: `{fmt_ts(rs['expires_at'])}`",
                parse_mode="Markdown",
                reply_markup=reseller_menu_kb(),
            )
        return

    if not owner and not reseller:
        await q.edit_message_text("⛔ Access denied.")
        return

    # ── Generate Key ──
    if data == "gen_key":
        if not owner and not check_rate_limit(uid):
            await q.edit_message_text(
                "⏳ *Rate Limit*\n━━━━━━━━━━━━\nToo many keys created. Wait 1 minute.",
                parse_mode="Markdown", reply_markup=back_kb(),
            )
            return
        max_sec = RESELLER_MAX_DURATION if (reseller and not owner) else None
        await q.edit_message_text(
            "🔑 *Generate New Key*\n━━━━━━━━━━━━\nSelect duration:",
            parse_mode="Markdown",
            reply_markup=duration_kb(max_sec=max_sec),
        )

    elif data.startswith("newkey|"):
        secs = int(data.split("|")[1])
        if not owner and secs > RESELLER_MAX_DURATION:
            await q.edit_message_text("⛔ Max duration for resellers is 30 days.", reply_markup=back_kb())
            return
        if not owner and not check_rate_limit(uid):
            await q.edit_message_text(
                "⏳ *Rate Limit*\n━━━━━━━━━━━━\nToo many keys created. Wait 1 minute.",
                parse_mode="Markdown", reply_markup=back_kb(),
            )
            return
        code = gen_key_code()
        creator = str(uid)
        conn = get_db()
        conn.execute(
            "INSERT INTO license_keys (key_code, duration_sec, created_by) VALUES (?, ?, ?)",
            (code, secs, creator),
        )
        conn.commit(); conn.close()
        if not owner:
            record_key_creation(uid)
        log.info(f"Key created: {code} dur={secs}s by {uid}")
        await q.edit_message_text(
            f"✅ *Key Created*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🔑  `{code}`\n"
            f"⏱  Duration : {duration_label(secs)}\n"
            f"📌  Status   : Unused\n\n"
            f"_Share this key with the user._",
            parse_mode="Markdown",
            reply_markup=back_kb(),
        )

    # ── Bulk Generate ──
    elif data == "bulk_key":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        pending[uid] = {"action": "bulk_count"}
        await q.edit_message_text(
            "📦 *Bulk Generate*\n━━━━━━━━━━━━\nHow many keys? (1–100):",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    elif data.startswith("bulkkey|"):
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        secs = int(data.split("|")[1])
        state = pending.get(uid, {})
        count = state.get("bulk_count", 1)
        pending.pop(uid, None)
        creator = str(uid)
        conn = get_db()
        keys = []
        for _ in range(count):
            code = gen_key_code()
            conn.execute(
                "INSERT INTO license_keys (key_code, duration_sec, created_by) VALUES (?, ?, ?)",
                (code, secs, creator),
            )
            keys.append(code)
        conn.commit(); conn.close()
        log.info(f"Bulk keys created: {count} dur={secs}s by {uid}")
        keys_text = "\n".join([f"`{k}`" for k in keys])
        await q.edit_message_text(
            f"✅ *Bulk Keys Created*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🔢  Count    : *{count}*\n"
            f"⏱  Duration : {duration_label(secs)}\n\n"
            f"{keys_text}",
            parse_mode="Markdown",
            reply_markup=back_kb(),
        )

    # ── List Keys ──
    elif data == "list_keys":
        conn = get_db()
        if owner:
            rows = conn.execute(
                "SELECT key_code, duration_sec, status, used_by_ip, created_by, created_at "
                "FROM license_keys ORDER BY created_at DESC LIMIT 25"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT key_code, duration_sec, status, used_by_ip, created_by, created_at "
                "FROM license_keys WHERE created_by = ? ORDER BY created_at DESC LIMIT 25",
                (str(uid),)
            ).fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("📋 No keys found.", reply_markup=back_kb())
            return
        lines = []
        for r in rows:
            badge   = status_badge(r["status"])
            ip_info = f"\n     └ IP: `{r['used_by_ip']}`" if r["used_by_ip"] else ""
            by      = f"  _(by {r['created_by']})_" if owner else ""
            lines.append(f"{badge}  `{r['key_code']}`\n     {duration_label(r['duration_sec'])}{ip_info}{by}")
        await q.edit_message_text(
            "📋 *Keys*\n━━━━━━━━━━━━━━━━\n\n" + "\n\n".join(lines),
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    elif data == "my_keys":
        conn = get_db()
        rows = conn.execute(
            "SELECT key_code, duration_sec, status, used_by_ip FROM license_keys "
            "WHERE created_by = ? ORDER BY created_at DESC LIMIT 25",
            (str(uid),)
        ).fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("📋 You have no keys yet.", reply_markup=back_kb())
            return
        lines = []
        for r in rows:
            badge   = status_badge(r["status"])
            ip_info = f"\n     └ IP: `{r['used_by_ip']}`" if r["used_by_ip"] else ""
            lines.append(f"{badge}  `{r['key_code']}`\n     {duration_label(r['duration_sec'])}{ip_info}")
        await q.edit_message_text(
            "📋 *My Keys*\n━━━━━━━━━━━━━━━━\n\n" + "\n\n".join(lines),
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Active IPs ──
    elif data == "list_ips":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        conn = get_db()
        cleanup_expired(conn)
        now = int(time.time())
        rows = conn.execute(
            "SELECT ip, expires_at, key_used FROM allowed_ips WHERE status='active' AND expires_at > ? ORDER BY expires_at DESC",
            (now,)
        ).fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("🌐 No active IPs.", reply_markup=back_kb())
            return
        lines = [
            f"🟢  `{r['ip']}`\n     Expires: {fmt_ts(r['expires_at'])}\n     Key: `{r['key_used'] or '—'}`"
            for r in rows
        ]
        await q.edit_message_text(
            "🌐 *Active IPs*\n━━━━━━━━━━━━━━━━\n\n" + "\n\n".join(lines),
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Revoke IP ──
    elif data == "revoke_ip":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        pending[uid] = {"action": "revoke_ip"}
        await q.edit_message_text(
            "❌ *Revoke IP*\n━━━━━━━━━━━━\nSend the IP to revoke:",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Ban Key ──
    elif data == "ban_key":
        pending[uid] = {"action": "ban_key"}
        await q.edit_message_text(
            "🚫 *Ban Key*\n━━━━━━━━━━━━\n"
            "Send the key code:\n_Example:_ `M3SB-IOS-XXXXX-XXXXX-XXXXX`",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Delete Key ──
    elif data == "delete_key":
        pending[uid] = {"action": "delete_key"}
        await q.edit_message_text(
            "🗑 *Delete Key*\n━━━━━━━━━━━━\n"
            "Send the key code:\n_Example:_ `M3SB-IOS-XXXXX-XXXXX-XXXXX`",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Add Reseller ──
    elif data == "add_reseller":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        pending[uid] = {"action": "add_reseller_id"}
        await q.edit_message_text(
            "👥 *Add Reseller*\n"
            "━━━━━━━━━━━━━━━━\n"
            "📌 Send the person's *Telegram ID*\n"
            "_Example:_ `123456789`",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    elif data.startswith("rs_dur|"):
        secs  = int(data.split("|")[1])
        state = pending.get(uid, {})
        rs_id = state.get("rs_id")
        if not rs_id:
            await q.edit_message_text("⚠️ Session expired. Try again.", reply_markup=back_kb())
            return
        pending.pop(uid, None)
        expires_at = int(time.time()) + secs
        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO resellers (telegram_id, added_by, expires_at) VALUES (?, ?, ?)",
            (str(rs_id), str(uid), expires_at),
        )
        conn.commit(); conn.close()
        log.info(f"Reseller added: {rs_id} dur={secs}s by owner {uid}")

        try:
            await ctx.bot.send_message(
                chat_id=rs_id,
                text=(
                    "🎉 *You are now a Reseller on M3SB Proxy*\n"
                    "━━━━━━━━━━━━━━━━━━━━\n"
                    f"✅ Account activated as reseller\n"
                    f"📅 Duration : {duration_label(secs)}\n"
                    f"⏰ Expires  : `{fmt_ts(expires_at)}`\n\n"
                    "You can now:\n"
                    "• Generate keys and share them with users\n"
                    "• Manage your own keys only\n\n"
                    "Type /start to begin 🚀"
                ),
                parse_mode="Markdown",
            )
            notify_status = "✅ Reseller notified"
        except Exception:
            notify_status = "⚠️ Could not notify (reseller must start the bot first)"

        await q.edit_message_text(
            f"✅ *Reseller Added*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🆔 ID       : `{rs_id}`\n"
            f"📅 Duration : {duration_label(secs)}\n"
            f"⏰ Expires  : `{fmt_ts(expires_at)}`\n"
            f"{notify_status}",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── List Resellers ──
    elif data == "list_resellers":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        conn = get_db()
        rows = conn.execute(
            "SELECT telegram_id, username, expires_at, created_at FROM resellers ORDER BY expires_at DESC"
        ).fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("👥 No resellers found.", reply_markup=back_kb())
            return
        now = int(time.time())
        lines = []
        for r in rows:
            active = "🟢" if r["expires_at"] > now else "🔴"
            lines.append(
                f"{active}  `{r['telegram_id']}`\n"
                f"     Expires: {fmt_ts(r['expires_at'])}"
            )
        await q.edit_message_text(
            "👥 *Resellers*\n━━━━━━━━━━━━━━━━\n\n" + "\n\n".join(lines),
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Remove Reseller ──
    elif data == "remove_reseller":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        pending[uid] = {"action": "remove_reseller"}
        await q.edit_message_text(
            "🚫 *Remove Reseller*\n━━━━━━━━━━━━\n"
            "Send the reseller's *Telegram ID*:",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Statistics ──
    elif data == "stats":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        conn = get_db()
        now = int(time.time())
        active_ips  = conn.execute("SELECT COUNT(*) FROM allowed_ips WHERE status='active' AND expires_at > ?", (now,)).fetchone()[0]
        total_keys  = conn.execute("SELECT COUNT(*) FROM license_keys").fetchone()[0]
        unused_keys = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='unused'").fetchone()[0]
        used_keys   = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='used'").fetchone()[0]
        banned_keys = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='banned'").fetchone()[0]
        expired_keys = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='expired'").fetchone()[0]
        total_rs    = conn.execute("SELECT COUNT(*) FROM resellers").fetchone()[0]
        active_rs   = conn.execute("SELECT COUNT(*) FROM resellers WHERE expires_at > ?", (now,)).fetchone()[0]
        reqs_24h    = conn.execute(
            "SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= datetime('now','-1 day')"
        ).fetchone()[0]
        reqs_7d     = conn.execute(
            "SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= datetime('now','-7 days')"
        ).fetchone()[0]
        reqs_30d    = conn.execute(
            "SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= datetime('now','-30 days')"
        ).fetchone()[0]
        reqs_total  = conn.execute("SELECT COUNT(*) FROM proxy_logs").fetchone()[0]
        keys_7d     = conn.execute(
            "SELECT COUNT(*) FROM license_keys WHERE created_at >= datetime('now','-7 days')"
        ).fetchone()[0]
        keys_30d    = conn.execute(
            "SELECT COUNT(*) FROM license_keys WHERE created_at >= datetime('now','-30 days')"
        ).fetchone()[0]
        # Bot visitors
        visitors_total = conn.execute("SELECT COUNT(*) FROM bot_visitors").fetchone()[0]
        visitors_today = conn.execute(
            "SELECT COUNT(*) FROM bot_visitors WHERE last_seen >= datetime('now','-1 day')"
        ).fetchone()[0]
        visitors_7d = conn.execute(
            "SELECT COUNT(*) FROM bot_visitors WHERE last_seen >= datetime('now','-7 days')"
        ).fetchone()[0]
        visitors_30d = conn.execute(
            "SELECT COUNT(*) FROM bot_visitors WHERE last_seen >= datetime('now','-30 days')"
        ).fetchone()[0]
        conn.close()
        await q.edit_message_text(
            "📊 *Statistics*\n"
            "━━━━━━━━━━━━━━━━\n\n"
            "👤 *Bot Users*\n"
            f"     Total    : `{visitors_total}`\n"
            f"     Monthly  : `{visitors_30d}`\n"
            f"     Weekly   : `{visitors_7d}`\n"
            f"     Today    : `{visitors_today}`\n\n"
            "🔑 *Keys*\n"
            f"     Total    : `{total_keys}`\n"
            f"     Unused   : `{unused_keys}`\n"
            f"     Used     : `{used_keys}`\n"
            f"     Banned   : `{banned_keys}`\n"
            f"     Expired  : `{expired_keys}`\n\n"
            "📈 *Keys Created*\n"
            f"     7 Days   : `{keys_7d}`\n"
            f"     30 Days  : `{keys_30d}`\n\n"
            f"🌐  Active IPs : `{active_ips}`\n"
            f"👥  Resellers  : `{active_rs}/{total_rs}`\n\n"
            "📡 *Proxy Requests*\n"
            f"     24h      : `{reqs_24h}`\n"
            f"     7 Days   : `{reqs_7d}`\n"
            f"     30 Days  : `{reqs_30d}`\n"
            f"     Total    : `{reqs_total}`",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    elif data == "my_stats":
        conn = get_db()
        total  = conn.execute("SELECT COUNT(*) FROM license_keys WHERE created_by=?", (str(uid),)).fetchone()[0]
        unused = conn.execute("SELECT COUNT(*) FROM license_keys WHERE created_by=? AND status='unused'", (str(uid),)).fetchone()[0]
        used   = conn.execute("SELECT COUNT(*) FROM license_keys WHERE created_by=? AND status='used'", (str(uid),)).fetchone()[0]
        banned = conn.execute("SELECT COUNT(*) FROM license_keys WHERE created_by=? AND status='banned'", (str(uid),)).fetchone()[0]
        conn.close()
        rs = get_reseller(uid)
        await q.edit_message_text(
            "📊 *My Stats*\n"
            "━━━━━━━━━━━━━━━━\n"
            f"⏰  Expires    : `{fmt_ts(rs['expires_at'])}`\n"
            f"🔑  Total Keys : `{total}`\n"
            f"✅  Unused     : `{unused}`\n"
            f"🔒  Used       : `{used}`\n"
            f"🚫  Banned     : `{banned}`",
            parse_mode="Markdown", reply_markup=back_kb(),
        )

    # ── Proxy Control ──
    elif data == "proxy_control":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        maint = is_maintenance_on()
        maint_text = "🔧 Maintenance: *ON* — all users see maintenance message" if maint else "🔧 Maintenance: *OFF*"
        await q.edit_message_text(
            f"🖥 *Proxy Control*\n━━━━━━━━━━━━━━━━\n{maint_text}\n\nSelect a port:",
            parse_mode="Markdown",
            reply_markup=proxy_control_kb(),
        )

    elif data == "toggle_maintenance":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        current = is_maintenance_on()
        set_maintenance(not current)
        new_state = is_maintenance_on()
        maint_text = "🔧 Maintenance: *ON* — all users see maintenance message" if new_state else "🔧 Maintenance: *OFF*"
        await q.edit_message_text(
            f"🖥 *Proxy Control*\n━━━━━━━━━━━━━━━━\n{maint_text}\n\nSelect a port:",
            parse_mode="Markdown",
            reply_markup=proxy_control_kb(),
        )

    elif data.startswith("port|"):
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        port = int(data.split("|")[1])
        if port not in PROXY_PORTS:
            await q.edit_message_text("⚠️ Unknown port.", reply_markup=back_kb()); return
        info = PROXY_PORTS[port]
        st = proxy_status(port)
        emoji = "🟢" if st == "active" else "🔴"
        await q.edit_message_text(
            f"🖥 *Port {port}*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"📁 Feature : `{info['feature']}`\n"
            f"{emoji} Status  : `{st}`",
            parse_mode="Markdown",
            reply_markup=port_control_kb(port),
        )

    elif data.startswith("proxy_start|"):
        if not owner:
            return
        port = int(data.split("|")[1])
        ok = proxy_action(port, "start")
        st = proxy_status(port)
        msg = f"▶️ Port {port}: {'Started ✅' if ok else 'Failed ❌'}\nStatus: `{st}`"
        await q.edit_message_text(msg, parse_mode="Markdown", reply_markup=port_control_kb(port))

    elif data.startswith("proxy_stop|"):
        if not owner:
            return
        port = int(data.split("|")[1])
        ok = proxy_action(port, "stop")
        st = proxy_status(port)
        msg = f"⏹ Port {port}: {'Stopped ✅' if ok else 'Failed ❌'}\nStatus: `{st}`"
        await q.edit_message_text(msg, parse_mode="Markdown", reply_markup=port_control_kb(port))

    elif data.startswith("proxy_restart|"):
        if not owner:
            return
        port = int(data.split("|")[1])
        ok = proxy_action(port, "restart")
        st = proxy_status(port)
        msg = f"🔄 Port {port}: {'Restarted ✅' if ok else 'Failed ❌'}\nStatus: `{st}`"
        await q.edit_message_text(msg, parse_mode="Markdown", reply_markup=port_control_kb(port))

    elif data.startswith("proxy_status|"):
        if not owner:
            return
        port = int(data.split("|")[1])
        info = PROXY_PORTS[port]
        st = proxy_status(port)
        emoji = "🟢" if st == "active" else "🔴"
        feature_dir = os.path.join(DATA_DIR, info["feature"])
        files = os.listdir(feature_dir) if os.path.exists(feature_dir) else []
        files_str = ", ".join(files) if files else "empty"
        await q.edit_message_text(
            f"📊 *Port {port} Status*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"📁 Feature : `{info['feature']}`\n"
            f"{emoji} Status  : `{st}`\n"
            f"📄 Files   : `{files_str}`",
            parse_mode="Markdown",
            reply_markup=port_control_kb(port),
        )

    elif data.startswith("change_hex|"):
        if not owner:
            return
        port = int(data.split("|")[1])
        pending[uid] = {"action": "upload_hex", "port": port}
        await q.edit_message_text(
            f"📝 *Change Hex — Port {port}*\n━━━━━━━━━━━━\n"
            f"Send the new hex file (`.txt`):",
            parse_mode="Markdown",
            reply_markup=back_kb("proxy_control"),
        )

    elif data.startswith("change_fi|"):
        if not owner:
            return
        port = int(data.split("|")[1])
        pending[uid] = {"action": "upload_fileinfo", "port": port}
        await q.edit_message_text(
            f"📋 *Change Fileinfo — Port {port}*\n━━━━━━━━━━━━\n"
            f"Send the new fileinfo file (`.txt`):",
            parse_mode="Markdown",
            reply_markup=back_kb("proxy_control"),
        )

    # ── API Keys ──
    elif data == "api_keys":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        await q.edit_message_text(
            "🔐 *API Key Management*\n━━━━━━━━━━━━━━━━\n"
            "Manage API keys for `m3sbios.com`:",
            parse_mode="Markdown",
            reply_markup=api_keys_kb(),
        )

    elif data == "gen_api_key":
        if not owner:
            return
        key = gen_api_key()
        conn = get_db()
        conn.execute(
            "INSERT INTO api_keys (api_key, created_by) VALUES (?, ?)",
            (key, str(uid)),
        )
        conn.commit(); conn.close()
        log.info(f"API key generated by {uid}")
        await q.edit_message_text(
            f"🔐 *API Key Generated*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🔑  `{key}`\n\n"
            f"_Use this key in the `X-API-Key` header._\n"
            f"_Base URL:_ `https://m3sbios.com/api/v1`",
            parse_mode="Markdown",
            reply_markup=back_kb("api_keys"),
        )

    elif data == "list_api_keys":
        if not owner:
            return
        conn = get_db()
        rows = conn.execute(
            "SELECT api_key, status, created_at FROM api_keys ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("🔐 No API keys found.", reply_markup=back_kb("api_keys"))
            return
        lines = []
        for r in rows:
            emoji = "🟢" if r["status"] == "active" else "🔴"
            short = r["api_key"][:20] + "..."
            lines.append(f"{emoji} `{short}`")
        await q.edit_message_text(
            "🔐 *API Keys*\n━━━━━━━━━━━━━━━━\n\n" + "\n".join(lines),
            parse_mode="Markdown",
            reply_markup=back_kb("api_keys"),
        )

    elif data == "revoke_api_key":
        if not owner:
            return
        pending[uid] = {"action": "revoke_api_key"}
        await q.edit_message_text(
            "🚫 *Revoke API Key*\n━━━━━━━━━━━━\n"
            "Send the API key to revoke:",
            parse_mode="Markdown",
            reply_markup=back_kb("api_keys"),
        )

    # ── Convert File ──
    elif data == "convert_file":
        if not owner:
            await q.edit_message_text("⛔ Owner only."); return
        await q.edit_message_text(
            "📁 *Convert File to Hex*\n━━━━━━━━━━━━━━━━\n"
            "Select the file type:",
            parse_mode="Markdown",
            reply_markup=convert_file_kb(),
        )

    elif data.startswith("conv|"):
        if not owner:
            return
        file_type = data.split("|")[1]
        pending[uid] = {"action": "convert_file", "file_type": file_type}
        await q.edit_message_text(
            f"📁 *Convert to {file_type}*\n━━━━━━━━━━━━\n"
            f"Send the binary file to convert:",
            parse_mode="Markdown",
            reply_markup=back_kb("convert_file"),
        )


# ─── Text Handler ──────────────────────────────────────────────

async def text_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid      = update.effective_user.id
    track_visitor(update.effective_user)
    text     = update.message.text.strip()
    owner    = is_owner(uid)
    reseller = is_reseller(uid) if not owner else False
    state    = pending.get(uid, {})
    action   = state.get("action")

    # ── Revoke IP ──
    if owner and action == "revoke_ip":
        pending.pop(uid, None)
        conn = get_db()
        row = conn.execute("SELECT ip FROM allowed_ips WHERE ip = ?", (text,)).fetchone()
        if row:
            conn.execute("DELETE FROM allowed_ips WHERE ip = ?", (text,))
            conn.commit()
            msg = f"❌ *IP Revoked*\n`{text}`"
        else:
            msg = f"⚠️ IP `{text}` not found."
        conn.close()
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_kb())
        return

    # ── Bulk Count ──
    if owner and action == "bulk_count":
        try:
            count = int(text)
            if count < 1 or count > 100:
                await update.message.reply_text("⚠️ Enter a number between 1 and 100.", reply_markup=back_kb())
                return
        except ValueError:
            await update.message.reply_text("⚠️ Send a valid number (1–100).", reply_markup=back_kb())
            return
        pending[uid] = {"action": "bulk_duration", "bulk_count": count}
        await update.message.reply_text(
            f"📦 *Bulk Generate: {count} Keys*\n━━━━━━━━━━━━\nSelect duration:",
            parse_mode="Markdown",
            reply_markup=bulk_duration_kb(),
        )
        return

    # ── Ban Key ──
    if (owner or reseller) and action == "ban_key":
        pending.pop(uid, None)
        conn = get_db()
        row = conn.execute(
            "SELECT key_code, status, used_by_ip, created_by FROM license_keys WHERE key_code = ?", (text,)
        ).fetchone()
        if not row:
            msg = f"⚠️ Key `{text}` not found."
        elif reseller and row["created_by"] != str(uid):
            msg = "⛔ You can only ban keys you created."
        elif row["status"] == "banned":
            msg = f"⚠️ Key `{text}` is already banned."
        else:
            if row["used_by_ip"]:
                conn.execute(
                    "UPDATE allowed_ips SET status='banned', expires_at=0 WHERE ip = ?",
                    (row["used_by_ip"],)
                )
            conn.execute("UPDATE license_keys SET status='banned' WHERE key_code=?", (text,))
            conn.commit()
            ip_note = f"\n🌐 IP `{row['used_by_ip']}` was also revoked." if row["used_by_ip"] else ""
            msg = f"🚫 *Key Banned*\n`{text}`{ip_note}"
            log.info(f"Key banned: {text} by {uid}")
        conn.close()
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_kb())
        return

    # ── Delete Key ──
    if (owner or reseller) and action == "delete_key":
        pending.pop(uid, None)
        conn = get_db()
        row = conn.execute(
            "SELECT key_code, used_by_ip, created_by FROM license_keys WHERE key_code = ?", (text,)
        ).fetchone()
        if not row:
            msg = f"⚠️ Key `{text}` not found."
        elif reseller and row["created_by"] != str(uid):
            msg = "⛔ You can only delete keys you created."
        else:
            if row["used_by_ip"]:
                conn.execute("DELETE FROM allowed_ips WHERE ip = ?", (row["used_by_ip"],))
            conn.execute("DELETE FROM license_keys WHERE key_code = ?", (text,))
            conn.commit()
            ip_note = f"\n🌐 IP `{row['used_by_ip']}` was also revoked." if row["used_by_ip"] else ""
            msg = f"🗑 *Key Deleted*\n`{text}`{ip_note}"
            log.info(f"Key deleted: {text} by {uid}")
        conn.close()
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_kb())
        return

    # ── Add Reseller ID ──
    if owner and action == "add_reseller_id":
        if not text.isdigit():
            await update.message.reply_text(
                "⚠️ Send a valid numeric ID.\n_Example:_ `123456789`",
                parse_mode="Markdown"
            )
            return
        pending[uid] = {"action": "add_reseller_dur", "rs_id": int(text)}
        await update.message.reply_text(
            f"👥 ID: `{text}`\n\n📅 Select reseller duration:",
            parse_mode="Markdown",
            reply_markup=reseller_duration_kb(),
        )
        return

    # ── Remove Reseller ──
    if owner and action == "remove_reseller":
        pending.pop(uid, None)
        if not text.isdigit():
            await update.message.reply_text("⚠️ Send a valid numeric ID.")
            return
        conn = get_db()
        row = conn.execute("SELECT telegram_id FROM resellers WHERE telegram_id = ?", (text,)).fetchone()
        if row:
            conn.execute("DELETE FROM resellers WHERE telegram_id = ?", (text,))
            conn.commit()
            msg = f"🚫 *Reseller Removed*\nID: `{text}`"
        else:
            msg = f"⚠️ ID `{text}` not found in resellers list."
        conn.close()
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_kb())
        return

    # ── Revoke API Key ──
    if owner and action == "revoke_api_key":
        pending.pop(uid, None)
        conn = get_db()
        row = conn.execute("SELECT api_key FROM api_keys WHERE api_key = ?", (text,)).fetchone()
        if row:
            conn.execute("UPDATE api_keys SET status='revoked' WHERE api_key = ?", (text,))
            conn.commit()
            msg = "🚫 *API Key Revoked*"
        else:
            msg = "⚠️ API key not found."
        conn.close()
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_kb("api_keys"))
        return

    # ── Update IP ──
    if action == "update_ip":
        key_code = state.get("key_code")
        old_ip = state.get("old_ip")
        expires_at = state.get("expires_at")
        ip = text.strip()
        if not is_valid_ip(ip):
            await update.message.reply_text(
                "⚠️ Invalid IP address.\n_Example:_ `105.74.64.140`",
                parse_mode="Markdown",
            )
            return
        pending.pop(uid, None)
        conn = get_db()
        conn.execute("DELETE FROM allowed_ips WHERE ip = ? AND key_used = ?", (old_ip, key_code))
        conn.execute(
            "INSERT OR REPLACE INTO allowed_ips (ip, expires_at, key_used, status) VALUES (?, ?, ?, 'active')",
            (ip, expires_at, key_code),
        )
        conn.execute("UPDATE license_keys SET used_by_ip=? WHERE key_code=?", (ip, key_code))
        conn.commit(); conn.close()
        log.info(f"IP updated: {old_ip} -> {ip} key={key_code} user={uid}")
        await update.message.reply_text(
            f"✅ *IP Updated*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🌐  New IP  : `{ip}`\n"
            f"📅  Expires : {fmt_ts(expires_at)}",
            parse_mode="Markdown",
        )
        return

    # ── Waiting IP (activation) ──
    if action == "waiting_ip":
        key_code = state.get("key_code")
        dur_sec  = state.get("duration_sec", 2592000)
        ip = text.strip()
        if not is_valid_ip(ip):
            await update.message.reply_text(
                "⚠️ Invalid IP address.\n_Example:_ `105.74.64.140`",
                parse_mode="Markdown",
            )
            return
        conn = get_db()
        existing = conn.execute(
            "SELECT expires_at, status FROM allowed_ips WHERE ip = ?", (ip,)
        ).fetchone()
        if existing and existing["status"] != "banned" and existing["expires_at"] > int(time.time()):
            conn.close()
            pending.pop(uid, None)
            await update.message.reply_text(
                f"⚠️ IP `{ip}` is already active.\n"
                f"Expires: {fmt_ts(existing['expires_at'])}",
                parse_mode="Markdown", reply_markup=back_kb(),
            )
            return
        pending.pop(uid, None)
        expires_at = int(time.time()) + dur_sec
        conn.execute(
            "INSERT OR REPLACE INTO allowed_ips (ip, expires_at, key_used, status) VALUES (?, ?, ?, 'active')",
            (ip, expires_at, key_code),
        )
        conn.execute(
            "UPDATE license_keys SET status='used', used_by_ip=?, used_by_uid=?, used_at=datetime('now') WHERE key_code=?",
            (ip, str(uid), key_code),
        )
        conn.commit(); conn.close()
        log.info(f"IP activated: {ip} key={key_code} user={uid}")
        await update.message.reply_text(
            f"🎉 *Access Activated!*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🌐  Your IP  : `{ip}`\n"
            f"⏱  Duration : {duration_label(dur_sec)}\n"
            f"📅  Expires  : {fmt_ts(expires_at)}\n\n"
            f"_Connect to the proxy and enjoy!_\n"
            f"👑 M3SB Proxy | @m3sbffxx",
            parse_mode="Markdown",
        )
        return

    # ── Key Input (verify / update IP) ──
    if text.startswith("M3SB-IOS-"):
        conn = get_db()
        row = conn.execute(
            "SELECT key_code, duration_sec, status FROM license_keys WHERE key_code = ?", (text,)
        ).fetchone()
        conn.close()
        if not row:
            await update.message.reply_text(
                "❌ *Invalid Key*\n"
                "This key does not exist.\n"
                "_Contact @m3sbffxx to get a key._",
                parse_mode="Markdown",
            )
            return
        if row["status"] == "banned":
            await update.message.reply_text(
                "🚫 *Key Banned*\n_Contact @m3sbffxx for support._",
                parse_mode="Markdown",
            )
            return
        if row["status"] == "used":
            conn2 = get_db()
            key_row = conn2.execute(
                "SELECT used_by_uid FROM license_keys WHERE key_code = ?", (text,)
            ).fetchone()
            original_uid = key_row["used_by_uid"] if key_row else None
            if original_uid and original_uid != str(uid):
                conn2.close()
                await update.message.reply_text(
                    "🔒 *Key Already Used*\n_This key belongs to another user._",
                    parse_mode="Markdown",
                )
                return
            ip_row = conn2.execute(
                "SELECT ip, expires_at FROM allowed_ips WHERE key_used = ? AND status = 'active'",
                (text,)
            ).fetchone()
            now = int(time.time())
            if ip_row and ip_row["expires_at"] > now:
                pending[uid] = {
                    "action": "update_ip",
                    "key_code": text,
                    "old_ip": ip_row["ip"],
                    "expires_at": ip_row["expires_at"],
                }
                conn2.close()
                await update.message.reply_text(
                    f"🔄 *Update IP*\n"
                    f"━━━━━━━━━━━━━━━━\n"
                    f"🌐  Current IP : `{ip_row['ip']}`\n"
                    f"📅  Expires    : {fmt_ts(ip_row['expires_at'])}\n\n"
                    f"📡 Send your new *IP address*:",
                    parse_mode="Markdown",
                )
            else:
                conn2.close()
                await update.message.reply_text(
                    "⏳ *Subscription Expired*\n"
                    "_Contact the seller to renew._",
                    parse_mode="Markdown",
                )
            return
        if row["status"] == "expired":
            await update.message.reply_text(
                "⏳ *Key Expired*\n_Contact the seller to renew._",
                parse_mode="Markdown",
            )
            return
        pending[uid] = {"action": "waiting_ip", "key_code": row["key_code"], "duration_sec": row["duration_sec"]}
        await update.message.reply_text(
            f"✅ *Key Verified!*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🔑  Key      : `{row['key_code']}`\n"
            f"⏱  Duration : {duration_label(row['duration_sec'])}\n\n"
            f"📡 Now send your *IP address* to activate:",
            parse_mode="Markdown",
        )
        return

    # ── Default ──
    if not owner and not reseller:
        await update.message.reply_text(
            "📩 Send your key to get started.\n_Example:_ `M3SB-IOS-XXXXX-XXXXX-XXXXX`",
            parse_mode="Markdown",
        )


# ─── Document Handler ──────────────────────────────────────────

async def document_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid   = update.effective_user.id
    state = pending.get(uid, {})
    action = state.get("action")

    if not is_owner(uid):
        return

    doc = update.message.document
    if not doc:
        return

    file = await ctx.bot.get_file(doc.file_id)
    buf = io.BytesIO()
    await file.download_to_memory(buf)
    raw_data = buf.getvalue()

    # ── Convert File ──
    if action == "convert_file":
        file_type = state.get("file_type", "cache_res")
        pending.pop(uid, None)

        hex_str, fi_hex, comp_size, uncomp_size, comp_sha1, uncomp_sha1 = convert_to_hex_gzip(raw_data, file_type)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix=f'{file_type}_', delete=False) as f:
            f.write(hex_str)
            hex_path = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='fileinfo_', delete=False) as f:
            f.write(fi_hex)
            fi_path = f.name

        try:
            await update.message.reply_document(
                document=open(hex_path, 'rb'),
                filename=f"{file_type}.txt",
                caption=(
                    f"✅ *{file_type} Converted*\n"
                    f"━━━━━━━━━━━━━━━━\n"
                    f"📦 Compressed : `{comp_size}` bytes\n"
                    f"📄 Original   : `{uncomp_size}` bytes\n"
                    f"🔒 SHA1 (gz)  : `{comp_sha1}`"
                ),
                parse_mode="Markdown",
            )
            await update.message.reply_document(
                document=open(fi_path, 'rb'),
                filename="fileinfo.txt",
                caption="📋 *Fileinfo* (matching hex above)",
                parse_mode="Markdown",
            )
        finally:
            os.unlink(hex_path)
            os.unlink(fi_path)
        return

    # ── Upload Hex for Port ──
    if action == "upload_hex":
        port = state.get("port")
        pending.pop(uid, None)
        if port not in PROXY_PORTS:
            await update.message.reply_text("⚠️ Unknown port."); return
        feature = PROXY_PORTS[port]["feature"]
        dest_dir = os.path.join(DATA_DIR, feature)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, "cache_res.txt")
        with open(dest_path, 'wb') as f:
            f.write(raw_data)
        proxy_action(port, "restart")
        await update.message.reply_text(
            f"✅ *Hex Updated — Port {port}*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"📁 Feature : `{feature}`\n"
            f"📄 File    : `cache_res.txt` ({len(raw_data)} bytes)\n"
            f"🔄 Proxy restarted",
            parse_mode="Markdown",
            reply_markup=back_kb("proxy_control"),
        )
        return

    # ── Upload Fileinfo for Port ──
    if action == "upload_fileinfo":
        port = state.get("port")
        pending.pop(uid, None)
        if port not in PROXY_PORTS:
            await update.message.reply_text("⚠️ Unknown port."); return
        feature = PROXY_PORTS[port]["feature"]
        dest_dir = os.path.join(DATA_DIR, feature)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, "fileinfo.txt")
        with open(dest_path, 'wb') as f:
            f.write(raw_data)
        proxy_action(port, "restart")
        await update.message.reply_text(
            f"✅ *Fileinfo Updated — Port {port}*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"📁 Feature : `{feature}`\n"
            f"📄 File    : `fileinfo.txt` ({len(raw_data)} bytes)\n"
            f"🔄 Proxy restarted",
            parse_mode="Markdown",
            reply_markup=back_kb("proxy_control"),
        )
        return


# ─── Periodic Cleanup ──────────────────────────────────────────

async def periodic_cleanup_loop():
    while True:
        await asyncio.sleep(300)
        try:
            conn = get_db()
            cleanup_expired(conn)
            conn.close()
            log.info("Periodic cleanup completed")
        except Exception as e:
            log.error(f"Periodic cleanup error: {e}")


async def post_init(application):
    asyncio.create_task(periodic_cleanup_loop())


# ─── Main ──────────────────────────────────────────────────────

def main():
    if not BOT_TOKEN:
        print("ERROR: Set M3SB_BOT_TOKEN in environment"); sys.exit(1)
    init_db()
    app = ApplicationBuilder().token(BOT_TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("reset", reset_cmd))
    app.add_handler(CommandHandler("check", check_cmd))
    app.add_handler(CallbackQueryHandler(button))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    log.info("M3SB Bot v5 started")
    print("[M3SB Bot v5] Started.")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
