# ╔══════════════════════════════════════╗
# ║   M3SB IOS | @m3sbffxx              ║
# ║   Free Project For All               ║
# ╚══════════════════════════════════════╝
import os
import sqlite3
import time
import logging
from mitmproxy import http, ctx, tls

DATA_DIR = os.environ.get("M3SB_DATA_DIR", "/opt/m3sb/data")
DB_PATH  = os.environ.get("M3SB_DB_PATH",  "/opt/m3sb/m3sb.db")
FEATURE  = os.environ.get("M3SB_ACTIVE_FEATURE", "NECK_ANTENNA")
LOG_DIR  = os.environ.get("M3SB_LOG_DIR",  "/opt/m3sb/logs")

INTERCEPT_PATTERNS = ["cache_res", "assetindexer", "fileinfo"]
MAINTENANCE_FLAG = os.path.join(os.path.dirname(DB_PATH), "maintenance.flag")

# Domains that NEED TLS interception (MITM).
# Everything else gets TLS passthrough (transparent tunnel, no fake cert).
MITM_DOMAINS = [
    "ggpolarbear.com",       # majorlogin IP check (HTTPS)
    "freefiremobile.com",    # CDN file interception (cache_res, assetindexer, fileinfo)
]

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, f"proxy_{FEATURE}.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("m3sb_proxy")

FILE_CACHE = {}
IP_CACHE = {}  # {ip: (status, expire_time)}
IP_CACHE_TTL = 30  # seconds
MAINTENANCE_CACHE = {"active": False, "checked": 0}
MAINTENANCE_TTL = 5  # seconds

def is_maintenance() -> bool:
    now = time.time()
    if now - MAINTENANCE_CACHE["checked"] < MAINTENANCE_TTL:
        return MAINTENANCE_CACHE["active"]
    active = os.path.exists(MAINTENANCE_FLAG)
    MAINTENANCE_CACHE["active"] = active
    MAINTENANCE_CACHE["checked"] = now
    return active

def msg_maintenance(ip):
    return (
        f"[FFFF00]🔧 Proxy Under Maintenance!\n"
        f"[FFFFFF]The proxy is currently under maintenance.\n"
        f"[FFFF00]Your IP : {ip}\n"
        f"[00FFFF]Please try again later."
    )

def check_ip_cached(ip: str) -> str:
    now = time.time()
    cached = IP_CACHE.get(ip)
    if cached and now - cached[1] < IP_CACHE_TTL:
        return cached[0]
    status = is_ip_allowed(ip)
    IP_CACHE[ip] = (status, now)
    return status

def msg_not_registered(ip):
    return (
        f"[FF0000]🚫 Not Registered!\n"
        f"[FFFFFF]Your IP is not in the system.\n"
        f"[FFFF00]Your IP : {ip}\n"
        f"[00FFFF]Get access: contact @m3sbffxx"
    )

def msg_expired(ip):
    return (
        f"[FF9900]⏳ Subscription Expired!\n"
        f"[FFFFFF]Your access has ended.\n"
        f"[FFFF00]Your IP : {ip}\n"
        f"[00FFFF]Renew: contact @m3sbffxx"
    )

def msg_banned(ip):
    return (
        f"[FF0000]🚫 You Are Banned!\n"
        f"[FFFFFF]Your IP has been banned from the system.\n"
        f"[FFFF00]Your IP : {ip}\n"
        f"[00FFFF]Contact: the seller"
    )

MSG_SUCCESS = (
    "[00FF00]⚡ Successfully Injected!\n"
    "[FFFFFF]Please turn OFF proxy to login.\n"
    "[00FFFF]👑 M3SB IOS | @m3sbffxx"
)

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS allowed_ips (
            ip         TEXT PRIMARY KEY,
            expires_at INTEGER DEFAULT 0,
            key_used   TEXT,
            status     TEXT DEFAULT 'active',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS license_keys (
            key_code     TEXT PRIMARY KEY,
            duration_sec INTEGER DEFAULT 2592000,
            status       TEXT DEFAULT 'unused',
            created_by   TEXT DEFAULT 'owner',
            used_by_ip   TEXT,
            used_at      TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS proxy_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT DEFAULT (datetime('now')),
            client_ip  TEXT,
            url        TEXT,
            action     TEXT,
            feature    TEXT,
            status_code INTEGER
        );
    """)
    conn.commit()
    conn.close()

def is_ip_allowed(ip: str) -> str:
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT expires_at, status FROM allowed_ips WHERE ip = ?", (ip,)
        ).fetchone()
        conn.close()
        if row:
            if row["status"] == "banned":
                return "BANNED"
            return "ACTIVE" if row["expires_at"] > int(time.time()) else "EXPIRED"
    except Exception as e:
        log.error(f"DB check error: {e}")
    return "NOT_FOUND"

def log_req(ip, url, action, code):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO proxy_logs (client_ip, url, action, feature, status_code) VALUES (?,?,?,?,?)",
            (ip, url, action, FEATURE, code),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Log error: {e}")

def load_files():
    base = os.path.join(DATA_DIR, FEATURE)
    if not os.path.exists(base):
        log.error(f"Data dir not found: {base}"); return
    for pattern in INTERCEPT_PATTERNS:
        for name in [pattern, pattern + ".txt", pattern + ".bin"]:
            path = os.path.join(base, name)
            if os.path.exists(path):
                with open(path, "rb") as f: raw = f.read()
                try:
                    clean = raw.decode("ascii").strip().replace(" ","").replace("\n","").replace("\r","")
                    if all(c in "0123456789abcdefABCDEF" for c in clean) and len(clean) > 10:
                        FILE_CACHE[pattern] = bytes.fromhex(clean)
                        ctx.log.info(f"[M3SB IOS] Loaded {pattern} (hex): {len(FILE_CACHE[pattern])} bytes")
                        break
                except (UnicodeDecodeError, ValueError): pass
                FILE_CACHE[pattern] = raw
                ctx.log.info(f"[M3SB IOS] Loaded {pattern} (bin): {len(raw)} bytes")
                break
    ctx.log.info(f"[M3SB IOS] Ready: {list(FILE_CACHE.keys())}")


class M3SBProxy:

    def load(self, loader):
        init_db()
        ctx.log.info(f"[M3SB IOS] Proxy loaded — Feature: {FEATURE}")
        ctx.log.info(f"[M3SB IOS] TLS MITM only for: {MITM_DOMAINS}")
        load_files()

    def tls_clienthello(self, data: tls.ClientHelloData):
        """TLS passthrough for non-game domains.

        Only MITM the specific game domains we need to intercept.
        All other HTTPS connections (Apple, Google, Facebook, ad networks,
        anti-cheat, Unity, etc.) pass through as transparent TCP tunnels
        with no certificate spoofing — invisible to the game and OS.
        """
        sni = data.client_hello.sni
        if not sni:
            return
        if not any(d in sni for d in MITM_DOMAINS):
            data.ignore_connection = True

    def request(self, flow: http.HTTPFlow):
        ip  = flow.client_conn.peername[0]
        url = flow.request.pretty_url
        url_lower = url.lower()

        # Maintenance mode — block all file interception
        if is_maintenance():
            for p in INTERCEPT_PATTERNS:
                if p.lower() in url_lower:
                    log_req(ip, url, f"MAINTENANCE_{p.upper()}", 503)
                    return
            return

        for p in INTERCEPT_PATTERNS:
            if p.lower() in url_lower:
                status = check_ip_cached(ip)
                if status != "ACTIVE":
                    log_req(ip, url, f"BLOCKED_{p.upper()}_{status}", 403)
                    log.warning(f"BLOCKED file intercept ip={ip} status={status} file={p}")
                    return
                data = FILE_CACHE.get(p)
                if data:
                    flow.response = http.Response.make(
                        200, data,
                        {
                            "Content-Type": "application/octet-stream",
                            "Content-Length": str(len(data)),
                            "Accept-Ranges": "bytes",
                            "Cache-Control": "public, max-age=86400",
                            "Connection": "keep-alive",
                            "X-Cache": "HIT",
                        },
                    )
                    log_req(ip, url, f"INTERCEPT_{p.upper()}", 200)
                else:
                    log_req(ip, url, f"MISSING_{p.upper()}", 404)
                return

    def response(self, flow: http.HTTPFlow):
        ip  = flow.client_conn.peername[0]
        url = flow.request.pretty_url
        if "majorlogin" in url.lower() and flow.response.status_code == 200:
            # Maintenance mode — show maintenance message to everyone
            if is_maintenance():
                flow.response.status_code = 400
                flow.response.content = msg_maintenance(ip).encode("utf-8")
                flow.response.headers["Content-Type"] = "text/plain; charset=utf-8"
                log.info(f"MAINTENANCE ip={ip}")
                ctx.log.info(f"[M3SB IOS] MAINTENANCE ip={ip}")
                return
            status = is_ip_allowed(ip)
            if status == "ACTIVE":
                flow.response.status_code = 400
                flow.response.content = MSG_SUCCESS.encode("utf-8")
                flow.response.headers["Content-Type"] = "text/plain; charset=utf-8"
                log.info(f"INJECTED ip={ip}")
                ctx.log.info(f"[M3SB IOS] Injected ip={ip}")
            elif status == "BANNED":
                flow.response.status_code = 400
                flow.response.content = msg_banned(ip).encode("utf-8")
                flow.response.headers["Content-Type"] = "text/plain; charset=utf-8"
                log.info(f"BANNED ip={ip}")
                ctx.log.warn(f"[M3SB IOS] BANNED ip={ip}")
            elif status == "EXPIRED":
                flow.response.status_code = 400
                flow.response.content = msg_expired(ip).encode("utf-8")
                flow.response.headers["Content-Type"] = "text/plain; charset=utf-8"
                log.info(f"EXPIRED ip={ip}")
                ctx.log.warn(f"[M3SB IOS] EXPIRED ip={ip}")
            else:
                flow.response.status_code = 400
                flow.response.content = msg_not_registered(ip).encode("utf-8")
                flow.response.headers["Content-Type"] = "text/plain; charset=utf-8"
                log.info(f"NOT_REGISTERED ip={ip}")
                ctx.log.warn(f"[M3SB IOS] NOT_REGISTERED ip={ip}")

addons = [M3SBProxy()]
