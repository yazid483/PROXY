# ╔══════════════════════════════════════╗
# ║   M3SB IOS | @m3sbffxx              ║
# ║   Free Project For All               ║
# ╚══════════════════════════════════════╝
"""
M3SB Public REST API — m3sbios.com
Provides key management endpoints for external websites/apps.
Authentication via X-API-Key header (keys generated from the Telegram bot).
"""
import os, sys, time, sqlite3, secrets, json, logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

API_PORT = int(os.environ.get("M3SB_WEB_API_PORT", "8443"))
DB_PATH  = os.environ.get("M3SB_DB_PATH", "/opt/m3sb/m3sb.db")
LOG_DIR  = os.environ.get("M3SB_LOG_DIR", "/opt/m3sb/logs")

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "web_api.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("m3sb_web_api")

DURATION_MAP = {
    "1d": 86400, "3d": 259200, "7d": 604800,
    "14d": 1209600, "30d": 2592000, "60d": 5184000, "90d": 7776000,
}

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn

def gen_key_code():
    p1 = secrets.token_hex(3).upper()[:5]
    p2 = secrets.token_hex(3).upper()[:5]
    p3 = secrets.token_hex(3).upper()[:5]
    return f"M3SB-IOS-{p1}-{p2}-{p3}"

def duration_label(sec):
    labels = {86400: "1 Day", 259200: "3 Days", 604800: "7 Days",
              1209600: "14 Days", 2592000: "30 Days", 5184000: "60 Days", 7776000: "90 Days"}
    return labels.get(sec, f"{sec // 86400} Days")

def verify_api_key(api_key):
    if not api_key:
        return False
    conn = get_db()
    row = conn.execute(
        "SELECT api_key FROM api_keys WHERE api_key = ? AND status = 'active'",
        (api_key,)
    ).fetchone()
    if row:
        conn.execute("UPDATE api_keys SET last_used = datetime('now') WHERE api_key = ?", (api_key,))
        conn.commit()
    conn.close()
    return row is not None


class WebAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s %s", self.client_address[0], fmt % args)

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def auth_check(self):
        api_key = self.headers.get("X-API-Key", "")
        if not verify_api_key(api_key):
            self.send_json(401, {"error": "Invalid or missing API key"})
            return False
        return True

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "" or path == "/":
            self.send_json(200, {
                "service": "M3SB Proxy API",
                "version": "1.0",
                "docs": "https://m3sbios.com/api/v1",
            })
            return

        if not self.auth_check():
            return

        # GET /api/v1/keys/list
        if path == "/api/v1/keys/list":
            conn = get_db()
            rows = conn.execute(
                "SELECT key_code, duration_sec, status, used_by_ip, created_at "
                "FROM license_keys ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
            conn.close()
            keys = []
            for r in rows:
                keys.append({
                    "key": r["key_code"],
                    "duration": r["duration_sec"],
                    "duration_label": duration_label(r["duration_sec"]),
                    "status": r["status"],
                    "ip": r["used_by_ip"],
                    "created_at": r["created_at"],
                })
            self.send_json(200, {"count": len(keys), "keys": keys})
            return

        # GET /api/v1/keys/check/<key_code>
        if path.startswith("/api/v1/keys/check/"):
            key_code = path.split("/")[-1]
            conn = get_db()
            row = conn.execute(
                "SELECT key_code, duration_sec, status, used_by_ip, used_at, created_at "
                "FROM license_keys WHERE key_code = ?",
                (key_code,)
            ).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "Key not found"})
                return
            ip_info = None
            if row["used_by_ip"]:
                ip_row = conn.execute(
                    "SELECT expires_at, status FROM allowed_ips WHERE ip = ?",
                    (row["used_by_ip"],)
                ).fetchone()
                if ip_row:
                    ip_info = {"ip": row["used_by_ip"], "expires_at": ip_row["expires_at"], "status": ip_row["status"]}
            conn.close()
            self.send_json(200, {
                "key": row["key_code"],
                "duration": row["duration_sec"],
                "duration_label": duration_label(row["duration_sec"]),
                "status": row["status"],
                "ip_info": ip_info,
                "used_at": row["used_at"],
                "created_at": row["created_at"],
            })
            return

        # GET /api/v1/stats
        if path == "/api/v1/stats":
            conn = get_db()
            now = int(time.time())
            total = conn.execute("SELECT COUNT(*) FROM license_keys").fetchone()[0]
            unused = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='unused'").fetchone()[0]
            used = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='used'").fetchone()[0]
            banned = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='banned'").fetchone()[0]
            expired = conn.execute("SELECT COUNT(*) FROM license_keys WHERE status='expired'").fetchone()[0]
            active_ips = conn.execute("SELECT COUNT(*) FROM allowed_ips WHERE status='active' AND expires_at > ?", (now,)).fetchone()[0]
            conn.close()
            self.send_json(200, {
                "total_keys": total, "unused": unused, "used": used,
                "banned": banned, "expired": expired, "active_ips": active_ips,
            })
            return

        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if not self.auth_check():
            return

        body = self.read_body()

        # POST /api/v1/keys/generate
        if path == "/api/v1/keys/generate":
            dur = body.get("duration", "30d")
            if isinstance(dur, str):
                dur_sec = DURATION_MAP.get(dur.lower())
                if not dur_sec:
                    self.send_json(400, {"error": f"Invalid duration '{dur}'. Use: {list(DURATION_MAP.keys())}"})
                    return
            elif isinstance(dur, int):
                dur_sec = dur
                if dur_sec not in DURATION_MAP.values():
                    self.send_json(400, {"error": f"Invalid duration. Allowed: {list(DURATION_MAP.values())}"})
                    return
            else:
                self.send_json(400, {"error": "Duration must be string or integer"})
                return

            count = body.get("count", 1)
            if not isinstance(count, int) or count < 1 or count > 100:
                self.send_json(400, {"error": "Count must be 1-100"})
                return

            conn = get_db()
            keys = []
            for _ in range(count):
                code = gen_key_code()
                conn.execute(
                    "INSERT INTO license_keys (key_code, duration_sec, created_by) VALUES (?, ?, 'api')",
                    (code, dur_sec),
                )
                keys.append(code)
            conn.commit(); conn.close()
            log.info(f"API generated {count} keys dur={dur_sec}s")
            self.send_json(200, {
                "keys": keys,
                "count": count,
                "duration": dur_sec,
                "duration_label": duration_label(dur_sec),
            })
            return

        # POST /api/v1/keys/ban
        if path == "/api/v1/keys/ban":
            key_code = body.get("key", "")
            if not key_code:
                self.send_json(400, {"error": "Missing 'key' field"})
                return
            conn = get_db()
            row = conn.execute("SELECT key_code, status, used_by_ip FROM license_keys WHERE key_code = ?", (key_code,)).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "Key not found"})
                return
            if row["used_by_ip"]:
                conn.execute("UPDATE allowed_ips SET status='banned', expires_at=0 WHERE ip=?", (row["used_by_ip"],))
            conn.execute("UPDATE license_keys SET status='banned' WHERE key_code=?", (key_code,))
            conn.commit(); conn.close()
            log.info(f"API banned key: {key_code}")
            self.send_json(200, {"status": "banned", "key": key_code})
            return

        # POST /api/v1/keys/delete
        if path == "/api/v1/keys/delete":
            key_code = body.get("key", "")
            if not key_code:
                self.send_json(400, {"error": "Missing 'key' field"})
                return
            conn = get_db()
            row = conn.execute("SELECT key_code, used_by_ip FROM license_keys WHERE key_code = ?", (key_code,)).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "Key not found"})
                return
            if row["used_by_ip"]:
                conn.execute("DELETE FROM allowed_ips WHERE ip=?", (row["used_by_ip"],))
            conn.execute("DELETE FROM license_keys WHERE key_code=?", (key_code,))
            conn.commit(); conn.close()
            log.info(f"API deleted key: {key_code}")
            self.send_json(200, {"status": "deleted", "key": key_code})
            return

        # POST /api/v1/keys/reset
        if path == "/api/v1/keys/reset":
            key_code = body.get("key", "")
            if not key_code:
                self.send_json(400, {"error": "Missing 'key' field"})
                return
            conn = get_db()
            row = conn.execute(
                "SELECT key_code, duration_sec, status, used_by_ip FROM license_keys WHERE key_code = ?",
                (key_code,)
            ).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "Key not found"})
                return
            if row["status"] not in ("used", "expired"):
                conn.close()
                self.send_json(400, {"error": f"Key status is '{row['status']}', nothing to reset"})
                return
            old_ip = row["used_by_ip"]
            if old_ip:
                conn.execute("DELETE FROM allowed_ips WHERE ip=? AND key_used=?", (old_ip, key_code))
            conn.execute(
                "UPDATE license_keys SET status='unused', used_by_ip=NULL, used_at=NULL WHERE key_code=?",
                (key_code,)
            )
            conn.commit(); conn.close()
            log.info(f"API reset key: {key_code}")
            self.send_json(200, {"status": "reset", "key": key_code, "old_ip": old_ip})
            return

        # POST /api/v1/activate
        if path == "/api/v1/activate":
            key_code = body.get("key", "")
            ip = body.get("ip", "")
            if not key_code or not ip:
                self.send_json(400, {"error": "Missing 'key' and/or 'ip' fields"})
                return
            conn = get_db()
            row = conn.execute(
                "SELECT key_code, duration_sec, status FROM license_keys WHERE key_code = ?",
                (key_code,)
            ).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "Key not found"})
                return
            if row["status"] == "banned":
                conn.close()
                self.send_json(403, {"error": "Key is banned"})
                return
            if row["status"] == "used":
                conn.close()
                self.send_json(400, {"error": "Key already used"})
                return
            if row["status"] == "expired":
                conn.close()
                self.send_json(400, {"error": "Key expired"})
                return
            expires_at = int(time.time()) + row["duration_sec"]
            conn.execute(
                "INSERT OR REPLACE INTO allowed_ips (ip, expires_at, key_used, status) VALUES (?, ?, ?, 'active')",
                (ip, expires_at, key_code),
            )
            conn.execute(
                "UPDATE license_keys SET status='used', used_by_ip=?, used_at=datetime('now') WHERE key_code=?",
                (ip, key_code),
            )
            conn.commit(); conn.close()
            log.info(f"API activated ip={ip} key={key_code}")
            self.send_json(200, {
                "status": "activated",
                "key": key_code,
                "ip": ip,
                "expires_at": expires_at,
                "duration_label": duration_label(row["duration_sec"]),
            })
            return

        self.send_json(404, {"error": "Not found"})


def main():
    server = HTTPServer(("0.0.0.0", API_PORT), WebAPIHandler)
    print(f"[M3SB Web API] Listening on port {API_PORT}")
    print(f"[M3SB Web API] Database: {DB_PATH}")
    log.info(f"Web API started on port {API_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[M3SB Web API] Stopped")
        server.server_close()


if __name__ == "__main__":
    main()
