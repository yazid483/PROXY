# ╔══════════════════════════════════════╗
# ║   M3SB IOS | @m3sbffxx              ║
# ║   Free Project For All               ║
# ╚══════════════════════════════════════╝
import os
import sqlite3
import time
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

API_PORT       = int(os.environ.get("M3SB_API_PORT", 8080))
DATA_DIR       = os.environ.get("M3SB_DATA_DIR", "/opt/m3sb/data")
DB_PATH        = os.environ.get("M3SB_DB_PATH",  "/opt/m3sb/m3sb.db")
AUTH_KEY       = os.environ.get("M3SB_AUTH_KEY", "M3SB_PROXY")
ACTIVE_FEATURE = os.environ.get("M3SB_ACTIVE_FEATURE", "NECK_ANTENNA")
TIME_TOLERANCE = 300

HEX_CHARS = "0123456789abcdef"

def verify_auth(header_value):
    if not header_value:
        return False
    parts = header_value.split(".", 1)
    if len(parts) != 2:
        return False
    try:
        client_ts = int(parts[0])
    except ValueError:
        return False
    if abs(time.time() - client_ts) > TIME_TOLERANCE:
        return False
    s = str(client_ts)
    expected = ""
    for i in range(len(s)):
        val = (ord(s[i]) + ord(AUTH_KEY[i % len(AUTH_KEY)])) ^ 42
        expected += format(val, "02x")
    return parts[1] == expected

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn

def is_ip_allowed(ip):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM allowed_ips WHERE ip = ? AND expires_at > ?",
        (ip, int(time.time())),
    ).fetchone()
    conn.close()
    return row is not None

def encode_with_poison(hex_data):
    poisoned = ""
    for i in range(0, len(hex_data), 2):
        if i + 1 < len(hex_data):
            byte = hex_data[i] + hex_data[i + 1]
            garbage = HEX_CHARS[random.randint(0, 15)]
            poisoned += byte + garbage
    return "M3SB" + poisoned + "END"

class M3SBAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        ua = (self.headers.get("User-Agent") or "").lower()
        if any(t in ua for t in ["curl", "postman", "wget", "python", "insomnia"]):
            self.send_error(404)
            return

        auth_header = self.headers.get("X-M3SB-AUTH", "")
        if not verify_auth(auth_header):
            self.send_error(404)
            return

        client_ip = self.headers.get("X-Forwarded-For", self.client_address[0])
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        action = params.get("action", [""])[0]
        if action == "popup":
            if is_ip_allowed(client_ip):
                msg = (
                    "[c][b][00FF00]M3SB VIP ACCESS GRANTED\n"
                    "[FFFFFF]──────────────────\n"
                    f"[00FFFF]Feature: {ACTIVE_FEATURE}\n"
                    "[FFFFFF]M3SB IOS | @m3sbffxx | @m3sbffxx"
                )
            else:
                msg = (
                    "[c][b][FFFF00]IP NOT REGISTERED!\n"
                    "[FFFFFF]Contact admin to authorize your IP.\n"
                    f"[FF0000]Your IP: {client_ip}"
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(msg.encode())
            return

        file_type = params.get("file", [""])[0]
        if not file_type:
            self.send_error(400)
            return

        if not is_ip_allowed(client_ip):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        file_path = os.path.join(DATA_DIR, ACTIVE_FEATURE, f"{file_type}.txt")
        if not os.path.exists(file_path):
            bin_path = os.path.join(DATA_DIR, ACTIVE_FEATURE, file_type)
            if os.path.exists(bin_path):
                with open(bin_path, "rb") as f:
                    raw = f.read()
                hex_data = raw.hex()
            else:
                self.send_error(404)
                return
        else:
            with open(file_path, "r") as f:
                hex_data = f.read().strip().replace(" ", "").replace("\n", "")

        encoded = encode_with_poison(hex_data)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(encoded.encode())

def main():
    server = HTTPServer(("0.0.0.0", API_PORT), M3SBAPIHandler)
    print(f"[M3SB API] Listening on port {API_PORT}")
    print(f"[M3SB API] Feature: {ACTIVE_FEATURE}")
    print(f"[M3SB API] Data dir: {DATA_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[M3SB API] Stopped")
        server.server_close()

if __name__ == "__main__":
    main()
