# ╔══════════════════════════════════════╗
# ║   M3SB IOS | @m3sbffxx              ║
# ║   Free Project For All               ║
# ╚══════════════════════════════════════╝
import sys
import sqlite3
from datetime import datetime, timedelta

DB_PATH = r"C:\m3sb\m3sb.db"

def add_ip(ip, hours=720):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS allowed_ips (
            ip TEXT PRIMARY KEY,
            added_by TEXT DEFAULT 'admin',
            expires_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS proxy_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            client_ip TEXT,
            url TEXT,
            action TEXT,
            feature TEXT,
            status_code INTEGER
        )
    """)
    expires = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT OR REPLACE INTO allowed_ips (ip, added_by, expires_at) VALUES (?, 'admin', ?)",
        (ip, expires),
    )
    conn.commit()
    print(f"Added IP {ip}, expires: {expires}")
    rows = conn.execute("SELECT ip, expires_at FROM allowed_ips").fetchall()
    print(f"\nAll whitelisted IPs ({len(rows)}):")
    for row in rows:
        print(f"  {row[0]} -> {row[1]}")
    conn.close()

if __name__ == "__main__":
    ip    = sys.argv[1] if len(sys.argv) > 1 else "54.201.200.193"
    hours = int(sys.argv[2]) if len(sys.argv) > 2 else 720
    add_ip(ip, hours)
