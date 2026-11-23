#!/usr/bin/env python3
"""
Generates sample_logs/access.log: a simulated incident hidden in normal traffic.

Attack storyline (all IPs are from RFC 5737 documentation ranges):
  09:00  Normal customer traffic all morning
  09:14  198.51.100.23 runs gobuster against the site (directory brute-force)
  09:17  Same IP probes for .env / .git exposure
  09:21  203.0.113.45 runs sqlmap against /products?id=
  09:26  203.0.113.45 tries path traversal - one request returns 200 (!)
  09:31  192.0.2.77 brute-forces /login, then gets in
  09:34  192.0.2.77 tries command injection via the ping utility
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)
TZ = timezone(timedelta(hours=0))
START = datetime(2026, 11, 20, 9, 0, 0, tzinfo=TZ)
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
PAGES = ["/", "/products", "/products?id=3", "/products?id=12", "/about", "/contact", "/cart",
         "/static/css/main.css", "/static/js/app.js", "/images/logo.png"]
lines = []


def log(ts, ip, method, path, status, size, agent, ref="-"):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    lines.append((ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{agent}"'))


# Normal background traffic: ~40 minutes from ~25 users
for _ in range(400):
    ts = START + timedelta(seconds=random.randint(0, 2400))
    ip = f"10.20.{random.randint(1, 5)}.{random.randint(2, 30)}"
    log(ts, ip, "GET", random.choice(PAGES), 200, random.randint(500, 9000), random.choice(BROWSERS))
for _ in range(6):  # a few honest 404s and logins
    ts = START + timedelta(seconds=random.randint(0, 2400))
    log(ts, f"10.20.1.{random.randint(2, 30)}", "GET", "/favicon.ico", 404, 0, random.choice(BROWSERS))
    log(ts, f"10.20.2.{random.randint(2, 30)}", "POST", "/login", 200, 312, random.choice(BROWSERS))

# 1) Directory brute-force with gobuster
t = START + timedelta(minutes=14)
for word in ["admin", "backup", "old", "test", "dev", "uploads", "config", "private", "api/v1", "server-status",
             "phpmyadmin", "cgi-bin", "logs", "tmp", "db", "staging", "portal", "secret", "panel", "console"]:
    t += timedelta(seconds=1)
    log(t, "198.51.100.23", "GET", f"/{word}", 404 if word not in ("admin", "uploads") else 301, 162,
        "gobuster/3.6")
t = START + timedelta(minutes=17)
for p in ["/.env", "/.git/config", "/wp-config.php", "/backup.zip"]:
    t += timedelta(seconds=2)
    log(t, "198.51.100.23", "GET", p, 404, 162, "gobuster/3.6")

# 2) SQL injection with sqlmap
t = START + timedelta(minutes=21)
for payload in ["3%27", "3%20AND%201%3D1", "3%27%20OR%20%271%27%3D%271",
                "3%20UNION%20SELECT%20NULL%2CNULL%2CNULL--",
                "3%20UNION%20ALL%20SELECT%20table_name%2CNULL%20FROM%20information_schema.tables--",
                "3%20AND%20SLEEP(5)"]:
    t += timedelta(seconds=3)
    log(t, "203.0.113.45", "GET", f"/products?id={payload}", 500, 0, "sqlmap/1.8.4#stable (https://sqlmap.org)")

# 3) Path traversal - the last one succeeds
t = START + timedelta(minutes=26)
for payload, status, size in [("../../etc/passwd", 400, 0), ("..%2f..%2f..%2fetc%2fpasswd", 403, 0),
                              ("....//....//....//etc/passwd", 200, 1842)]:
    t += timedelta(seconds=4)
    log(t, "203.0.113.45", "GET", f"/download?file={payload}", status, size, BROWSERS[0])

# 4) Login brute-force, then success
t = START + timedelta(minutes=31)
for i in range(14):
    t += timedelta(seconds=2)
    log(t, "192.0.2.77", "POST", "/login", 401, 98, "python-requests/2.32.3", "https://shop.example.com/login")
t += timedelta(seconds=2)
log(t, "192.0.2.77", "POST", "/login", 200, 312, "python-requests/2.32.3", "https://shop.example.com/login")

# 5) Post-login command injection through a diagnostics page
t = START + timedelta(minutes=34)
for payload in ["127.0.0.1%3Bwhoami", "127.0.0.1%7Ccat%20%2Fetc%2Fpasswd"]:
    t += timedelta(seconds=5)
    log(t, "192.0.2.77", "GET", f"/admin/ping?host={payload}", 200, 640, "python-requests/2.32.3")

# 6) A reflected XSS attempt
log(START + timedelta(minutes=38), "203.0.113.45", "GET",
    "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200, 2210, BROWSERS[0])

lines.sort(key=lambda x: x[0])
out = Path(__file__).with_name("access.log")
out.write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")
print(f"Wrote {len(lines)} lines to {out}")
