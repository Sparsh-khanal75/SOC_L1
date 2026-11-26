#!/usr/bin/env python3
"""
Generates sample_logs/drupal_access.log: a simulated Drupal "Fail2Install"
(CVE-2026-132165) site takeover hidden in normal traffic.

Storyline (all IPs are from RFC 5737 documentation ranges, the site is fictional):
  18:30  Normal visitors on a Drupal 10 site that never blocked /core/install.php
  19:02  198.51.100.61 checks whether the installer is reachable  -> 200 (exposed)
  19:06  203.0.113.99 opens the installer and POSTs through the reinstall steps
         -> answered 200/302: the site has been reinstalled, user 1 replaced
  19:09  203.0.113.99 logs in as the new admin and browses /admin/people, /admin/modules
  19:12  203.0.113.99 calls a PHP file it dropped in /sites/default/files/
  19:30  Admin blocks the installer; 192.0.2.140 keeps probing -> 403 (block works)
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(11)
START = datetime(2026, 11, 19, 18, 30, 0, tzinfo=timezone.utc)
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]
ATTACKER_UA = "python-requests/2.32.3"
PAGES = ["/", "/node/12", "/node/27", "/node/31", "/blog", "/about-us", "/contact",
         "/core/misc/drupal.js", "/sites/default/files/css/css_main.css", "/themes/custom/site/logo.svg"]
lines = []


def log(ts, ip, method, path, status, size, agent, ref="-"):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    lines.append((ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{agent}"'))


# Normal traffic: one hour of visitors
for _ in range(300):
    ts = START + timedelta(seconds=random.randint(0, 3600))
    ip = f"10.30.{random.randint(1, 4)}.{random.randint(2, 40)}"
    log(ts, ip, "GET", random.choice(PAGES), 200, random.randint(800, 12000), random.choice(BROWSERS))

# 1) Recon: is the installer reachable?
t = START + timedelta(minutes=32)
log(t, "198.51.100.61", "GET", "/core/install.php", 200, 4120, "Mozilla/5.0 zgrab/0.x")

# 2) Fail2Install: walk the installer against the live site
t = START + timedelta(minutes=36)
steps = [
    ("GET", "/core/install.php", 200, 4120),
    ("GET", "/core/install.php?langcode=en", 200, 5230),
    ("POST", "/core/install.php?langcode=en&profile=standard", 200, 6110),
    ("POST", "/core/install.php?langcode=en&profile=standard&id=1&op=do_nojs", 200, 820),
    ("POST", "/core/install.php?langcode=en&profile=standard&continue=1", 302, 0),
]
for method, path, status, size in steps:
    t += timedelta(seconds=random.randint(3, 8))
    log(t, "203.0.113.99", method, path, status, size, ATTACKER_UA)

# 3) Log in with the account the attacker just created, then explore
t = START + timedelta(minutes=39)
for method, path, status, size in [("POST", "/user/login", 303, 0), ("GET", "/admin/people", 200, 9800),
                                   ("GET", "/admin/modules", 200, 15400), ("GET", "/admin/config", 200, 7600)]:
    t += timedelta(seconds=6)
    log(t, "203.0.113.99", method, path, status, size, ATTACKER_UA)

# 4) Call a dropped PHP file (the tool does not flag this itself - the analyst pivots here)
t = START + timedelta(minutes=42)
log(t, "203.0.113.99", "GET", "/sites/default/files/tmp_4f2a.php?c=id", 200, 54, ATTACKER_UA)

# 5) After the admin blocks the installer, a late scanner is refused
t = START + timedelta(minutes=60)
for path in ["/core/install.php", "/core/install.php?langcode=en&profile=standard"]:
    t += timedelta(seconds=2)
    log(t, "192.0.2.140", "POST" if "profile" in path else "GET", path, 403, 162, ATTACKER_UA)

lines.sort(key=lambda x: x[0])
out = Path(__file__).with_name("drupal_access.log")
out.write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")
print(f"Wrote {len(lines)} lines to {out}")
