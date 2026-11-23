# 🔎 Log Hunter — Web Access Log Threat Hunting Tool

A lightweight Python tool that reads Nginx/Apache access logs the way a SOC analyst would: it finds attack payloads, recognises offensive tooling, spots brute-force behaviour, and flags the requests that **may have actually succeeded**. Every finding is mapped to **MITRE ATT&CK**.

Built while working through the TryHackMe **SOC Level 2 — Working with Logs** module, to turn manual log triage into a repeatable process.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen) ![Tests](https://img.shields.io/badge/tests-10%20passing-success) ![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)

---

## Why I built it

When I investigated web-server logs in labs, I kept asking the same questions every time: *who* is attacking, *what* are they trying, *when* did it start, and *did it work?* Scrolling through thousands of lines with `grep` answers the first three slowly and the fourth almost never. Log Hunter answers all four in one report, ranking the findings an analyst should look at first.

## What it detects

| Detection | Method | MITRE ATT&CK | Severity |
|---|---|---|---|
| SQL Injection | Signature (decoded URL) | T1190 | HIGH |
| Cross-Site Scripting | Signature | T1190 | MEDIUM |
| Path Traversal / LFI | Signature | T1083 | HIGH |
| Command Injection | Signature | T1059 | CRITICAL |
| Sensitive file probes (`.env`, `.git`, backups) | Signature | T1595.003 | MEDIUM |
| Offensive tool user-agents (sqlmap, nikto, gobuster, ffuf, hydra…) | Signature | T1595 | HIGH |
| Directory brute-force | Behaviour: 404 bursts in a sliding window | T1595.003 | MEDIUM |
| Login brute-force | Behaviour: auth POST bursts in a sliding window | T1110 | HIGH |
| **Brute-force followed by a successful login** | Correlation | T1110 | **CRITICAL** |
| **Attack payload answered with HTTP 2xx** | Correlation | per technique | **CRITICAL** |

Design choices worth noting:

- **Double URL-decoding** so `%2527` → `%27` → `'` payloads aren't missed.
- **Sliding time windows** instead of raw counts — 20 × 404 in 20 seconds is a scanner; 20 × 404 across a day is a broken link.
- **Success correlation** — a blocked attack (403/500) and an answered one (200) deserve very different responses. Reflected XSS is deliberately *not* escalated, because a 200 there is normal and proves nothing on its own.

## Quick start

```bash
git clone https://github.com/Sparsh-khanal75/SOC_L1.git
cd SOC_L1/Log_Hunter

python log_hunter.py sample_logs/access.log                      # coloured report
python log_hunter.py sample_logs/access.log --json report.json    # + JSON for a SIEM / ticket
python log_hunter.py /var/log/nginx/access.log --window 30 --threshold 25
python -m unittest -v                                             # run the tests
```

No `pip install` needed — standard library only. Exit code is `2` when a CRITICAL finding exists, so it can gate a CI job or cron alert.

## Sample investigation

`sample_logs/access.log` (463 lines) hides a simulated intrusion inside ~400 normal requests. Regenerate it with `python sample_logs/generate_sample.py`.

```
 Events parsed : 463
 Unique IPs    : 140
 Findings      : CRITICAL=5, HIGH=6, MEDIUM=3
------------------------------------------------------------------------------
[01] CRITICAL Possible Successful Path Traversal / LFI
     Source IP : 203.0.113.45    Events: 1
     Evidence  : HTTP 200 returned for: /download?file=....//....//....//etc/passwd
[02] CRITICAL Brute-Force Followed by Successful Login
     Source IP : 192.0.2.77    Events: 1
     Evidence  : HTTP 200 on /login after 14 failures
[03] CRITICAL Command Injection
     Source IP : 192.0.2.77    Events: 2
     Evidence  : /admin/ping?host=127.0.0.1;whoami
...
 Suspicious IPs ranked by highest severity, then finding count:
   192.0.2.77       CRITICAL 6 finding(s)
   203.0.113.45     CRITICAL 5 finding(s)
   198.51.100.23    HIGH     3 finding(s)
```

**Reconstructed timeline from the report:**

| Time | Source | Activity | Outcome |
|---|---|---|---|
| 09:14 | 198.51.100.23 | gobuster directory brute-force, then `.env` / `.git` probes | Recon only |
| 09:21 | 203.0.113.45 | sqlmap against `/products?id=` | Server errors (500) — likely failed, but the parameter needs fixing |
| 09:26 | 203.0.113.45 | Path traversal — filter bypass with `....//` | **200, 1.8 KB returned → `/etc/passwd` likely disclosed** |
| 09:31 | 192.0.2.77 | 14 failed logins in 28 s, then success | **Account compromised** |
| 09:34 | 192.0.2.77 | Command injection via `/admin/ping` | **200 → probable RCE** |

**Analyst recommendation:** isolate the web server, reset the compromised account and enforce MFA/rate-limiting on `/login`, block the three IPs at the WAF, patch the `file` and `host` parameters, and hunt on the host for activity after 09:34.

## Project structure

```
Log_Hunter/
├── log_hunter.py            # parser, detection rules, correlation, reporting
├── test_log_hunter.py       # 10 unit tests (parser, each detection, false-positive checks)
└── sample_logs/
    ├── generate_sample.py   # builds a reproducible simulated incident
    └── access.log
```

## Limitations & next steps

- Signature rules catch common payloads, not every obfuscation — a WAF/IDS remains the primary control.
- HTTP 200 is a *signal* of success, not proof; response size and host telemetry should confirm it.
- Planned: GeoIP/threat-intel enrichment of source IPs, Sigma-rule export, and a Splunk-ready output format.

> All IP addresses in the sample data come from RFC 5737 documentation ranges. Use this tool only on logs you are authorised to analyse.
