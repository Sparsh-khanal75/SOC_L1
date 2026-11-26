# 🔎 Log Hunter — Web Access Log Threat Hunting Tool

A lightweight Python tool that reads Nginx/Apache access logs the way a SOC analyst would: it finds attack payloads, recognises offensive tooling, spots brute-force behaviour, and flags the requests that **may have actually succeeded**. Every finding is mapped to **MITRE ATT&CK**.

Built while working through the TryHackMe **SOC Level 2 — Working with Logs** module, to turn manual log triage into a repeatable process.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen) ![Tests](https://img.shields.io/badge/tests-16%20passing-success) ![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)

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
| Exposed CMS installer — Drupal `/core/install.php`, WordPress `setup-config.php`, Joomla `/installation/` | Signature + response code | T1190 | HIGH (LOW if blocked) |
| **Installer POST answered — possible reinstall / site takeover** (Drupal Fail2Install, CVE-2026-132165 / CVE-2026-136716) | Correlation | T1190 | **CRITICAL** |

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

## Case study: Drupal "Fail2Install" (CVE-2026-132165)

In November 2026 attackers began abusing Drupal's installer, `/core/install.php`, which stays on every site after setup and is not blocked by default. Under certain conditions an **anonymous POST** to it reinstalls the live site and replaces the **user 1** admin account. Exploitation started about a day after the 18 Nov patch, and CISA added the flaw to its KEV catalog on 24 Nov. A follow-up flaw, CVE-2026-136716, covers install states the first fix missed.

Log Hunter grades installer traffic by **whether the installer answered**:

| What the log shows | Meaning | Severity |
|---|---|---|
| POST to the installer answered 2xx/3xx | Installer accepted form data on a finished site → possible takeover | CRITICAL |
| GET answered 2xx/3xx | Installer is reachable from the internet → block it now | HIGH |
| Only 403/404 | Probing, but the block works | LOW |

`sample_logs/drupal_access.log` (313 lines, regenerate with `python sample_logs/generate_drupal_sample.py`) simulates the attack on a site that never blocked its installer:

```
$ python log_hunter.py sample_logs/drupal_access.log
 Findings      : CRITICAL=1, HIGH=2, LOW=1
[01] CRITICAL Possible Drupal Reinstall / Site Takeover (CVE-2026-132165 / CVE-2026-136716)
     Source IP : 203.0.113.99    Events: 3
     Evidence  : POST /core/install.php?langcode=en&profile=standard answered HTTP 200 - check the admin account, settings.php and new files
[03] HIGH     Exposed Drupal Installer (CVE-2026-132165 / CVE-2026-136716)
     Source IP : 198.51.100.61    Events: 1
[04] LOW      Blocked Drupal Installer Probe (CVE-2026-132165 / CVE-2026-136716)
     Source IP : 192.0.2.140    Events: 2
```

**Analyst next steps from that report:** treat the site as compromised. Pivot on `203.0.113.99` to find what happened after 19:06: an admin login at 19:09 and a dropped PHP file called at 19:12. Check user 1's email and password, look for changes to `settings.php` and new `.php` files under `sites/default/files/`, then rebuild from a pre-18 Nov backup, patch to 10.6.23 / 11.3.23 / 11.4.14 and block the installer.

**SIEM versions of the detection:**

- Sigma: [`rules/sigma/web_drupal_installer_access.yml`](rules/sigma/web_drupal_installer_access.yml), one rule for any answered installer request (high) and one for an answered POST (critical)
- Splunk:

```spl
index=web uri_path="*/core/install.php"
| eval answered=if(status>=200 AND status<400, 1, 0), answered_post=if(answered=1 AND method="POST", 1, 0)
| stats count values(method) as methods values(status) as codes max(answered) as answered max(answered_post) as answered_post by src_ip, host
| eval severity=case(answered_post=1, "critical", answered=1, "high", true(), "low")
| sort - answered_post - answered - count
```

## Project structure

```
Log_Hunter/
├── log_hunter.py            # parser, detection rules, correlation, reporting
├── test_log_hunter.py       # 16 unit tests (parser, each detection, false-positive checks)
├── rules/sigma/
│   └── web_drupal_installer_access.yml   # Sigma rules for the Fail2Install detection
└── sample_logs/
    ├── generate_sample.py          # builds a reproducible simulated incident
    ├── access.log
    ├── generate_drupal_sample.py   # simulated Drupal Fail2Install takeover
    └── drupal_access.log
```

## Limitations & next steps

- Signature rules catch common payloads, not every obfuscation — a WAF/IDS remains the primary control.
- HTTP 200 is a *signal* of success, not proof; response size and host telemetry should confirm it.
- Installer detection sees the HTTP request only; it can't tell whether the reinstall actually completed. Confirm on the host (user 1, `settings.php`, new files).
- Planned: GeoIP/threat-intel enrichment of source IPs, Sigma rules for the remaining detections, and a Splunk-ready output format.

> All IP addresses in the sample data come from RFC 5737 documentation ranges. Use this tool only on logs you are authorised to analyse.
