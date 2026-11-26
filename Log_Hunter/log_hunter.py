#!/usr/bin/env python3
"""
Log Hunter - a lightweight web access-log threat hunting tool for SOC analysts.

Parses Nginx / Apache "combined" access logs and flags:
  * Web attack payloads (SQLi, XSS, path traversal / LFI, command injection)
  * Known offensive-tool user agents (sqlmap, nikto, gobuster, ...)
  * Directory / content brute-forcing (bursts of 404s from one IP)
  * Login brute-force (bursts of failed POSTs to auth endpoints)
  * Attack payloads that received a 2xx response (possible successful exploitation)
  * Requests to CMS installers (Drupal Fail2Install CVE-2026-132165, WordPress, Joomla)

Every finding is mapped to a MITRE ATT&CK technique and given a severity.
Standard library only - runs anywhere Python 3.8+ is installed.

Usage:
    python log_hunter.py sample_logs/access.log
    python log_hunter.py access.log --json report.json --csv report.csv
    python log_hunter.py access.log --window 60 --threshold 20
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Iterable, Iterator, List, Optional
from urllib.parse import unquote_plus

# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]+))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogEntry:
    line_no: int
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    agent: str
    raw: str

    @property
    def decoded_path(self) -> str:
        # Decode twice to catch double-URL-encoded payloads (%2527 -> %27 -> ')
        return unquote_plus(unquote_plus(self.path))


def parse_line(line: str, line_no: int) -> Optional[LogEntry]:
    m = COMBINED_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), TIME_FMT)
    except ValueError:
        return None
    return LogEntry(
        line_no=line_no,
        ip=m.group("ip"),
        time=ts,
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        agent=m.group("agent") or "-",
        raw=line.rstrip("\n"),
    )


def read_log(lines: Iterable[str]) -> Iterator[LogEntry]:
    for i, line in enumerate(lines, start=1):
        entry = parse_line(line, i)
        if entry:
            yield entry


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    mitre: str
    severity: str
    escalate_on_success: bool = True  # a 2xx response suggests the attack may have worked


PAYLOAD_RULES: List[Rule] = [
    Rule("SQL Injection",
         re.compile(r"(\bunion\b.{0,20}\bselect\b|'\s*(or|and)\s+'?\d|\b(or|and)\s+\d+\s*=\s*\d+\b|\d'$|"
                    r"\bsleep\s*\(|benchmark\s*\(|information_schema|--\s*$|;\s*drop\s+table)",
                    re.I),
         "T1190 Exploit Public-Facing Application", "HIGH"),
    Rule("Cross-Site Scripting",
         re.compile(r"(<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg|<\s*img[^>]+src)", re.I),
         "T1190 Exploit Public-Facing Application", "MEDIUM",
         escalate_on_success=False),  # reflected XSS normally returns 200; not proof of impact
    Rule("Path Traversal / LFI",
         re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|php://filter|/proc/self/environ)", re.I),
         "T1083 File and Directory Discovery", "HIGH"),
    Rule("Command Injection",
         re.compile(r"(;|\||`|\$\()\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b", re.I),
         "T1059 Command and Scripting Interpreter", "CRITICAL"),
    Rule("Sensitive File Probe",
         re.compile(r"(/\.env\b|/\.git/|/wp-config\.php|/\.htpasswd|/backup\.(zip|sql|tar))", re.I),
         "T1595.003 Active Scanning: Wordlist Scanning", "MEDIUM"),
]

SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|gobuster|dirbuster|dirb|ffuf|wfuzz|wpscan|masscan|hydra|zgrab|nuclei)", re.I
)
AUTH_PATHS = re.compile(r"/(login|signin|wp-login\.php|admin|auth|user/login|api/login)", re.I)

# CMS installers that stay on disk after setup. A production site should never
# serve them, so any hit is worth a look and a POST that gets answered is an
# emergency. Drupal's /core/install.php is the vector for "Fail2Install"
# (CVE-2026-132165, follow-up CVE-2026-136716): an anonymous POST can reinstall
# the live site and take over the user 1 admin account.
INSTALLERS = [
    ("Drupal", re.compile(r"/core/install\.php$", re.I), "CVE-2026-132165 / CVE-2026-136716"),
    ("WordPress", re.compile(r"/wp-admin/(install|setup-config)\.php$", re.I), None),
    ("Joomla", re.compile(r"/installation/(index\.php)?$", re.I), None),
]

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class Finding:
    detection: str
    severity: str
    mitre: str
    ip: str
    first_seen: str
    last_seen: str
    count: int
    evidence: str
    lines: List[int] = field(default_factory=list)


class Hunter:
    def __init__(self, window: int = 60, threshold_404: int = 15, threshold_auth: int = 10):
        self.window = window
        self.threshold_404 = threshold_404
        self.threshold_auth = threshold_auth
        self.entries: List[LogEntry] = []

    def load(self, entries: Iterable[LogEntry]) -> "Hunter":
        self.entries = sorted(entries, key=lambda e: e.time)
        return self

    # -- signature-based ---------------------------------------------------- #
    def payload_findings(self) -> List[Finding]:
        grouped: dict = defaultdict(list)
        for e in self.entries:
            target = e.decoded_path
            for rule in PAYLOAD_RULES:
                if rule.pattern.search(target):
                    grouped[(rule.name, e.ip)].append((rule, e))
        findings = []
        for (name, ip), hits in grouped.items():
            rule = hits[0][0]
            events = [h[1] for h in hits]
            findings.append(self._make(name, rule.severity, rule.mitre, ip, events,
                                       evidence=events[0].decoded_path[:120]))
            # Escalate: an attack payload that got a 2xx back may have worked
            successes = [ev for ev in events if 200 <= ev.status < 300]
            if successes and rule.escalate_on_success:
                findings.append(self._make(
                    f"Possible Successful {name}", "CRITICAL", rule.mitre, ip, successes,
                    evidence=f"HTTP {successes[0].status} returned for: {successes[0].decoded_path[:100]}"))
        return findings

    def scanner_findings(self) -> List[Finding]:
        grouped: dict = defaultdict(list)
        for e in self.entries:
            m = SCANNER_AGENTS.search(e.agent)
            if m:
                grouped[(m.group(1).lower(), e.ip)].append(e)
        return [self._make(f"Offensive Tool User-Agent ({tool})", "HIGH",
                           "T1595 Active Scanning", ip, events, evidence=events[0].agent[:120])
                for (tool, ip), events in grouped.items()]

    def installer_findings(self) -> List[Finding]:
        """Requests to CMS installers, graded by whether the installer answered."""
        grouped: dict = defaultdict(list)
        for e in self.entries:
            stem = e.decoded_path.split("?", 1)[0]
            for product, pattern, cve in INSTALLERS:
                if pattern.search(stem):
                    grouped[(product, cve, e.ip)].append(e)
                    break

        mitre = "T1190 Exploit Public-Facing Application"
        findings = []
        for (product, cve, ip), events in grouped.items():
            ref = f" ({cve})" if cve else ""
            answered = [ev for ev in events if 200 <= ev.status < 400]
            posts = [ev for ev in answered if ev.method == "POST"]
            if posts:
                # The installer accepted form data: the site may have been reinstalled
                findings.append(self._make(
                    f"Possible {product} Reinstall / Site Takeover{ref}", "CRITICAL", mitre, ip, posts,
                    evidence=f"POST {posts[0].path[:80]} answered HTTP {posts[0].status} "
                             f"- check the admin account, settings.php and new files"))
            elif answered:
                findings.append(self._make(
                    f"Exposed {product} Installer{ref}", "HIGH", mitre, ip, answered,
                    evidence=f"GET {answered[0].path[:80]} answered HTTP {answered[0].status} "
                             f"- installer is reachable from the internet, block it"))
            else:
                findings.append(self._make(
                    f"Blocked {product} Installer Probe{ref}", "LOW", mitre, ip, events,
                    evidence=f"{len(events)} request(s) refused (HTTP {events[0].status}) - block is working"))
        return findings

    # -- behaviour-based (sliding window) ----------------------------------- #
    def _burst(self, events: List[LogEntry], threshold: int) -> Optional[List[LogEntry]]:
        """Return the largest burst of events within `window` seconds, if >= threshold."""
        q: deque = deque()
        best: List[LogEntry] = []
        for e in events:
            q.append(e)
            while (e.time - q[0].time).total_seconds() > self.window:
                q.popleft()
            if len(q) > len(best):
                best = list(q)
        return best if len(best) >= threshold else None

    def bruteforce_findings(self) -> List[Finding]:
        by_ip_404: dict = defaultdict(list)
        by_ip_auth: dict = defaultdict(list)
        for e in self.entries:
            if e.status == 404:
                by_ip_404[e.ip].append(e)
            if e.method == "POST" and AUTH_PATHS.search(e.path) and e.status in (200, 401, 403):
                by_ip_auth[e.ip].append(e)

        findings = []
        for ip, events in by_ip_404.items():
            burst = self._burst(events, self.threshold_404)
            if burst:
                findings.append(self._make(
                    "Directory Brute-Force", "MEDIUM", "T1595.003 Active Scanning: Wordlist Scanning",
                    ip, burst, evidence=f"{len(burst)} x 404 within {self.window}s"))
        for ip, events in by_ip_auth.items():
            burst = self._burst(events, self.threshold_auth)
            if burst:
                failed = sum(1 for ev in burst if ev.status in (401, 403))
                findings.append(self._make(
                    "Login Brute-Force", "HIGH", "T1110 Brute Force", ip, burst,
                    evidence=f"{len(burst)} POSTs to {burst[0].path} in {self.window}s ({failed} failed)"))
                # A success after many failures is the moment an analyst cares about most
                after_fail = [ev for ev in burst if ev.status == 200]
                if failed >= self.threshold_auth - 1 and after_fail:
                    findings.append(self._make(
                        "Brute-Force Followed by Successful Login", "CRITICAL", "T1110 Brute Force",
                        ip, after_fail, evidence=f"HTTP 200 on {after_fail[0].path} after {failed} failures"))
        return findings

    # -- helpers ------------------------------------------------------------ #
    @staticmethod
    def _make(name, severity, mitre, ip, events, evidence) -> Finding:
        return Finding(
            detection=name, severity=severity, mitre=mitre, ip=ip,
            first_seen=events[0].time.isoformat(), last_seen=events[-1].time.isoformat(),
            count=len(events), evidence=evidence, lines=[e.line_no for e in events][:25],
        )

    def run(self) -> List[Finding]:
        findings = (self.payload_findings() + self.scanner_findings()
                    + self.installer_findings() + self.bruteforce_findings())
        return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.first_seen))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"


def print_report(entries: List[LogEntry], findings: List[Finding], color: bool = True) -> None:
    def c(sev: str, text: str) -> str:
        return f"{COLORS.get(sev, '')}{text}{RESET}" if color else text

    print("=" * 78)
    print(" LOG HUNTER - Web Access Log Threat Report")
    print("=" * 78)
    if entries:
        print(f" Events parsed : {len(entries)}")
        print(f" Time range    : {entries[0].time.isoformat()}  ->  {entries[-1].time.isoformat()}")
        print(f" Unique IPs    : {len({e.ip for e in entries})}")
    sev_counts = Counter(f.severity for f in findings)
    print(" Findings      : " + ", ".join(f"{c(s, s)}={sev_counts[s]}" for s in SEVERITY_ORDER if sev_counts[s])
          if findings else " Findings      : none")
    print("-" * 78)

    for i, f in enumerate(findings, 1):
        print(f"[{i:02}] {c(f.severity, f.severity):<8} {f.detection}")
        print(f"     Source IP : {f.ip}    Events: {f.count}")
        print(f"     MITRE     : {f.mitre}")
        print(f"     Window    : {f.first_seen} -> {f.last_seen}")
        print(f"     Evidence  : {f.evidence}")
        print(f"     Log lines : {', '.join(map(str, f.lines[:10]))}{' ...' if len(f.lines) > 10 else ''}")
        print()

    # Top talkers help the analyst scope the incident
    if findings:
        print("-" * 78)
        print(" Suspicious IPs ranked by highest severity, then finding count:")
        per_ip: dict = defaultdict(list)
        for f in findings:
            per_ip[f.ip].append(f)
        ranked = sorted(per_ip.items(),
                        key=lambda kv: (-max(SEVERITY_ORDER[f.severity] for f in kv[1]), -len(kv[1])))
        for ip, fs in ranked:
            top = max(fs, key=lambda f: SEVERITY_ORDER[f.severity]).severity
            print(f"   {ip:<16} {c(top, top):<8} {len(fs)} finding(s)")
    print("=" * 78)


def write_json(path: str, findings: List[Finding]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)


def write_csv(path: str, findings: List[Finding]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(findings[0]).keys()) if findings else ["detection"])
        writer.writeheader()
        for f in findings:
            row = asdict(f)
            row["lines"] = " ".join(map(str, row["lines"]))
            writer.writerow(row)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Hunt for attacks in Nginx/Apache access logs.")
    ap.add_argument("logfile", help="Path to access log (combined format)")
    ap.add_argument("--window", type=int, default=60, help="Sliding window in seconds (default 60)")
    ap.add_argument("--threshold", type=int, default=15, help="404s per window for directory brute-force")
    ap.add_argument("--auth-threshold", type=int, default=10, help="Auth POSTs per window for login brute-force")
    ap.add_argument("--json", help="Write findings to a JSON file")
    ap.add_argument("--csv", help="Write findings to a CSV file")
    ap.add_argument("--no-color", action="store_true", help="Disable coloured output")
    args = ap.parse_args(argv)

    with open(args.logfile, encoding="utf-8", errors="replace") as fh:
        entries = list(read_log(fh))
    if not entries:
        print("No parsable log lines found. Is this a combined-format access log?", file=sys.stderr)
        return 1

    hunter = Hunter(args.window, args.threshold, args.auth_threshold).load(entries)
    findings = hunter.run()
    print_report(hunter.entries, findings, color=not args.no_color and sys.stdout.isatty())

    if args.json:
        write_json(args.json, findings)
        print(f"JSON report written to {args.json}")
    if args.csv:
        write_csv(args.csv, findings)
        print(f"CSV report written to {args.csv}")
    return 2 if any(f.severity == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
