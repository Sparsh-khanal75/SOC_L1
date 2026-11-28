"""Unit tests for Log Hunter. Run with:  python -m unittest -v"""
import unittest

from log_hunter import Hunter, parse_line

UA = "Mozilla/5.0"


def line(ip, time, method, path, status, agent=UA):
    return f'{ip} - - [20/Nov/2026:09:{time} +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{agent}"'


def hunt(raw_lines, **kw):
    entries = [parse_line(l, i) for i, l in enumerate(raw_lines, 1)]
    return Hunter(**kw).load([e for e in entries if e]).run()


def names(findings):
    return {f.detection for f in findings}


class ParserTests(unittest.TestCase):
    def test_parses_combined_format(self):
        e = parse_line(line("10.0.0.1", "00:01", "GET", "/index.html", 200), 1)
        self.assertEqual((e.ip, e.method, e.path, e.status), ("10.0.0.1", "GET", "/index.html", 200))

    def test_rejects_garbage(self):
        self.assertIsNone(parse_line("this is not a log line", 1))

    def test_double_url_decoding(self):
        e = parse_line(line("10.0.0.1", "00:01", "GET", "/p?id=1%2527", 200), 1)
        self.assertIn("'", e.decoded_path)


class DetectionTests(unittest.TestCase):
    def test_benign_traffic_is_quiet(self):
        logs = [line("10.0.0.5", f"00:{i:02}", "GET", "/products?id=3", 200) for i in range(30)]
        self.assertEqual(hunt(logs), [])

    def test_sql_injection(self):
        f = hunt([line("1.2.3.4", "00:01", "GET", "/p?id=1%20UNION%20SELECT%20NULL--", 500)])
        self.assertIn("SQL Injection", names(f))

    def test_successful_lfi_escalates_to_critical(self):
        f = hunt([line("1.2.3.4", "00:01", "GET", "/dl?file=../../etc/passwd", 200)])
        self.assertIn("Possible Successful Path Traversal / LFI", names(f))
        self.assertEqual(f[0].severity, "CRITICAL")

    def test_xss_200_is_not_escalated(self):
        f = hunt([line("1.2.3.4", "00:01", "GET", "/s?q=<script>alert(1)</script>", 200)])
        self.assertEqual(names(f), {"Cross-Site Scripting"})

    def test_scanner_user_agent(self):
        f = hunt([line("1.2.3.4", "00:01", "GET", "/", 200, agent="Nikto/2.5.0")])
        self.assertIn("Offensive Tool User-Agent (nikto)", names(f))

    def test_directory_bruteforce_window(self):
        burst = [line("1.2.3.4", f"00:{i:02}", "GET", f"/dir{i}", 404) for i in range(20)]
        self.assertIn("Directory Brute-Force", names(hunt(burst)))
        # Same number of 404s spread over 20 minutes should NOT alert
        slow = [line("1.2.3.4", f"{i:02}:00", "GET", f"/dir{i}", 404) for i in range(20)]
        self.assertNotIn("Directory Brute-Force", names(hunt(slow)))

    def test_login_bruteforce_then_success(self):
        logs = [line("9.9.9.9", f"00:{i:02}", "POST", "/login", 401) for i in range(12)]
        logs.append(line("9.9.9.9", "00:13", "POST", "/login", 200))
        found = names(hunt(logs))
        self.assertIn("Login Brute-Force", found)
        self.assertIn("Brute-Force Followed by Successful Login", found)


class InstallerTests(unittest.TestCase):
    """Drupal Fail2Install (CVE-2026-132165) and other exposed CMS installers."""

    def test_answered_installer_post_is_critical(self):
        f = hunt([line("5.5.5.5", "00:01", "GET", "/core/install.php", 200),
                  line("5.5.5.5", "00:02", "POST", "/core/install.php?langcode=en&profile=standard", 200)])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("CVE-2026-132165", f[0].detection)

    def test_reachable_installer_is_high(self):
        f = hunt([line("5.5.5.5", "00:01", "GET", "/core/install.php", 200)])
        self.assertEqual([(x.detection.split(" (")[0], x.severity) for x in f],
                         [("Exposed Drupal Installer", "HIGH")])

    def test_blocked_probe_is_low(self):
        f = hunt([line("5.5.5.5", "00:01", "POST", "/core/install.php", 403),
                  line("5.5.5.5", "00:02", "GET", "/core/install.php", 404)])
        self.assertEqual(f[0].severity, "LOW")

    def test_subdirectory_and_encoded_paths(self):
        f = hunt([line("5.5.5.5", "00:01", "GET", "/drupal/core/install%2Ephp?profile=minimal", 200)])
        self.assertIn("Exposed Drupal Installer", f[0].detection)

    def test_wordpress_setup_config(self):
        f = hunt([line("5.5.5.5", "00:01", "GET", "/wp-admin/setup-config.php", 200)])
        self.assertEqual(names(f), {"Exposed WordPress Installer"})

    def test_lookalike_paths_are_ignored(self):
        logs = [line("10.0.0.5", "00:01", "GET", "/core/install.php.html", 200),
                line("10.0.0.5", "00:02", "GET", "/docs/core/install-guide", 200),
                line("10.0.0.5", "00:03", "GET", "/core/misc/drupal.js", 200)]
        self.assertEqual(hunt(logs), [])


class HtmlReportTests(unittest.TestCase):
    def test_html_report_from_sample_log(self):
        import os
        import tempfile

        from log_hunter import main

        here = os.path.dirname(os.path.abspath(__file__))
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.html")
            main([os.path.join(here, "sample_logs", "access.log"), "--html", out, "--no-color"])
            with open(out, encoding="utf-8") as fh:
                page = fh.read()
        self.assertIn("Web access-log hunt", page)
        self.assertIn("Brute-Force Followed by Successful Login", page)
        self.assertNotIn("<script>alert(document.cookie)", page)  # payloads are escaped


if __name__ == "__main__":
    unittest.main()
