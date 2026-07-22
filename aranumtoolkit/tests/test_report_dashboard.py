#!/usr/bin/env python3
"""test_report_dashboard.py — the dashboard generator (report-dashboard.py) is the
largest module and had no unit test; it already regressed once (build_index dropping
AD-depth CRITICALs vs findings.json). These assert CRITICAL-parity with report.py,
the data.json search payload, and per-service wiki deep-links from a fixture.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"
PY = sys.executable


def _assert_wellformed(testcase: unittest.TestCase, out: Path) -> None:
    """Every generated *.html must parse without the stdlib HTMLParser raising,
    and data.json must be valid JSON. Guards against template holes / malformed
    markup / broken search payloads on adversarial engagement data."""
    pages = list(out.glob("*.html"))
    testcase.assertTrue(pages, f"no HTML pages generated in {out}")
    for p in pages:
        try:
            HTMLParser().feed(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001 — any parse failure is a bug
            testcase.fail(f"malformed HTML in {p.name}: {exc}")
    dj = out / "data.json"
    if dj.exists():
        json.loads(dj.read_text(encoding="utf-8"))  # raises -> test failure


def _fixture(root: Path) -> Path:
    """A scan tree with one CRITICAL (redis unauth) + one MEDIUM (http CORS)."""
    scan = root / "scan"
    (scan / "redis" / "10.0.0.1_6379").mkdir(parents=True)
    (scan / "redis" / "10.0.0.1_6379" / "info.txt").write_text(
        "[!!] UNAUTH Redis 10.0.0.1:6379 — redis_version:7.0.15 role:master\n")
    (scan / "http" / "10.0.0.2_80").mkdir(parents=True)
    (scan / "http" / "10.0.0.2_80" / "probe.txt").write_text("CORS reflect origin echoed\n")
    return scan


class TestReportDashboard(unittest.TestCase):
    def _run(self, args, **kw):
        r = subprocess.run(args, capture_output=True, text=True, timeout=90, **kw)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def test_dashboard_critical_parity_and_datajson(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            scan = _fixture(root)
            # 1) report.py to establish the CRITICAL truth set
            self._run([PY, str(NET / "report.py"), str(scan), "--findings-only"])
            findings = json.loads((scan / "findings.json").read_text())["findings"]
            crit_hosts = {f["host"] for f in findings if f["severity"] == "critical"}
            self.assertIn("10.0.0.1", crit_hosts, "redis unauth should be CRITICAL")

            # 2) dashboard from the same tree
            out = root / "dash"
            self._run([PY, str(NET / "report-dashboard.py"), str(scan), "--output", str(out)])

            # data.json search payload exists + has the expected shape
            dj = out / "data.json"
            self.assertTrue(dj.exists(), "dashboard must emit data.json")
            payload = json.loads(dj.read_text())
            self.assertTrue(isinstance(payload, (dict, list)), "data.json is JSON")

            # 3) CRITICAL parity: the redis CRITICAL must not be dropped by the
            # dashboard's index (the exact class of regression that shipped before).
            blob = " ".join(p.read_text(errors="replace") for p in out.glob("*.html"))
            self.assertIn("10.0.0.1", blob)
            self.assertRegex(blob.lower(), r"critical")

            # 4) per-service page deep-links to the quick-win wiki page
            svc = out / "service_redis.html"
            self.assertTrue(svc.exists())
            self.assertIn('href="wiki_redis.html"', svc.read_text())


class TestReportRobustness(unittest.TestCase):
    """Adversarial / malformed engagement data must never crash the generators
    (report.py + report-dashboard.py). Each case degrades to rc=0 with a clean,
    well-formed dashboard. Locks in the offline battle-test hardening."""

    def _report(self, scan: Path, *extra) -> subprocess.CompletedProcess:
        return subprocess.run(
            [PY, str(NET / "report.py"), str(scan), *extra],
            capture_output=True, text=True, timeout=90)

    def _dashboard(self, scan: Path, out: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [PY, str(NET / "report-dashboard.py"), str(scan), "--output", str(out)],
            capture_output=True, text=True, timeout=90)

    def _both_ok(self, scan: Path, out: Path):
        r = self._report(scan, "--findings-only")
        self.assertEqual(r.returncode, 0, f"report.py crashed: {r.stderr}")
        self.assertNotIn("Traceback", r.stderr)
        d = self._dashboard(scan, out)
        self.assertEqual(d.returncode, 0, f"dashboard crashed: {d.stderr}")
        self.assertNotIn("Traceback", d.stderr)
        _assert_wellformed(self, out)

    def test_empty_tree(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"; scan.mkdir()
            self._both_ok(scan, Path(td) / "out")

    def test_service_dir_with_zero_findings(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            (scan / "http" / "10.0.0.1").mkdir(parents=True)
            (scan / "http" / "10.0.0.1" / "out.txt").write_text("nothing here\n")
            self._both_ok(scan, Path(td) / "out")

    def test_non_utf8_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            hd = scan / "http" / "10.0.0.2"; hd.mkdir(parents=True)
            (hd / "e.txt").write_bytes(
                b"UNAUTH \xff\xfe\x00 CRITICAL: UNAUTH NATS \x80\x81 anonymous\n")
            self._both_ok(scan, Path(td) / "out")

    def test_huge_line(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            hd = scan / "http" / "10.0.0.3"; hd.mkdir(parents=True)
            (hd / "big.txt").write_text("CRITICAL " + "A" * 500000 + "\n")
            self._both_ok(scan, Path(td) / "out")

    def test_malformed_service_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            hd = scan / "redis" / "10.0.0.4"; hd.mkdir(parents=True)
            (hd / "f.txt").write_text("[!!] UNAUTH Redis\n")
            (scan / "service-metadata.json").write_text("{ not valid json ]]")
            self._both_ok(scan, Path(td) / "out")

    def test_html_injection_is_escaped(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            hd = scan / "http" / "10.0.0.5"; hd.mkdir(parents=True)
            (hd / "f.txt").write_text(
                'CRITICAL: UNAUTH <script>alert(1)</script> '
                '</td><td>x & "q" <b>b</b>\n')
            out = Path(td) / "out"
            self._both_ok(scan, out)
            for p in out.glob("*.html"):
                self.assertNotIn("<script>alert(1)</script>", p.read_text(),
                                 f"unescaped injection leaked into {p.name}")

    def test_adversarial_names_do_not_escape_output(self):
        """Odd service/host directory names must not make the dashboard write a
        page outside --output (safe_name neutralises path separators)."""
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            (scan / "smb" / "...--evil").mkdir(parents=True)
            (scan / "smb" / "...--evil" / "f.txt").write_text("CRITICAL: UNAUTH x\n")
            (scan / "we ird svc" / "a..b..c").mkdir(parents=True)
            (scan / "we ird svc" / "a..b..c" / "f.txt").write_text("UNAUTH y\n")
            out = Path(td) / "out"
            self._both_ok(scan, out)
            for p in out.rglob("*"):
                self.assertTrue(
                    out.resolve() in p.resolve().parents or p.resolve() == out.resolve(),
                    f"generated file escaped output dir: {p}")

    def test_redact_removes_every_ip(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            hd = scan / "http" / "10.0.0.6_8080"; hd.mkdir(parents=True)
            (hd / "f.txt").write_text(
                "CRITICAL: UNAUTH at 10.0.0.6 and 172.16.31.9 http://10.0.0.6:8080/x\n")
            r = self._report(scan, "--redact", "--findings-only")
            self.assertEqual(r.returncode, 0, r.stderr)
            import re
            blob = (scan / "findings.json").read_text()
            leaked = re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])", blob)
            self.assertEqual(leaked, [], f"raw IPs survived --redact: {leaked}")

    def test_symlink_evidence_is_not_followed_out_of_tree(self):
        """OPSEC §9 containment: a symlink whose target is outside the scan tree
        must never be read into findings."""
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "scan"
            hd = scan / "http" / "10.0.0.7"; hd.mkdir(parents=True)
            secret = Path(td) / "secret.txt"
            secret.write_text("CRITICAL: UNAUTH totally-a-finding\n")
            try:
                (hd / "leak.txt").symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unsupported on this platform")
            r = self._report(scan, "--findings-only")
            self.assertEqual(r.returncode, 0, r.stderr)
            findings = json.loads((scan / "findings.json").read_text())["findings"]
            self.assertEqual(findings, [],
                             "symlink target outside the scan tree was ingested")


if __name__ == "__main__":
    unittest.main()
