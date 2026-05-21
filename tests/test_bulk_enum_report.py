#!/usr/bin/env python3
"""test_bulk_enum_report.py — J.3 unit tests for report.py's bulk-enum mode.

Asserts:
  * _is_bulk_enum_dir() correctly identifies the bulk layout
  * walk_findings_bulk() applies _BULK_RULES to each host's linenum.txt
  * _per_host_verdicts() assigns the right verdict per host (max-severity rule)
  * The four checked-in fixtures (web01/db02/app03/old04) hit the expected
    verdict tiers

Run with: python3 -m unittest tests.test_bulk_enum_report
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO        = Path(__file__).resolve().parent.parent
REPORT_PATH = REPO / "network" / "report.py"
FIXTURES    = REPO / "tests" / "fixtures" / "bulk-enum"


def _load_report_module():
    spec = importlib.util.spec_from_file_location("report_mod", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report_module()


# --------------------------------------------------------------------- layout
class TestLayoutDetection(unittest.TestCase):
    def test_fixtures_dir_detected_as_bulk(self):
        self.assertTrue(R._is_bulk_enum_dir(FIXTURES),
                        f"{FIXTURES} should be detected as bulk-enum layout")

    def test_empty_dir_not_bulk(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(R._is_bulk_enum_dir(Path(td)))

    def test_auto_enum_layout_not_bulk(self):
        # Synthesize an auto-enum-style layout: $OUT/<service>/<host>/...
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "smb" / "10.0.0.1").mkdir(parents=True)
            (p / "smb" / "10.0.0.1" / "shares.txt").write_text("share1\n")
            self.assertFalse(R._is_bulk_enum_dir(p))


# --------------------------------------------------------------------- walker + verdicts
class TestBulkVerdicts(unittest.TestCase):
    """Anchor on the checked-in fixtures so this test is the canonical
    contract for the verdict semantics."""

    EXPECTED = {
        # Linux fixtures (J)
        "web01":            "critical",   # NOPASSWD sudo
        "db02":             "critical",   # cap_setuid + perl SUID
        "app03":            "high",       # writable systemd + cred-in-history
        "old04":            "medium",     # non-gtfobin SUID + old kernel
        # Windows fixtures (K)
        "win-svc-imperson": "critical",   # SeImpersonate ENABLED + AlwaysInstallElevated + WRITABLE BINARY
        "win-backup-op":    "high",       # SeBackup ENABLED + Account Operators + SYSTEM task + writable PATH
        "win-old-rdp":      "medium",     # Remote Desktop Users + cred-in-file + EOL Win7
    }
    EXPECTED_OS = {
        "web01": "linux", "db02": "linux", "app03": "linux", "old04": "linux",
        "win-svc-imperson": "windows",
        "win-backup-op":    "windows",
        "win-old-rdp":      "windows",
    }

    def setUp(self):
        self.findings = list(R.walk_findings_bulk(FIXTURES, []))
        self.per_host = R._per_host_verdicts(self.findings)

    def test_every_fixture_host_has_findings(self):
        hosts_with_findings = {f["host"] for f in self.findings}
        self.assertEqual(hosts_with_findings, set(self.EXPECTED.keys()),
                         f"Findings host set mismatch: {hosts_with_findings}")

    def test_finding_service_matches_evidence_file(self):
        # Every Linux fixture finding should be tagged 'linenum'; every Windows
        # fixture finding should be tagged 'winenum'. Mixed-OS detection in
        # report.py uses this attribution.
        for f in self.findings:
            if f["host"].startswith("win-"):
                self.assertEqual(f["service"], "winenum", f"{f}")
            else:
                self.assertEqual(f["service"], "linenum", f"{f}")

    def test_per_host_verdicts_match_expected(self):
        for host, expected_verdict in self.EXPECTED.items():
            self.assertIn(host, self.per_host, f"{host} missing from per_host")
            actual = self.per_host[host]["verdict"]
            self.assertEqual(actual, expected_verdict,
                             f"{host}: expected verdict={expected_verdict}, got {actual}")

    def test_per_host_os_tagged_correctly(self):
        for host, expected_os in self.EXPECTED_OS.items():
            self.assertIn(host, self.per_host, f"{host} missing from per_host")
            self.assertEqual(self.per_host[host]["os"], expected_os,
                             f"{host}: expected os={expected_os}, got {self.per_host[host]['os']}")

    def test_se_disabled_hint_does_not_false_positive_critical(self):
        # Regression: `Privilege.*ENABLED` re.I previously matched the
        # disabled hint `(disabled — can still be enabled)`. The literal-
        # parens anchor `\(ENABLED\)` (no re.I) fixes this.
        for f in self.findings:
            if "(disabled" in f["line"] and "Privilege" in f["line"]:
                self.assertNotEqual(f["severity"], "critical",
                    f"disabled-hint should NOT be critical: {f}")

    def test_findings_have_required_fields(self):
        for f in self.findings:
            for k in ("host", "port", "service", "severity", "line", "evidence_path"):
                self.assertIn(k, f, f"finding missing field {k}: {f}")
            self.assertIn(f["severity"], R._SEV_ORDER)

    def test_evidence_paths_relative(self):
        for f in self.findings:
            # Evidence paths must be relative to out_dir so reports survive being
            # moved to a different filesystem path.
            self.assertFalse(Path(f["evidence_path"]).is_absolute(),
                             f"evidence_path must be relative: {f['evidence_path']}")


# --------------------------------------------------------------------- end-to-end CLI
class TestCLIBulkMode(unittest.TestCase):
    def test_cli_produces_findings_json_with_per_host(self):
        with tempfile.TemporaryDirectory() as td:
            # report.py writes outputs INTO out_dir, so we copy fixtures to a
            # writable temp dir first.
            for host_dir in FIXTURES.iterdir():
                if not host_dir.is_dir():
                    continue
                dst = Path(td) / host_dir.name
                dst.mkdir()
                for f in host_dir.iterdir():
                    (dst / f.name).write_bytes(f.read_bytes())
            p = subprocess.run(
                [sys.executable, str(REPORT_PATH), td, "--label", "test-bulk"],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, f"report.py failed: {p.stderr}")
            self.assertIn("bulk-enum layout detected", p.stdout)
            findings = json.loads((Path(td) / "findings.json").read_text())
            self.assertEqual(findings["mode"], "bulk-enum")
            self.assertIn("per_host", findings)
            # Per-host map should preserve worst-first ordering
            verdicts = [v["verdict"] for v in findings["per_host"].values()]
            sev_rank = ["critical", "high", "medium", "low"]
            indexed = [sev_rank.index(v) for v in verdicts]
            self.assertEqual(indexed, sorted(indexed),
                             "per_host should be sorted worst-first")
            # report.md + report.html written
            self.assertTrue((Path(td) / "report.md").is_file())
            self.assertTrue((Path(td) / "report.html").is_file())
            html_text = (Path(td) / "report.html").read_text()
            self.assertIn("Per-host privesc verdict (bulk-enum)", html_text)


if __name__ == "__main__":
    unittest.main()
