#!/usr/bin/env python3
"""test_ad_signals.py — D1.6 unit tests for report.py AD-depth severity rules.

Each fixture under tests/fixtures/ad-signals/ exercises one rule class added
by D1.5 (_AD_DEPTH_RULES). The tests construct a minimal auto-enum-style
output dir, drop the fixture file under a service subdir, and assert
report.py classifies it with the expected severity.

Run with: python3 -m unittest tests.test_ad_signals
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
FIXTURES    = REPO / "tests" / "fixtures" / "ad-signals"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_d15", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def _classify_fixture(fixture_dir: Path) -> dict[str, int]:
    """Drop each line through the AD-depth rules; return {severity: count}."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for fp in fixture_dir.iterdir():
        if not fp.is_file():
            continue
        for line in fp.read_text().splitlines():
            sev = R._classify(line, R._AD_DEPTH_RULES)
            if sev:
                counts[sev] += 1
    return counts


class TestADDepthRules(unittest.TestCase):
    """Each rule class has a dedicated fixture; we assert the expected
    severity COUNT (not exact lines) so a future regex tightening that
    matches fewer false-positives doesn't break the test if the SEMANTICS
    are still right."""

    def test_certipy_esc1_classified_critical(self):
        c = _classify_fixture(FIXTURES / "certipy-esc1")
        self.assertGreaterEqual(c["critical"], 1,
            "Certipy ESC1 (Vulnerable) line must classify CRITICAL")

    def test_bloodhound_zip_classified_high(self):
        c = _classify_fixture(FIXTURES / "bloodhound-zip")
        self.assertGreaterEqual(c["high"], 1,
            "BLOODHOUND_ZIP: signal must classify HIGH")

    def test_gpp_cpassword_classified_critical(self):
        c = _classify_fixture(FIXTURES / "gpp-cpassword")
        self.assertGreaterEqual(c["critical"], 1,
            "GPP cpassword= match must classify CRITICAL")

    def test_laps_cleartext_critical_encrypted_high(self):
        c = _classify_fixture(FIXTURES / "laps-readable")
        self.assertGreaterEqual(c["critical"], 1,
            "LAPS cleartext-readable must classify CRITICAL")
        self.assertGreaterEqual(c["high"], 1,
            "LAPS encrypted-blob must classify HIGH")

    def test_unconstrained_delegation_classified_high(self):
        c = _classify_fixture(FIXTURES / "delegation-uncons")
        self.assertGreaterEqual(c["high"], 1,
            "UNCONSTRAINED DELEGATION account-count line must classify HIGH")

    def test_printnightmare_exploitable_classified_critical(self):
        c = _classify_fixture(FIXTURES / "pn-exploitable")
        self.assertGreaterEqual(c["critical"], 1,
            "PrintNightmare exploitable-config line must classify CRITICAL")


class TestCLIIntegrationAuto(unittest.TestCase):
    """End-to-end: drop a Certipy fixture into a synthetic auto-enum tree
    and verify report.py picks up the AD-depth rule via CLI."""

    def test_certipy_fixture_surfaces_in_findings_json(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            # Synthesize auto-enum layout: <out>/ldap/10.0.0.10_389/<fixture>
            (out / "ldap" / "10.0.0.10_389").mkdir(parents=True)
            src = FIXTURES / "certipy-esc1" / "certipy_20260520.txt"
            (out / "ldap" / "10.0.0.10_389" / "certipy.txt").write_bytes(src.read_bytes())
            p = subprocess.run(
                [sys.executable, str(REPORT_PATH), str(out), "--label", "ad-test"],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, f"report.py: {p.stderr}")
            d = json.loads((out / "findings.json").read_text())
            # Should be auto-enum mode (no _meta.json + linenum.txt)
            self.assertEqual(d["mode"], "auto-enum")
            crit = [f for f in d["findings"] if f["severity"] == "critical"]
            self.assertGreater(len(crit), 0, "Certipy ESC1 fixture should produce critical findings")
            esc1 = [f for f in crit if "ESC1" in f["line"]]
            self.assertGreater(len(esc1), 0, "At least one CRITICAL should mention ESC1")


if __name__ == "__main__":
    unittest.main()
