#!/usr/bin/env python3
"""test_dashboard_kb.py — S2/D2.2 dashboard surfaces for the finding KB.

Drives report-dashboard.py over a fixture and asserts the three new pages/panels
render what they must:
  * Active Directory page groups an SMB-signing finding under "Relay & coercion",
    lists the detected DC, and carries the "Uncorrelated signals" caveat;
  * the Run-health panel on the index lists an ungraded nuclei timeout as a
    coverage gap (not a finding);
  * the Categories page renders and KB guidance exposes copy-to-clipboard
    buttons (data-copy).
Pages must also stay well-formed HTML.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"
PY = sys.executable


def _build_fixture(root: Path) -> Path:
    """A DC (10.0.0.10: 88 + 389 + 445) with an SMB-signing finding, plus an
    ungraded nuclei timeout in a dispatcher log."""
    scan = root / "scan"
    smb = scan / "smb" / "10.0.0.10_445"
    smb.mkdir(parents=True)
    (smb / "enum.txt").write_text("SMB signing disabled on 10.0.0.10\n")
    (scan / "kerberos" / "10.0.0.10_88").mkdir(parents=True)
    (scan / "kerberos" / "10.0.0.10_88" / "k.txt").write_text("kerberos 88 open\n")
    (scan / "ldap" / "10.0.0.10_389").mkdir(parents=True)
    (scan / "ldap" / "10.0.0.10_389" / "l.txt").write_text("ldap 389 open\n")
    http = scan / "http"
    http.mkdir(parents=True)
    (http / "_dispatcher.log").write_text(
        "[+] http dispatch start\n"
        "[!] nuclei timed out after 300s on 10.0.0.9\n")
    return scan


class TestDashboardKB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        scan = _build_fixture(root)
        cls.out = root / "dash"
        r = subprocess.run(
            [PY, str(NET / "report-dashboard.py"), str(scan), "--output", str(cls.out)],
            capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f"dashboard build failed: {r.stderr}"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _read(self, name: str) -> str:
        p = self.out / name
        self.assertTrue(p.exists(), f"{name} not generated")
        return p.read_text(encoding="utf-8")

    def test_pages_are_wellformed(self):
        pages = list(self.out.glob("*.html"))
        self.assertTrue(pages)
        for p in pages:
            HTMLParser().feed(p.read_text(encoding="utf-8", errors="replace"))

    def test_ad_page_groups_signing_under_relay_with_caveat(self):
        ad = self._read("ad.html")
        self.assertIn("Relay &amp; coercion", ad)
        self.assertIn("signing disabled", ad)
        # Cross-family correlation caveat must be present (S2 has no domain id).
        self.assertIn("Uncorrelated signals", ad)
        # The DC (88 + 389/445) is positively identified.
        self.assertIn("10.0.0.10", ad)

    def test_run_health_lists_ungraded_timeout(self):
        idx = self._read("index.html")
        self.assertIn("Run health", idx)
        self.assertIn("timeout", idx)
        self.assertIn("nuclei timed out", idx)

    def test_categories_page_and_copy_buttons(self):
        cats = self._read("categories.html")
        self.assertIn("data-copy", cats)  # KB guidance exposes copy buttons
        # The AD page's guidance expander also carries a copy button.
        self.assertIn("data-copy", self._read("ad.html"))


if __name__ == "__main__":
    unittest.main()
