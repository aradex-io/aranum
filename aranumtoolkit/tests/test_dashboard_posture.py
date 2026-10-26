#!/usr/bin/env python3
"""test_dashboard_posture.py — S3/D3.5 dashboard posture surfaces.

Drives report-dashboard.py over a bulk fixture with POSTURE lines from two
domain-joined Windows hosts and one Linux host, and asserts:
  * the Posture page carries the host x group matrix (ERR excluded from the
    score) and a per-check table with KB guidance for failing checks;
  * a host page carries a Posture card with domain membership;
  * the AD page renders a Domain posture table (canonical status, conflict
    note, every observer kept), ties host findings to the posture-established
    domain, and files posture relay findings under "Relay & coercion";
  * a domain-scope finding never becomes a host row or host page;
  * a quarantined POSTURE line is surfaced in Run health.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"
PY = sys.executable

_HOSTS = {
    "win1": ("10.0.0.31", "winenum.txt",
             "POSTURE|WIN-SMB-SRVSIGN|FAIL|RequireSecuritySignature=0\n"
             "POSTURE|WIN-CRED-WDIGEST|PASS|UseLogonCredential=0\n"
             "POSTURE|WIN-DOMAIN-JOINED|INFO|domain=corp.local role=member\n"
             "POSTURE|AD-PWPOL-MINLEN|FAIL|domain=corp.local observer=win1 minPwdLength=7\n"
             "POSTURE|AD-MAQ|WARN|domain=corp.local observer=win1 ms-DS-MachineAccountQuota=10\n"
             "POSTURE|WIN-BOGUS|FAIL|x\n"),
    "win2": ("10.0.0.32", "winenum.txt",
             "POSTURE|WIN-SMB-SRVSIGN|PASS|RequireSecuritySignature=1\n"
             "POSTURE|AD-PWPOL-MINLEN|PASS|domain=corp.local observer=win2 minPwdLength=14\n"
             "POSTURE|AD-MAQ|ERR|domain=corp.local observer=win2 ldap timeout\n"),
    "lin1": ("10.0.0.21", "linenum.txt",
             "POSTURE|LIN-SSH-ROOTLOGIN|FAIL|PermitRootLogin yes (sshd_config)\n"
             "POSTURE|LIN-SYSCTL-ASLR|PASS|kernel.randomize_va_space=2\n"
             "POSTURE|LIN-ACCT-EMPTYPW|ERR|shadow unreadable\n"),
}


def _section(html: str, start_marker: str, end_marker: str = "</section>") -> str:
    i = html.find(start_marker)
    assert i != -1, f"section {start_marker!r} missing"
    return html[i:html.find(end_marker, i)]


class TestDashboardPosture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        scan = root / "scan"
        for name, (ip, fname, text) in _HOSTS.items():
            d = scan / name
            d.mkdir(parents=True)
            (d / "_meta.json").write_text(json.dumps({"host": ip, "port": 22, "status": "OK"}))
            (d / fname).write_text(text)
        cls.out = root / "dash"
        r = subprocess.run([PY, str(NET / "report-dashboard.py"), str(scan), "--output", str(cls.out)],
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
        for p in self.out.glob("*.html"):
            HTMLParser().feed(p.read_text(encoding="utf-8", errors="replace"))

    def test_posture_page_matrix_and_checks(self):
        page = self._read("posture.html")
        self.assertIn('href="posture.html"', page)          # in the navbar
        matrix = _section(page, "Host × group")
        for ip in ("10.0.0.21", "10.0.0.31", "10.0.0.32"):
            self.assertIn(ip, matrix)
        # Linux host: PASS 1, FAIL 1, ERR 1 -> score 50% (ERR is not graded).
        row = re.search(r"10\.0\.0\.21</code></a>.*?</tr>", matrix, re.S).group(0)
        self.assertIn(">50%<", row)
        self.assertIn('class="pm pm-err"', row)
        checks = _section(page, "Checks across hosts")
        smb = re.search(r"WIN-SMB-SRVSIGN</code></td>.*?</tr>", checks, re.S).group(0)
        self.assertIn("chip-st-fail", smb)
        self.assertIn("RequireSecuritySignature=0", smb)
        self.assertIn("data-copy", smb)                     # KB test/fix commands
        self.assertNotIn("AD-PWPOL-MINLEN", page)           # domain checks live on the AD page

    def test_host_page_posture_card(self):
        page = self._read("host_10.0.0.31.html")
        card = _section(page, 'id="posture"')
        self.assertIn("member of <code class=\"mono\">corp.local</code>", card)
        self.assertIn("WIN-CRED-WDIGEST", card)
        self.assertIn("chip-st-pass", card)

    def test_ad_page_domain_posture_and_correlation(self):
        page = self._read("ad.html")
        dom = _section(page, "Domain posture · ")
        minlen = re.search(r"AD-PWPOL-MINLEN</code></td>.*?</tr>", dom, re.S).group(0)
        self.assertIn("chip-st-fail", minlen)
        self.assertIn("conflict: 10.0.0.31=FAIL 10.0.0.32=PASS", minlen)
        self.assertIn("10.0.0.31", minlen)
        self.assertIn("10.0.0.32", minlen)                  # the PASS observer is kept
        maq = re.search(r"AD-MAQ</code></td>.*?</tr>", dom, re.S).group(0)
        self.assertIn("chip-st-warn", maq)                  # WARN beats the ERR observer
        self.assertIn("chip-st-err", maq)
        self.assertIn("Confirmed domain context", page)
        relay = _section(page, "Relay &amp; coercion")
        self.assertIn("10.0.0.31", relay)
        self.assertIn("<code class=\"mono\">corp.local</code>", relay)

    def test_domain_scope_never_becomes_a_host(self):
        self.assertFalse((self.out / "host_corp.local.html").exists())
        self.assertNotIn("corp.local", self._read("hosts.html"))

    def test_run_health_lists_quarantined_posture_line(self):
        idx = self._read("index.html")
        health = _section(idx, "Run health")
        self.assertIn("quarantined", health)
        self.assertIn("unknown posture check id WIN-BOGUS", health)


class TestDashboardWithoutPosture(unittest.TestCase):
    def test_empty_posture_page_explains_how_to_collect(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan" / "smb" / "10.0.0.10_445"
            scan.mkdir(parents=True)
            (scan / "enum.txt").write_text("SMB signing disabled on 10.0.0.10\n")
            out = Path(tmp) / "dash"
            r = subprocess.run([PY, str(NET / "report-dashboard.py"), str(Path(tmp) / "scan"),
                                "--output", str(out)], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("No host posture collected", (out / "posture.html").read_text())
            ad = (out / "ad.html").read_text()
            self.assertIn("Uncorrelated signals", ad)
            self.assertNotIn("Confirmed domain context", ad)
            self.assertNotIn("Domain posture · ", ad)


if __name__ == "__main__":
    unittest.main()
