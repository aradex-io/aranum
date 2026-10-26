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

    def test_domain_findings_link_to_the_domain_not_a_host_page(self):
        # R7: a domain-scope finding is labelled "domain" and links to that domain's
        # posture section on the AD page -- on every page that lists findings.
        pages = {p.name: p.read_text(encoding="utf-8") for p in self.out.glob("*.html")}
        pages["data.json"] = (self.out / "data.json").read_text(encoding="utf-8")
        self.assertFalse([n for n, t in pages.items() if "host_corp.local.html" in t])
        # The subject exists: the domain findings are still listed, with the new link.
        for name in ("index.html", "inbox.html", "categories.html", "severity_high.html",
                     "service_posture.html", "data.json"):
            self.assertIn("ad.html#domain-corp.local", pages[name], name)
        self.assertIn('<span class="chip chip-scope">domain</span>', pages["inbox.html"])
        self.assertIn('id="domain-corp.local"', pages["ad.html"])     # the anchor target exists

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


def _load_dashboard():
    import importlib.util
    spec = importlib.util.spec_from_file_location("dash_posture_mod", NET / "report-dashboard.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dash_posture_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestDashboardMalformedPosture(unittest.TestCase):
    def test_malformed_posture_structures_do_not_crash(self):
        # R8: non-dict host/check/observer/domain records are discarded at the model
        # boundary; an unknown status becomes ERR (never PASS); valid siblings render.
        dash = _load_dashboard()
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan" / "win1"
            scan.mkdir(parents=True)
            (scan / "_meta.json").write_text(json.dumps({"host": "10.0.0.31", "port": 22, "status": "OK"}))
            (scan / "winenum.txt").write_text("POSTURE|WIN-SMB-SRVSIGN|FAIL|RequireSecuritySignature=0\n")
            real = dash.rpt.collect

            def bad_collect(*a, **kw):
                col = real(*a, **kw)
                hosts = {"10.0.0.31": {"os": "windows", "checks": {
                            "LIN-SYSCTL-ASLR": "bad", "WIN-CRED-WDIGEST": {"status": "BOGUS"},
                            "WIN-SMB-SRVSIGN": {"status": "FAIL", "detail": "RequireSecuritySignature=0"}},
                            "domain_observations": ["x"]},
                         "10.0.0.99": "not-a-dict"}
                domains = {"corp.local": {"checks": {
                               "AD-MAQ": {"status": "WARN", "detail": "q=10", "observed_from": ["x", 3,
                                          {"host": "10.0.0.31", "status": "WARN", "detail": "q=10"}]},
                               "AD-PWPOL-MINLEN": "bad"}},
                           "bad.example": [1, 2]}
                return col._replace(posture={"hosts": hosts, "domains": domains}, domains=domains)

            dash.rpt.collect = bad_collect
            try:
                model = dash.build_index(Path(tmp) / "scan", True, None)
                posture = dash.render_posture(model)
                ad = dash.render_ad(model)
                host = dash.render_host_detail(model, "10.0.0.31")
            finally:
                dash.rpt.collect = real
        self.assertEqual(set(model["posture"]), {"10.0.0.31"})
        self.assertEqual(model["posture"]["10.0.0.31"]["checks"]["WIN-CRED-WDIGEST"]["status"], "ERR")
        self.assertNotIn("LIN-SYSCTL-ASLR", model["posture"]["10.0.0.31"]["checks"])
        self.assertIn("RequireSecuritySignature=0", posture)          # valid sibling still rendered
        self.assertIn("WIN-SMB-SRVSIGN", host)
        maq = re.search(r"AD-MAQ</code></td>.*?</tr>", ad, re.S).group(0)
        self.assertIn("10.0.0.31", maq)                               # the one valid observer kept
        self.assertNotIn("AD-PWPOL-MINLEN", ad)
        self.assertNotIn("bad.example", ad)


class TestDashboardHostilePostureText(unittest.TestCase):
    """R10: posture-derived text (details, domain, observer details, quarantined
    lines) is escaped in content and in title attributes on every page."""
    SCRIPT = "<script>alert(1)</script>"
    ATTR = '"><img src=x onerror=alert(2)>'

    def test_hostile_strings_are_escaped_everywhere(self):
        win = "".join([
            f"POSTURE|WIN-SMB-SRVSIGN|FAIL|RequireSecuritySignature=0 {self.SCRIPT}\n",
            f"POSTURE|WIN-DOMAIN-JOINED|INFO|domain=corp.local role=member{self.SCRIPT}\n",
            f"POSTURE|AD-MAQ|WARN|domain=corp.local observer=win1 q=10 {self.ATTR}\n",
            f"POSTURE|AD-PWPOL-MINLEN|FAIL|domain=evil{self.SCRIPT.replace(' ', '')} observer=win1 x\n",
            f"POSTURE|WIN-BOGUS|FAIL|{self.SCRIPT} {self.ATTR}\n",
        ])
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "scan" / "win1"
            d.mkdir(parents=True)
            (d / "_meta.json").write_text(json.dumps({"host": "10.0.0.31", "port": 22, "status": "OK"}))
            (d / "winenum.txt").write_text(win)
            out = Path(tmp) / "dash"
            r = subprocess.run([PY, str(NET / "report-dashboard.py"), str(Path(tmp) / "scan"),
                                "--output", str(out)], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            pages = {p.name: p.read_text(encoding="utf-8") for p in out.glob("*.html")}
        raw = [n for n, t in pages.items() if "<script>alert(" in t or "<img src=x" in t]
        self.assertEqual(raw, [])
        # ...and the hostile text is present in escaped form (not silently dropped).
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", pages["posture.html"])
        self.assertIn("&quot;&gt;&lt;img src=x onerror=alert(2)&gt;", pages["ad.html"])   # observer title attr
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", pages["index.html"])       # quarantine in run health


if __name__ == "__main__":
    unittest.main()
