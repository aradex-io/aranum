"""Regression tests for the Phase-1 (TESTPLAN-001, 07JUN2026) hardening fixes.

Each test pins a bug found during the comprehensive functional test campaign so
it cannot silently regress. Tools are exercised as real subprocesses (the way an
operator runs them) and assert on exit code + output, not just "no crash".
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"
PY = sys.executable


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


class TestNmapParseHardening(unittest.TestCase):
    def _np(self, path, *extra):
        return run([PY, str(NET / "nmap-parse.py"), str(path), "--json", *extra])

    def test_binary_gnmap_fails_loud(self):
        # Was: vacuous rc0 + empty JSON identical to a clean scan.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.gnmap"
            p.write_bytes(os.urandom(256))
            r = self._np(p)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("unrecognized", r.stderr.lower())

    def test_empty_file_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e.gnmap"
            p.write_text("")
            self.assertEqual(self._np(p).returncode, 2)

    def test_all_hosts_down_is_legit_empty(self):
        # Genuinely empty (anchored) scan must STILL be rc0 — not over-flagged.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "down.gnmap"
            p.write_text("# Nmap 7.92 scan\nHost: 10.0.0.9 ()\tStatus: Down\n# Nmap done\n")
            self.assertEqual(self._np(p).returncode, 0)

    def test_portid_out_of_range_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "p.xml"
            p.write_text(
                '<nmaprun><host><status state="up"/>'
                '<address addr="10.0.0.1" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="65536"><state state="open"/></port>'
                '<port protocol="tcp" portid="80"><state state="open"/></port>'
                '</ports></host></nmaprun>')
            r = self._np(p)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("65536", r.stdout)
            self.assertIn("80", r.stdout)

    def test_real_fixtures_still_parse(self):
        for f in ("test.xml", "test.gnmap", "test.nmap"):
            r = self._np(NET / f)
            self.assertEqual(r.returncode, 0, f)


class TestReportHardening(unittest.TestCase):
    def _scan(self, d, line, host="10.0.0.1"):
        hd = Path(d) / "scan" / "http" / host
        hd.mkdir(parents=True)
        (hd / "h.txt").write_text(line + "\n")
        return Path(d) / "scan"

    def _report(self, scan, *extra):
        return run([PY, str(NET / "report.py"), str(scan), "--findings-only", *extra])

    def test_symlink_outside_tree_not_leaked(self):
        with tempfile.TemporaryDirectory() as d:
            scan = self._scan(d, "[+] EXPOSED /.git on host")
            outside = Path(d) / "secret.txt"
            outside.write_text("SENTINEL-LEAK-7f3a\n")
            os.symlink(outside, scan / "http" / "10.0.0.1" / "leak_link")
            self.assertEqual(self._report(scan).returncode, 0)
            blob = (scan / "findings.json").read_text()
            self.assertNotIn("SENTINEL-LEAK-7f3a", blob)

    def test_invalid_severity_rule_rc2(self):
        with tempfile.TemporaryDirectory() as d:
            scan = self._scan(d, "[+] EXPOSED /.git")
            rule = Path(d) / "r.txt"
            rule.write_text('{"pattern":"x","severity":"banana"}\n')
            r = self._report(scan, "--severity-rules", str(rule))
            self.assertEqual(r.returncode, 2)
            self.assertIn("invalid severity rule", r.stderr)

    def test_redos_rule_does_not_hang(self):
        with tempfile.TemporaryDirectory() as d:
            scan = self._scan(d, "EXPOSED " + "a" * 5000 + "!")
            rule = Path(d) / "r.txt"
            rule.write_text('{"pattern":"(a+)+$","severity":"high"}\n')
            # 60s subprocess timeout — a hang raises TimeoutExpired and fails.
            r = self._report(scan, "--severity-rules", str(rule))
            self.assertIn(r.returncode, (0, 2))

    def test_redact_ipv6_and_known_hostname(self):
        with tempfile.TemporaryDirectory() as d:
            scan = self._scan(
                d,
                "[+] EXPOSED /.git host fe80::dead:beef and 2001:db8::1 and 10.0.0.7 mac de:ad:be:ef:00:11",
                host="dc01.corp.local")
            self.assertEqual(self._report(scan, "--redact").returncode, 0)
            blob = (scan / "findings.json").read_text()
            self.assertNotIn("fe80::dead:beef", blob)
            self.assertNotIn("2001:db8::1", blob)
            self.assertNotIn("10.0.0.7", blob)
            self.assertNotIn("dc01.corp.local", blob)
            self.assertIn("de:ad:be:ef:00:11", blob)  # MAC preserved, not over-redacted


class TestMergeHardening(unittest.TestCase):
    def _src(self, d, evidence_path):
        s = Path(d) / "a" / "b" / "c" / "src"
        s.mkdir(parents=True)
        (s / "findings.json").write_text(json.dumps({"findings": [
            {"host": "h", "port": "1", "service": "s", "severity": "high",
             "line": "L", "evidence_path": evidence_path}]}))
        return s

    def _merge(self, src, out):
        return run([PY, str(NET / "merge-results.py"), str(src), "-o", str(out)])

    def test_traversal_evidence_not_copied(self):
        with tempfile.TemporaryDirectory() as d:
            secret = Path(d) / "leak" / "secret.txt"
            secret.parent.mkdir(parents=True)
            secret.write_text("SENTINEL-MERGE-LEAK\n")
            src = self._src(d, "../../../../leak/secret.txt")
            out = Path(d) / "out"
            self.assertEqual(self._merge(src, out).returncode, 0)
            for f in out.rglob("*"):
                if f.is_file():
                    self.assertNotIn("SENTINEL-MERGE-LEAK", f.read_text(errors="replace"))

    def test_absolute_evidence_not_copied(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._src(d, "/etc/hostname")
            out = Path(d) / "out"
            self.assertEqual(self._merge(src, out).returncode, 0)
            self.assertFalse((out / "evidence").exists() and
                             any("hostname" in p.name for p in out.rglob("*")))

    def test_non_object_findings_rc2(self):
        with tempfile.TemporaryDirectory() as d:
            s = Path(d) / "src"
            s.mkdir()
            (s / "findings.json").write_text('["not","an","object"]')
            r = self._merge(s, Path(d) / "out")
            self.assertEqual(r.returncode, 2)
            self.assertIn("not a JSON object", r.stderr)


class TestPlanHardening(unittest.TestCase):
    def _plan(self, *extra):
        with tempfile.TemporaryDirectory() as d:
            return run([PY, str(NET / "plan.py"), str(NET / "test.gnmap"),
                        "-o", str(Path(d) / "o"), *extra])

    def test_out_of_range_phase_fails_loud(self):
        self.assertNotEqual(self._plan("--phase", "9").returncode, 0)

    def test_empty_phase_fails_loud(self):
        self.assertNotEqual(self._plan("--phase", "").returncode, 0)

    def test_valid_run_ok(self):
        self.assertEqual(self._plan().returncode, 0)


class TestLibArityGuard(unittest.TestCase):
    def test_targets_without_value_clean_error_no_hang(self):
        # Affects all 61 dispatchers via parse_common_args. Must not abort on
        # set -u unbound $2, nor infinite-loop on shift 2.
        r = run(["bash", str(NET / "enum-ftp.sh"), "--targets"])
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing value", (r.stdout + r.stderr))

    def test_output_without_value_clean_error(self):
        r = run(["bash", str(NET / "enum-ftp.sh"), "--targets", "/tmp/x", "--output"])
        self.assertNotEqual(r.returncode, 0)


class TestBulkEnumTraversal(unittest.TestCase):
    def test_linux_target_cannot_escape_outdir(self):
        with tempfile.TemporaryDirectory() as d:
            hosts = Path(d) / "h.txt"
            hosts.write_text(f"root@../../../../../..{d}/ESC:22\n")
            out = Path(d) / "out"
            out.mkdir()
            run(["bash", str(NET / "bulk-enum-linux.sh"), "-i", str(hosts),
                 "-o", str(out), "--dry-run"])
            escaped = [p for p in Path(d).rglob("ESC") if p.is_dir()
                       and out.resolve() not in p.resolve().parents]
            self.assertEqual(escaped, [])

    def test_windows_target_cannot_escape_outdir(self):
        with tempfile.TemporaryDirectory() as d:
            hosts = Path(d) / "h.txt"
            hosts.write_text(f"../../../../../..{d}/ESCWIN\n")
            out = Path(d) / "wout"
            run([PY, str(NET / "bulk-enum-windows.py"), "-i", str(hosts),
                 "-o", str(out), "--dry-run"])
            escaped = [p for p in Path(d).rglob("ESCWIN") if p.is_dir()
                       and out.resolve() not in p.resolve().parents]
            self.assertEqual(escaped, [])


class TestEnumHttpAliveDetection(unittest.TestCase):
    """enum-http must not treat a connectable non-HTTP port as a live web
    endpoint (it previously queued such URLs for a 600s nuclei run)."""

    def _serve_non_http(self):
        # Tiny TCP server that accepts and sends a non-HTTP (ssh-like) banner.
        import socket
        import threading
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def loop():
            srv.settimeout(0.5)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except OSError:
                    continue
                try:
                    c.sendall(b"SSH-2.0-OpenSSH_lab\r\n")
                except OSError:
                    pass
                finally:
                    c.close()
            srv.close()

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return port, stop

    def test_non_http_port_skips_nuclei_and_alive_list(self):
        port, stop = self._serve_non_http()
        try:
            with tempfile.TemporaryDirectory() as d:
                tgt = Path(d) / "t.txt"
                tgt.write_text(f"127.0.0.1:{port}\n")
                out = Path(d) / "o"
                r = run(["bash", str(NET / "enum-http.sh"),
                         "--targets", str(tgt), "--output", str(out)], timeout=90)
                self.assertEqual(r.returncode, 0)
                alive = out / "_alive_urls.txt"
                # No real HTTP response -> alive list empty (or absent).
                if alive.exists():
                    self.assertEqual(alive.read_text().strip(), "")
        finally:
            stop.set()


if __name__ == "__main__":
    unittest.main()
