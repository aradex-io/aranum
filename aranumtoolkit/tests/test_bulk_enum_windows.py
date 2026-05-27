#!/usr/bin/env python3
"""test_bulk_enum_windows.py — K.3 unit tests for bulk-enum-windows.py.

Per ADR-003 'WHAT THIS ADR DOES NOT VALIDATE': this codebase ships with no
real Windows host for CI. These tests therefore mock pywinrm at the
`Session.run_ps` boundary and validate everything the orchestrator does
*outside* the WinRM transport (target parsing, IPv6 bracketing, output
layout, dry-run, --throttle precedence, arg-validation refusals, per-host
file writes).

Run with: python3 -m unittest tests.test_bulk_enum_windows
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "aranumtoolkit" / "network" / "bulk-enum-windows.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("bew_mod", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # @dataclass introspection looks up its decorated class via sys.modules;
    # importlib's spec_from_file_location doesn't auto-register, so we do it
    # here before exec_module runs the class body.
    sys.modules["bew_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


W = _load_module()


# --------------------------------------------------------------------- parse_spec
class TestParseSpec(unittest.TestCase):
    def test_bare_hostname_uses_default_user(self):
        t = W.parse_spec("host.example", "alice", 5985)
        self.assertEqual((t.user, t.host, t.port), ("alice", "host.example", 5985))

    def test_user_at_host(self):
        t = W.parse_spec("bob@host.example", "alice", 5985)
        self.assertEqual((t.user, t.host, t.port), ("bob", "host.example", 5985))

    def test_user_at_host_port(self):
        t = W.parse_spec("svc@srv1:5986", "alice", 5985)
        self.assertEqual((t.user, t.host, t.port), ("svc", "srv1", 5986))

    def test_ipv6_bracketed_no_port(self):
        t = W.parse_spec("[2001:db8::1]", "alice", 5985)
        self.assertEqual((t.user, t.host, t.port), ("alice", "2001:db8::1", 5985))

    def test_ipv6_bracketed_with_port(self):
        t = W.parse_spec("bob@[2001:db8::1]:5986", "alice", 5985)
        self.assertEqual((t.user, t.host, t.port), ("bob", "2001:db8::1", 5986))

    def test_comment_returns_none(self):
        self.assertIsNone(W.parse_spec("# this is a comment", "alice", 5985))

    def test_blank_returns_none(self):
        self.assertIsNone(W.parse_spec("   ", "alice", 5985))

    def test_trailing_comment_stripped(self):
        t = W.parse_spec("host.example  # production DC", "alice", 5985)
        self.assertEqual(t.host, "host.example")


# --------------------------------------------------------------------- WinRM endpoint URL
class TestWinRMEndpoint(unittest.TestCase):
    """The endpoint URL must bracket IPv6 hosts — urllib's parser otherwise
    treats the trailing :N of the address as a port number."""

    def _capture_endpoint(self, target: W.Target, *, tls: bool):
        """Patch winrm.Session at the module level and inspect the endpoint
        the orchestrator constructs."""
        captured = {}
        class FakeSession:
            def __init__(self, endpoint, **kwargs):
                captured["endpoint"] = endpoint
                captured["kwargs"] = kwargs
            def run_ps(self, script):
                r = mock.Mock(); r.status_code = 0
                r.std_out = b"PROBE_OK"; r.std_err = b""
                return r
        with mock.patch.object(W, "HAS_PYWINRM", True), \
             mock.patch("winrm.Session", FakeSession):
            W._winrm_run(target, "probe", password="pw", auth="ntlm",
                         tls=tls, timeout=10)
        return captured["endpoint"]

    def test_ipv4_endpoint(self):
        t = W.Target("u", "10.0.0.5", 5985, "u@10.0.0.5")
        self.assertEqual(self._capture_endpoint(t, tls=False),
                         "http://10.0.0.5:5985/wsman")

    def test_ipv6_endpoint_bracketed(self):
        t = W.Target("u", "2001:db8::5", 5985, "u@[2001:db8::5]")
        self.assertEqual(self._capture_endpoint(t, tls=False),
                         "http://[2001:db8::5]:5985/wsman")

    def test_tls_endpoint(self):
        t = W.Target("u", "win1.corp", 5986, "u@win1.corp:5986")
        self.assertEqual(self._capture_endpoint(t, tls=True),
                         "https://win1.corp:5986/wsman")


# --------------------------------------------------------------------- end-to-end via mocked pywinrm
class TestEndToEndMocked(unittest.TestCase):
    """Drive the script via subprocess but patch pywinrm's Session
    upstream via a sitecustomize-equivalent monkeypatch isn't easy
    across subprocess boundaries. Instead we drive the in-process
    main() with sys.argv munging and a mock.patch on winrm.Session."""

    def test_dry_run_produces_per_host_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "targets.txt"
            tgts.write_text("host-1.example\nbob@host-2.example:5986\n[2001:db8::1]\n")
            out  = Path(td) / "out"
            with mock.patch.object(sys, "argv",
                ["bulk-enum-windows.py", "--targets", str(tgts),
                 "-u", "alice", "-o", str(out), "--dry-run"]):
                rc = W.main()
            self.assertEqual(rc, 0)
            for host in ("host-1.example", "host-2.example", "2001:db8::1"):
                self.assertTrue((out / host).is_dir(), f"missing {host}")
            self.assertTrue((out / "run.log").is_file())
            self.assertTrue((out / "hosts.txt").is_file())

    def test_throttle_default_parallel_1(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"
            tgts.write_text("a.example\nb.example\n")
            out  = Path(td) / "out"
            with mock.patch.object(sys, "argv",
                ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "x",
                 "-o", str(out), "--dry-run", "--throttle"]):
                rc = W.main()
            self.assertEqual(rc, 0)

    def test_basic_over_http_refused(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("a.example\n")
            out  = Path(td) / "out"
            with mock.patch.object(sys, "argv",
                ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "x",
                 "--auth", "basic", "-o", str(out), "--dry-run"]):
                rc = W.main()
            self.assertEqual(rc, 2, "basic over HTTP must be refused")

    def test_use_smb_admin_without_pass_refused(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("a.example\n")
            out  = Path(td) / "out"
            with mock.patch.object(sys, "argv",
                ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "x",
                 "--use-smb-admin", "-o", str(out), "--dry-run"]):
                rc = W.main()
            self.assertEqual(rc, 2)

    def test_parallel_cap_refused(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("a.example\n")
            out  = Path(td) / "out"
            with mock.patch.object(sys, "argv",
                ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "x",
                 "-P", "32", "-o", str(out), "--dry-run"]):
                rc = W.main()
            self.assertEqual(rc, 2)

    def test_mocked_winrm_writes_per_host_output(self):
        """Patch winrm.Session to return canned stdout per host, drive
        the orchestrator non-dry-run, and verify winenum.txt + _meta.json
        get the expected contents."""
        canned_stdout = "FAKE_INVOKE_PRIVESC_OUTPUT\n[+] AlwaysInstallElevated ENABLED\n"
        class FakeSession:
            def __init__(self, endpoint, **kwargs): pass
            def run_ps(self, script):
                r = mock.Mock(); r.status_code = 0
                r.std_out = canned_stdout.encode()
                r.std_err = b""
                return r
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"
            tgts.write_text("a.example\n")
            out  = Path(td) / "out"
            with mock.patch.object(W, "HAS_PYWINRM", True), \
                 mock.patch("winrm.Session", FakeSession), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts),
                     "-u", "alice", "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 0)
            self.assertEqual((out / "a.example" / "winenum.txt").read_text(), canned_stdout)
            meta = json.loads((out / "a.example" / "_meta.json").read_text())
            self.assertEqual(meta["rc"], 0)
            self.assertEqual(meta["transport"], "winrm")
            self.assertTrue((out / "a.example" / ".done").is_file())


if __name__ == "__main__":
    unittest.main()
