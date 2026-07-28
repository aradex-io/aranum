#!/usr/bin/env python3
"""test_bulk_enum_windows_transports.py — ADR-006 Workstream 1c unit tests
for bulk-enum-windows.py's multi-transport layer (winrm/ssh/smb).

Per ADR-003/ADR-006 "WHAT THIS DOES NOT VALIDATE": no live Windows host,
no live pywinrm, no live impacket, no live Windows OpenSSH server exists in
this codebase's CI. Every test here MOCKS the transport boundary (subprocess
calls, shutil.which, and — where pywinrm is actually installed — winrm.Session)
so nothing touches a real network. What IS verified for real: --transport
spec parsing/ordering, the auto fallthrough state machine, dependency-absent
degradation messaging, the ssh argv builder for all three auth modes
(including the BatchMode/sshpass regression check called out in ADR-006's
"Post-review revisions" SSH-option-spec table), base64/no-base64 payload
wrapping, and status classification.

Run with:
    cd /srv/share/dev/aranum && python3 -m pytest \
        aranumtoolkit/tests/test_bulk_enum_windows_transports.py -x -q
or:
    python3 -m unittest aranumtoolkit.tests.test_bulk_enum_windows_transports
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "aranumtoolkit" / "network" / "bulk-enum-windows.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("bew_transports_mod", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bew_transports_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


W = _load_module()


def _args(**overrides) -> argparse.Namespace:
    """Build a minimal argparse.Namespace with the fields transports read,
    defaulting to sane values; override per-test as needed."""
    base = dict(
        password=None, key=None, auth="ntlm", tls=False, connect_timeout=10,
        ssh_port=22, output="/tmp/does-not-matter", use_smb_admin=False,
        script=str(W.DEFAULT_SCRIPT),
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------- transport spec parsing / ordering
class TestTransportSpecParsing(unittest.TestCase):
    def test_default_is_auto(self):
        self.assertEqual(W._flatten_transport_spec(None), ["auto"])

    def test_comma_list(self):
        self.assertEqual(W._flatten_transport_spec(["winrm,ssh"]), ["winrm", "ssh"])

    def test_repeatable_flags(self):
        self.assertEqual(W._flatten_transport_spec(["winrm", "ssh"]), ["winrm", "ssh"])

    def test_mixed_repeatable_and_comma(self):
        self.assertEqual(W._flatten_transport_spec(["winrm,ssh", "smb"]),
                         ["winrm", "ssh", "smb"])

    def test_dedup_preserves_first_order(self):
        self.assertEqual(W._flatten_transport_spec(["ssh,winrm,ssh"]), ["ssh", "winrm"])

    def test_unknown_transport_raises(self):
        with self.assertRaises(ValueError) as ctx:
            W._flatten_transport_spec(["rdp"])
        self.assertIn("rdp", str(ctx.exception))

    def test_whitespace_and_case_normalized(self):
        self.assertEqual(W._flatten_transport_spec([" SSH , Winrm "]), ["ssh", "winrm"])


class TestResolveTransportOrder(unittest.TestCase):
    def test_auto_default_excludes_smb_without_consent(self):
        order = W.resolve_transport_order(None, use_smb_admin=False)
        self.assertEqual(order, ["winrm", "ssh"])

    def test_auto_includes_smb_only_with_consent(self):
        order = W.resolve_transport_order(None, use_smb_admin=True)
        self.assertEqual(order, ["winrm", "ssh", "smb"])

    def test_explicit_order_honored_verbatim(self):
        order = W.resolve_transport_order(["ssh,winrm"], use_smb_admin=False)
        self.assertEqual(order, ["ssh", "winrm"])

    def test_explicit_smb_without_consent_refused(self):
        with self.assertRaises(ValueError) as ctx:
            W.resolve_transport_order(["smb"], use_smb_admin=False)
        self.assertIn("use-smb-admin", str(ctx.exception))

    def test_explicit_smb_with_consent_allowed(self):
        order = W.resolve_transport_order(["ssh,smb"], use_smb_admin=True)
        self.assertEqual(order, ["ssh", "smb"])

    def test_single_explicit_transport(self):
        order = W.resolve_transport_order(["ssh"], use_smb_admin=False)
        self.assertEqual(order, ["ssh"])


# --------------------------------------------------------------------- dependency-absent degradation
class TestDependencyDegradation(unittest.TestCase):
    def test_winrm_unavailable_reason(self):
        with mock.patch.object(W, "HAS_PYWINRM", False):
            self.assertFalse(W.WinRMTransport.available())
        self.assertEqual(W.WinRMTransport.unavailable_reason(), "pywinrm not installed")

    def test_ssh_unavailable_when_binary_missing(self):
        with mock.patch.object(W.shutil, "which", return_value=None):
            self.assertFalse(W.SSHTransport.available())

    def test_ssh_available_when_binary_present(self):
        with mock.patch.object(W.shutil, "which", return_value="/usr/bin/ssh"):
            self.assertTrue(W.SSHTransport.available())

    def test_smb_unavailable_without_impacket_binaries(self):
        with mock.patch.object(W.shutil, "which", return_value=None):
            self.assertFalse(W.SMBTransport.available())
        self.assertEqual(W.SMBTransport.unavailable_reason(), "impacket not installed")

    def test_main_warns_and_skips_unavailable_transport_to_dry_run(self):
        # winrm unavailable (no pywinrm), ssh available -> auto should still
        # succeed via --dry-run (dry-run never hard-fails on availability).
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("a.example\n")
            out = Path(td) / "out"
            with mock.patch.object(W, "HAS_PYWINRM", False), \
                 mock.patch.object(W.shutil, "which", side_effect=lambda b: "/usr/bin/ssh" if b == "ssh" else None), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "x",
                     "-o", str(out), "--dry-run"]):
                stderr_capture = mock.patch("sys.stderr")
                rc = W.main()
            self.assertEqual(rc, 0)

    def test_main_hard_fails_when_all_transports_unavailable_and_not_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("a.example\n")
            out = Path(td) / "out"
            with mock.patch.object(W, "HAS_PYWINRM", False), \
                 mock.patch.object(W.shutil, "which", return_value=None), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "x",
                     "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 2)


# --------------------------------------------------------------------- ssh argv builder (BLOCKER 3)
class TestSSHArgvBuilder(unittest.TestCase):
    """These assertions are the T2 counterpart of the T1 argv-assertion
    requirement (ADR-006 'Post-review revisions', resolves BLOCKER 3):
    the password path must NEVER carry BatchMode=yes, and must carry
    NumberOfPasswordPrompts=1 — this is what makes the 1a bug structurally
    impossible to re-ship in this Python transport."""

    def _tgt(self):
        return W.Target(user="alice", host="10.0.0.5", port=5985, raw_spec="alice@10.0.0.5")

    def test_key_mode_sets_batchmode_yes_and_publickey(self):
        argv, mode = W.build_ssh_argv(self._tgt(), user="alice", key="/keys/id_ed25519",
                                      password=None, ssh_port=22, connect_timeout=10,
                                      known_hosts=Path("/tmp/kh"))
        self.assertEqual(mode, "KEY")
        self.assertIn("-o", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("PreferredAuthentications=publickey", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("-i", argv)
        self.assertIn("/keys/id_ed25519", argv)
        self.assertNotIn("PubkeyAuthentication=no", argv)

    def test_key_mode_agent_default_no_key_flag(self):
        argv, mode = W.build_ssh_argv(self._tgt(), user="alice", key=None, password=None,
                                      ssh_port=22, connect_timeout=10, known_hosts=Path("/tmp/kh"))
        self.assertEqual(mode, "KEY")
        self.assertNotIn("-i", argv)
        self.assertIn("BatchMode=yes", argv)

    def test_pass_mode_omits_batchmode_yes(self):
        argv, mode = W.build_ssh_argv(self._tgt(), user="alice", key=None, password="hunter2",
                                      ssh_port=22, connect_timeout=10, known_hosts=Path("/tmp/kh"))
        self.assertEqual(mode, "PASS")
        self.assertNotIn("BatchMode=yes", argv)
        self.assertIn("BatchMode=no", argv)
        self.assertIn("NumberOfPasswordPrompts=1", argv)
        self.assertIn("PubkeyAuthentication=no", argv)
        self.assertIn("PreferredAuthentications=keyboard-interactive,password", argv)
        self.assertNotIn("-i", argv)

    def test_key_then_pass_mode_keeps_pubkey_enabled(self):
        argv, mode = W.build_ssh_argv(self._tgt(), user="alice", key="/keys/id_rsa",
                                      password="hunter2", ssh_port=22, connect_timeout=10,
                                      known_hosts=Path("/tmp/kh"))
        self.assertEqual(mode, "KEY_THEN_PASS")
        self.assertNotIn("BatchMode=yes", argv)
        self.assertIn("BatchMode=no", argv)
        self.assertIn("NumberOfPasswordPrompts=1", argv)
        self.assertIn("-i", argv)
        self.assertIn("/keys/id_rsa", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("PreferredAuthentications=publickey,keyboard-interactive,password", argv)
        # The regression-critical negative assertion: KEY_THEN_PASS must NOT
        # disable pubkey, or the key half of the fallback is dead (D1a-4 bug).
        self.assertNotIn("PubkeyAuthentication=no", argv)

    def test_ssh_port_and_connect_timeout_and_known_hosts_applied(self):
        argv, _mode = W.build_ssh_argv(self._tgt(), user="alice", key=None, password=None,
                                       ssh_port=2222, connect_timeout=7,
                                       known_hosts=Path("/eng/known_hosts"))
        self.assertIn("2222", argv)
        self.assertIn("ConnectTimeout=7", argv)
        self.assertIn("UserKnownHostsFile=/eng/known_hosts", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)

    def test_powershell_stdin_command_present(self):
        argv, _mode = W.build_ssh_argv(self._tgt(), user="alice", key=None, password=None,
                                       ssh_port=22, connect_timeout=10, known_hosts=Path("/tmp/kh"))
        self.assertIn("powershell", argv)
        self.assertIn("-NoProfile", argv)
        self.assertIn("-NonInteractive", argv)
        # trailing "-Command -" means the script arrives over stdin, not as
        # an argv element — no on-disk artifact, no base64 wrapping needed.
        self.assertEqual(argv[-2:], ["-Command", "-"])


# --------------------------------------------------------------------- payload wrapping: ssh (raw stdin) vs smb (base64)
class TestPayloadWrapping(unittest.TestCase):
    def test_ssh_ships_raw_script_as_stdin_not_base64(self):
        """ADR-006 D1c-1: ssh mirrors the Linux stdin-pipe exactly — the
        script is piped to `powershell ... -Command -` as-is. Confirm no
        base64/EncodedCommand wrapping happens on this path (that's the smb
        transport's mechanism, not ssh's)."""
        tgt = W.Target(user="alice", host="10.0.0.9", port=5985, raw_spec="alice@10.0.0.9")
        script_text = "Get-Process | Select -First 1"
        args = _args(output=tempfile.mkdtemp())
        captured = {}

        def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["input"] = input
            return mock.Mock(returncode=0, stdout="ok", stderr="")

        with mock.patch.object(W.shutil, "which", return_value=None), \
             mock.patch.object(W.subprocess, "run", side_effect=fake_run):
            result = W.SSHTransport().run(tgt, script_text, args)
        self.assertEqual(result.status, "OK")
        self.assertEqual(captured["input"], script_text)
        self.assertNotIn(base64.b64encode(script_text.encode()).decode(), captured["cmd"])
        joined = " ".join(captured["cmd"])
        self.assertNotIn("-EncodedCommand", joined)
        self.assertIn("-Command", captured["cmd"])

    def test_smb_wraps_script_as_base64_encoded_command(self):
        tgt = W.Target(user="CORP\\jay", host="1.2.3.4", port=5985, raw_spec="raw")
        script_text = "Write-Output hi"
        fake = mock.Mock(returncode=0, stdout="OK", stderr="")
        with mock.patch.object(W.shutil, "which", return_value="/usr/bin/impacket-wmiexec"), \
             mock.patch.object(W.subprocess, "run", return_value=fake) as run:
            rc, out, _err = W._smb_admin_run(tgt, script_text, password="pw", timeout=10)
        self.assertEqual(rc, 0)
        argv = run.call_args.args[0]
        self.assertIn("-EncodedCommand", argv[2])
        enc = base64.b64encode(script_text.encode("utf-16-le")).decode("ascii")
        self.assertIn(enc, argv[2])

    def test_ssh_password_path_uses_sshpass_wrapper(self):
        tgt = W.Target(user="alice", host="10.0.0.9", port=22, raw_spec="alice@10.0.0.9")
        args = _args(password="hunter2", output=tempfile.mkdtemp())
        captured = {}

        def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return mock.Mock(returncode=0, stdout="ok", stderr="")

        with mock.patch.object(W.shutil, "which", return_value="/usr/bin/sshpass"), \
             mock.patch.object(W.subprocess, "run", side_effect=fake_run):
            result = W.SSHTransport().run(tgt, "Write-Output hi", args)
        self.assertEqual(result.status, "OK")
        self.assertEqual(captured["cmd"][0], "sshpass")
        self.assertEqual(captured["cmd"][1], "-e")
        self.assertEqual(captured["env"]["SSHPASS"], "hunter2")

    def test_ssh_password_path_degrades_cleanly_without_sshpass(self):
        tgt = W.Target(user="alice", host="10.0.0.9", port=22, raw_spec="alice@10.0.0.9")
        args = _args(password="hunter2", output=tempfile.mkdtemp())
        with mock.patch.object(W.shutil, "which", return_value=None):
            result = W.SSHTransport().run(tgt, "Write-Output hi", args)
        self.assertEqual(result.status, "AUTH_FAIL")
        self.assertIn("sshpass", result.stderr.lower())


# --------------------------------------------------------------------- status classification
class TestStatusClassification(unittest.TestCase):
    def test_ssh_ok(self):
        self.assertEqual(W._classify_ssh_result(0, "", password_used=False), ("OK", ""))

    def test_ssh_permission_denied_is_auth_fail(self):
        status, reason = W._classify_ssh_result(
            255, "Permission denied (publickey,password).", password_used=True)
        self.assertEqual(status, "AUTH_FAIL")

    def test_ssh_connection_refused_is_unreachable(self):
        status, _reason = W._classify_ssh_result(255, "ssh: connect to host x port 22: Connection refused",
                                                  password_used=False)
        self.assertEqual(status, "UNREACHABLE")

    def test_ssh_timeout_is_unreachable(self):
        status, _reason = W._classify_ssh_result(255, "ssh: connect to host x port 22: Operation timed out",
                                                  password_used=False)
        self.assertEqual(status, "UNREACHABLE")

    def test_ssh_sshpass_incorrect_password_rc5(self):
        status, reason = W._classify_ssh_result(5, "", password_used=True)
        self.assertEqual(status, "AUTH_FAIL")
        self.assertIn("sshpass", reason)

    def test_ssh_nonzero_non255_is_remote_err(self):
        status, reason = W._classify_ssh_result(1, "some script error", password_used=False)
        self.assertEqual(status, "REMOTE_ERR")
        self.assertIn("rc=1", reason)

    def test_winrm_ok(self):
        self.assertEqual(W._classify_winrm(0, ""), ("OK", ""))

    def test_winrm_invalid_credentials_is_auth_fail(self):
        status, _reason = W._classify_winrm(255, "InvalidCredentialsError: the specified credentials "
                                                   "were rejected by the server")
        self.assertEqual(status, "AUTH_FAIL")

    def test_winrm_connection_error_is_unreachable(self):
        status, _reason = W._classify_winrm(255, "ConnectionError: Connection refused")
        self.assertEqual(status, "UNREACHABLE")

    def test_winrm_other_exception_is_remote_err(self):
        status, _reason = W._classify_winrm(1, "")
        self.assertEqual(status, "REMOTE_ERR")

    def test_smb_ok(self):
        self.assertEqual(W._classify_smb(0, ""), ("OK", ""))

    def test_smb_oversized_script_is_remote_err(self):
        status, _reason = W._classify_smb(126, "too large")
        self.assertEqual(status, "REMOTE_ERR")

    def test_smb_missing_binary_is_unreachable(self):
        status, _reason = W._classify_smb(127, "impacket-wmiexec not on PATH")
        self.assertEqual(status, "UNREACHABLE")

    def test_smb_logon_failure_is_auth_fail(self):
        status, _reason = W._classify_smb(1, "STATUS_LOGON_FAILURE")
        self.assertEqual(status, "AUTH_FAIL")

    def test_smb_connection_error_is_unreachable(self):
        status, _reason = W._classify_smb(1, "connection error: timed out")
        self.assertEqual(status, "UNREACHABLE")

    def test_smb_other_nonzero_is_remote_err(self):
        status, _reason = W._classify_smb(1, "some other wmi fault")
        self.assertEqual(status, "REMOTE_ERR")


# --------------------------------------------------------------------- auto fallthrough (end to end, mocked transports)
class TestAutoFallthrough(unittest.TestCase):
    def test_auto_falls_through_winrm_auth_fail_to_ssh_success(self):
        """winrm auth-fails, ssh succeeds -> _meta.json records transport=ssh
        and status=OK; the fallthrough tried winrm first (order matters)."""
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("host1.example\n")
            out = Path(td) / "out"

            def fake_winrm_run(cls_self, target, script_text, args):
                return W.TransportResult(255, "", "InvalidCredentialsError: rejected", "AUTH_FAIL", "bad creds")

            def fake_ssh_run(cls_self, target, script_text, args):
                return W.TransportResult(0, "SSH_ENUM_OK", "", "OK", "")

            with mock.patch.object(W, "HAS_PYWINRM", True), \
                 mock.patch.object(W.WinRMTransport, "run", fake_winrm_run), \
                 mock.patch.object(W.SSHTransport, "available", staticmethod(lambda: True)), \
                 mock.patch.object(W.SSHTransport, "run", fake_ssh_run), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "alice",
                     "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 0)
            meta = json.loads((out / "host1.example" / "_meta.json").read_text())
            self.assertEqual(meta["transport"], "ssh")
            self.assertEqual(meta["status"], "OK")
            self.assertEqual(meta["transports_attempted"], ["winrm=AUTH_FAIL", "ssh=OK"])
            self.assertEqual((out / "host1.example" / "winenum.txt").read_text(), "SSH_ENUM_OK")
            self.assertTrue((out / "host1.example" / ".done").is_file())

    def test_auto_stops_at_first_success_never_tries_next(self):
        """winrm succeeds immediately -> ssh.run must never be called."""
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("host1.example\n")
            out = Path(td) / "out"

            def fake_winrm_run(cls_self, target, script_text, args):
                return W.TransportResult(0, "WINRM_OK", "", "OK", "")

            ssh_run_mock = mock.Mock()

            with mock.patch.object(W, "HAS_PYWINRM", True), \
                 mock.patch.object(W.WinRMTransport, "run", fake_winrm_run), \
                 mock.patch.object(W.SSHTransport, "available", staticmethod(lambda: True)), \
                 mock.patch.object(W.SSHTransport, "run", ssh_run_mock), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "alice",
                     "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 0)
            ssh_run_mock.assert_not_called()
            meta = json.loads((out / "host1.example" / "_meta.json").read_text())
            self.assertEqual(meta["transport"], "winrm")

    def test_remote_err_also_stops_fallthrough(self):
        """Auth succeeded but the remote script exited non-zero (REMOTE_ERR)
        -- this counts as the transport having "won" (authenticated); we do
        NOT fall through to the next transport just because the enum script
        itself returned non-zero."""
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("host1.example\n")
            out = Path(td) / "out"

            def fake_winrm_run(cls_self, target, script_text, args):
                return W.TransportResult(1, "partial output", "script hiccup", "REMOTE_ERR",
                                         "remote command exited rc=1")

            ssh_run_mock = mock.Mock()
            with mock.patch.object(W, "HAS_PYWINRM", True), \
                 mock.patch.object(W.WinRMTransport, "run", fake_winrm_run), \
                 mock.patch.object(W.SSHTransport, "available", staticmethod(lambda: True)), \
                 mock.patch.object(W.SSHTransport, "run", ssh_run_mock), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "alice",
                     "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 0)
            ssh_run_mock.assert_not_called()
            meta = json.loads((out / "host1.example" / "_meta.json").read_text())
            self.assertEqual(meta["transport"], "winrm")
            self.assertEqual(meta["status"], "REMOTE_ERR")
            self.assertFalse((out / "host1.example" / ".done").exists())

    def test_all_transports_fail_records_last_attempt_with_history(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("host1.example\n")
            out = Path(td) / "out"

            def fake_winrm_run(cls_self, target, script_text, args):
                return W.TransportResult(255, "", "InvalidCredentialsError: rejected", "AUTH_FAIL", "bad creds")

            def fake_ssh_run(cls_self, target, script_text, args):
                return W.TransportResult(255, "", "Connection refused", "UNREACHABLE", "host unreachable")

            with mock.patch.object(W, "HAS_PYWINRM", True), \
                 mock.patch.object(W.WinRMTransport, "run", fake_winrm_run), \
                 mock.patch.object(W.SSHTransport, "available", staticmethod(lambda: True)), \
                 mock.patch.object(W.SSHTransport, "run", fake_ssh_run), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "alice",
                     "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 0)  # orchestrator itself still exits 0; per-host FAIL is reported
            meta = json.loads((out / "host1.example" / "_meta.json").read_text())
            self.assertEqual(meta["status"], "UNREACHABLE")
            self.assertEqual(meta["transport"], "ssh")
            self.assertIn("attempted: winrm=AUTH_FAIL, ssh=UNREACHABLE", meta["fail_reason"])


# --------------------------------------------------------------------- _summary.tsv gains status column
class TestSummaryTsv(unittest.TestCase):
    def test_summary_has_status_and_fail_reason_columns(self):
        with tempfile.TemporaryDirectory() as td:
            tgts = Path(td) / "t.txt"; tgts.write_text("host1.example\n")
            out = Path(td) / "out"

            def fake_winrm_run(cls_self, target, script_text, args):
                return W.TransportResult(0, "OK_OUT", "", "OK", "")

            with mock.patch.object(W, "HAS_PYWINRM", True), \
                 mock.patch.object(W.WinRMTransport, "run", fake_winrm_run), \
                 mock.patch.object(sys, "argv",
                    ["bulk-enum-windows.py", "--targets", str(tgts), "-u", "alice",
                     "-p", "pw", "-o", str(out)]):
                rc = W.main()
            self.assertEqual(rc, 0)
            header = (out / "_summary.tsv").read_text().splitlines()[0]
            self.assertIn("status", header)
            self.assertIn("fail_reason", header)


if __name__ == "__main__":
    unittest.main()
