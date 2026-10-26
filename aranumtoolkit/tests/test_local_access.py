#!/usr/bin/env python3
"""test_local_access.py — S4 unit tests for the `--local` access layer
(network/local-enum.py) and the `aranum run --local` / `aranum local` wiring.

Per ADR-007 'What this does not validate': there is no Windows host and no live
exec target in CI. These tests are hermetic and fast — target parsing, OS
inference, credential resolution, the dry-run PLAN contract, the compact-probe
builder (including the exec-ceiling gate and refusal), the exec argv/stdin
contract, output classification, dependency-absent degradation, argv
partitioning, and the mixed-tree collector. The real self-scan and the measured
pathway counts live in the M8 harness (docs/test-strategy/harness/m8_pathways.py),
not here.

Run with: python3 -m unittest tests.test_local_access
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
LE = REPO / "aranumtoolkit" / "network" / "local-enum.py"
REPORT = REPO / "aranumtoolkit" / "network" / "report.py"
ARANUM = REPO / "aranum.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # @dataclass introspection resolves the decorated class via sys.modules, so
    # the module must be registered before its class bodies execute.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


le = _load("le_mod", LE)
report = _load("report_mod_la", REPORT)
aranum = _load("aranum_mod_la", ARANUM)


# --------------------------------------------------------------------- targets
class TestTargetParsing(unittest.TestCase):
    def test_host_only(self):
        s = le.parse_targets_line("192.0.2.11", 1)
        self.assertEqual(s.host, "192.0.2.11")
        self.assertIsNone(s.port)
        self.assertEqual(s.os, "unknown")
        self.assertIsNone(s.via)

    def test_os_via_user_and_port(self):
        s = le.parse_targets_line("admin@192.0.2.21:5986 os=windows via=winrm,ssh user=svc", 2)
        self.assertEqual(s.host, "192.0.2.21")
        self.assertEqual(s.port, 5986)
        self.assertEqual(s.os, "windows")
        self.assertEqual(s.via, {"winrm", "ssh"})
        # explicit user= wins over the user@ prefix (last assignment)
        self.assertEqual(s.user, "svc")

    def test_comment_and_blank_are_skipped(self):
        self.assertIsNone(le.parse_targets_line("   # just a comment", 3))
        self.assertIsNone(le.parse_targets_line("", 4))

    def test_trailing_comment_still_parses_host(self):
        self.assertEqual(le.parse_targets_line("192.0.2.1  # trailing", 5).host, "192.0.2.1")

    def test_bad_os_rejected(self):
        with self.assertRaises(le.UsageError):
            le.parse_targets_line("192.0.2.1 os=solaris", 6)

    def test_unknown_pathway_rejected(self):
        with self.assertRaises(le.UsageError):
            le.parse_targets_line("192.0.2.1 via=telnet", 7)

    def test_unknown_key_rejected(self):
        with self.assertRaises(le.UsageError):
            le.parse_targets_line("192.0.2.1 role=dc", 8)

    def test_port_out_of_range_rejected(self):
        with self.assertRaises(le.UsageError):
            le.parse_targets_line("192.0.2.1:99999", 9)

    def test_load_targets_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.txt"
            p.write_text("# header\n192.0.2.11 os=linux\n\nadmin@192.0.2.21 os=windows\n")
            rows = le.load_targets(p)
            self.assertEqual([r.host for r in rows], ["192.0.2.11", "192.0.2.21"])
            self.assertEqual([r.os for r in rows], ["linux", "windows"])


# ----------------------------------------------------------------- OS inference
class TestInferOS(unittest.TestCase):
    def test_product_first_windows(self):
        self.assertEqual(le.infer_os({22}, ["Microsoft Windows RPC"]), "windows")

    def test_ssh_implies_linux(self):
        self.assertEqual(le.infer_os({22}, ["OpenSSH 8.9"]), "linux")

    def test_winrm_port_implies_windows(self):
        self.assertEqual(le.infer_os({5985}, []), "windows")

    def test_samba_on_445_is_not_windows(self):
        # 445 is a Windows signal port, but a Samba product overrides it.
        self.assertEqual(le.infer_os({445}, ["Samba smbd 4.15"]), "unknown")

    def test_unknown_when_no_signal(self):
        self.assertEqual(le.infer_os({8080}, ["nginx"]), "unknown")


# --------------------------------------------------------------- credentials
class TestCredentials(unittest.TestCase):
    def test_password_hash_and_key(self):
        with tempfile.TemporaryDirectory() as d:
            keyf = Path(d) / "id_rsa"
            keyf.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            os.chmod(keyf, 0o600)
            credf = Path(d) / "creds.txt"
            # `<host|*> <user> <secret>`
            credf.write_text(
                f"* alice {keyf}\n"                                   # existing file -> key
                "* bob nt:aad3b435b51404eeaad3b435b51404ee\n"         # nt: -> hash
                "* carol sEcret123\n"                                 # otherwise -> password
            )
            os.chmod(credf, 0o600)
            rows = le.load_creds(credf)
            by = {c.user: c for _sel, c in rows}
            self.assertEqual(by["alice"].key, str(keyf))
            self.assertIsNone(by["alice"].password)
            self.assertEqual(by["bob"].nthash, "aad3b435b51404eeaad3b435b51404ee")
            self.assertEqual(by["carol"].password, "sEcret123")

    def test_resolve_cred_prefers_host_match_over_default(self):
        default = le.Cred(user="def", password="dpw")
        rows = [("192.0.2.11", le.Cred(user="root", password="rpw"))]
        spec = le.HostSpec(host="192.0.2.11", user="root")
        c = le.resolve_cred(spec, rows, default)
        self.assertEqual(c.user, "root")
        self.assertEqual(c.password, "rpw")


# --------------------------------------------------------------- compact probe
class TestCompactProbe(unittest.TestCase):
    def test_wmiexec_carries_checks_within_ceiling(self):
        p = le.build_probe("wmiexec")
        self.assertGreaterEqual(len(p.checks), 1)
        self.assertLessEqual(p.chars, le.EXEC_CEILING["wmiexec"])
        self.assertTrue(p.command.startswith("powershell.exe -NoProfile -NonInteractive -EncodedCommand "))

    def test_smbexec_carries_at_least_the_core(self):
        p = le.build_probe("smbexec")
        self.assertGreaterEqual(len(p.checks), 1)
        self.assertLessEqual(p.chars, le.EXEC_CEILING["smbexec"])

    def test_psexec_refuses_core_over_ceiling(self):
        # Measured reality (ADR-007 erratum 26OCT2026): the core is ~7146 chars,
        # well over the 4000 psexec ceiling, so psexec carries no posture.
        with self.assertRaises(le.ProbeTooLarge):
            le.build_probe("psexec")

    def test_unknown_method_is_valueerror_not_probetoolarge(self):
        with self.assertRaises(ValueError):
            le.build_probe("bogusexec")

    def test_eligible_blocks_exclude_context_users(self):
        src = le.WIN_POSTURE.read_text(encoding="utf-8")
        blocks = le.eligible_blocks(src)
        for cid, block in blocks.items():
            refs, _ = le.block_variables(block)
            self.assertNotIn("context", refs, f"{cid} leaks $Context into the probe")

    def test_probe_checks_are_verbatim_subset_of_collector(self):
        # The probe can never drift from the collector: every carried block is
        # the collector's own minified block, and checks+omitted partition the
        # full host-check id list (nothing invented, nothing silently lost).
        src = le.WIN_POSTURE.read_text(encoding="utf-8")
        blocks = le.eligible_blocks(src)
        p = le.build_probe("wmiexec")
        for cid in p.checks:
            self.assertIn(blocks[cid], p.script, f"{cid} not embedded verbatim")
        all_ids = set(le.all_host_check_ids(src))
        self.assertTrue(set(p.checks).issubset(all_ids))
        self.assertEqual(set(p.checks) | set(p.omitted), all_ids)

    def test_annotate_omitted_emits_na_lines(self):
        text = le.annotate_omitted("", "smbexec", ["UAC-01", "LSA-02"])
        self.assertIn("POSTURE|UAC-01|NA|", text)
        self.assertIn("POSTURE|LSA-02|NA|", text)
        self.assertIn("smbexec compact probe", text)


# -------------------------------------------- exec-ceiling gate (Phase 7c RED)
class TestExecCeilingGate(unittest.TestCase):
    """The exec-ceiling refusal is a new acceptance gate. Prove it goes RED by
    mutating the ceiling, and prove the refusal is not vacuous by lifting it."""

    def test_tiny_ceiling_forces_refusal(self):
        # RED: a ceiling below the core makes a normally-fitting method refuse.
        with self.assertRaises(le.ProbeTooLarge):
            le.build_probe("wmiexec", ceiling=100)

    def test_huge_ceiling_carries_all_eligible_checks_no_refusal(self):
        # GREEN (non-vacuous): lift the ceiling and the SAME method carries every
        # eligible check with no refusal — so the RED above is ceiling-driven,
        # not a builder that always refuses.
        src = le.WIN_POSTURE.read_text(encoding="utf-8")
        eligible = set(le.eligible_blocks(src))
        p = le.build_probe("wmiexec", ceiling=10_000_000)
        self.assertEqual(set(p.checks), eligible)
        self.assertGreater(len(p.checks), len(le.build_probe("wmiexec").checks))


# ----------------------------------------------------------------- plan_host
def _probe_or_refuse(method):
    try:
        return le.build_probe(method), ""
    except le.ProbeTooLarge as e:
        return None, str(e)


class TestPlanHost(unittest.TestCase):
    def test_linux_ssh_full_row(self):
        spec = le.HostSpec(host="192.0.2.11", os="linux")
        cred = le.Cred(user="root", password="pw")
        hp = le.plan_host(spec, cred, {"ssh"}, None, None)
        rows = [r.line() for r in hp.rows]
        self.assertTrue(any(r.startswith("PLAN|192.0.2.11|linux|ssh|full|bulk-enum-linux.sh|") for r in rows))

    def test_windows_winrm_full_row(self):
        spec = le.HostSpec(host="192.0.2.21", os="windows")
        cred = le.Cred(user="admin", password="pw")
        hp = le.plan_host(spec, cred, {"winrm"}, None, None)
        rows = [r.line() for r in hp.rows]
        self.assertTrue(any(r.startswith("PLAN|192.0.2.21|windows|winrm|full|bulk-enum-windows.py|") for r in rows))

    def test_exec_wmiexec_fits_row(self):
        spec = le.HostSpec(host="192.0.2.21", os="windows")
        cred = le.Cred(user="admin", password="pw")
        probe, _ = _probe_or_refuse("wmiexec")
        hp = le.plan_host(spec, cred, {"exec"}, "wmiexec", probe)
        row = next(r.line() for r in hp.rows if "|wmiexec|compact|" in r.line())
        self.assertIn("fits=yes", row)

    def test_exec_psexec_refuse_and_skip_rows(self):
        spec = le.HostSpec(host="192.0.2.21", os="windows")
        cred = le.Cred(user="admin", password="pw")
        probe, err = _probe_or_refuse("psexec")
        self.assertIsNone(probe)
        hp = le.plan_host(spec, cred, {"exec"}, "psexec", probe, probe_error=err)
        rows = [r.line() for r in hp.rows]
        self.assertTrue(any("|psexec|compact|compact-probe|fits=no refuse" in r for r in rows))
        self.assertTrue(any("psexec:probe-too-large" in r for r in rows))
        self.assertEqual(hp.pathways, [])

    def test_no_user_skips_with_no_credentials(self):
        spec = le.HostSpec(host="192.0.2.11", os="linux")
        hp = le.plan_host(spec, le.Cred(), {"ssh"}, None, None)
        self.assertEqual(hp.skip, "no-credentials")


# --------------------------------------------------------------- resolve_allowed
class TestResolveAllowed(unittest.TestCase):
    def test_auto_is_ssh_and_winrm(self):
        self.assertEqual(
            le.resolve_allowed("auto", self_scan=False, win_exec=None,
                               use_smb_admin=False, desktop_ok=False),
            {"ssh", "winrm"})

    def test_auto_adds_local_on_self_and_exec_on_consent(self):
        a = le.resolve_allowed("auto", self_scan=True, win_exec="wmiexec",
                               use_smb_admin=True, desktop_ok=False)
        self.assertIn("local", a)
        self.assertIn("exec", a)

    def test_exec_requires_win_exec(self):
        with self.assertRaises(le.UsageError):
            le.resolve_allowed("exec", self_scan=False, win_exec=None,
                               use_smb_admin=True, desktop_ok=False)

    def test_exec_requires_use_smb_admin(self):
        with self.assertRaises(le.UsageError):
            le.resolve_allowed("exec", self_scan=False, win_exec="wmiexec",
                               use_smb_admin=False, desktop_ok=False)

    def test_desktop_transport_refused_until_s5(self):
        with self.assertRaises(le.UsageError):
            le.resolve_allowed("rdp", self_scan=False, win_exec=None,
                               use_smb_admin=False, desktop_ok=False)

    def test_desktop_ok_flag_refused_until_s5(self):
        with self.assertRaises(le.UsageError):
            le.resolve_allowed("auto", self_scan=False, win_exec=None,
                               use_smb_admin=False, desktop_ok=True)


# ------------------------------------------------------------- exec transport
class TestExecTransport(unittest.TestCase):
    def test_smbexec_uses_stdin_not_positional(self):
        cred = le.Cred(user="admin", password="pw")
        argv, stdin = le.exec_argv("impacket-smbexec", "smbexec", "192.0.2.21", cred, "whoami")
        self.assertIsNotNone(stdin)
        self.assertIn("whoami", stdin)
        self.assertTrue(stdin.strip().endswith("exit"))
        self.assertNotIn("whoami", argv)  # command is NOT a positional for smbexec

    def test_wmiexec_passes_command_as_positional(self):
        cred = le.Cred(user="admin", password="pw")
        argv, stdin = le.exec_argv("impacket-wmiexec", "wmiexec", "192.0.2.21", cred, "whoami")
        self.assertIsNone(stdin)
        self.assertIn("whoami", argv)

    def test_nthash_goes_on_argv(self):
        cred = le.Cred(user="admin", nthash="aad3b435b51404eeaad3b435b51404ee")
        argv, _ = le.exec_argv("impacket-wmiexec", "wmiexec", "192.0.2.21", cred, "whoami")
        self.assertIn("-hashes", argv)

    def test_classify_markers_ok(self):
        out = f"{le.PROBE_HEADER}\nPOSTURE|X|PASS|y\n{le.PROBE_END}\n"
        self.assertEqual(le.classify_exec(out, "", False)[0], "OK")

    def test_classify_auth_fail(self):
        self.assertEqual(le.classify_exec("", "STATUS_LOGON_FAILURE", False)[0], "AUTH_FAIL")

    def test_classify_timeout(self):
        self.assertEqual(le.classify_exec("", "", True)[0], "HOST_TIMEOUT")

    def test_find_exec_tool_absent_returns_none(self):
        with mock.patch.object(le.shutil, "which", return_value=None):
            self.assertIsNone(le.find_exec_tool("wmiexec"))


# --------------------------------------------------------------- --ad threading
class TestADThreading(unittest.TestCase):
    def _fake_args(self, ad):
        ns = mock.Mock()
        ns.ad = ad
        ns.parallel = 4
        ns.connect_timeout = 5
        return ns

    def _capture_engine_argv(self, ad):
        captured = {}

        def fake_run_bounded(argv, **kw):
            captured["argv"] = argv
            return (0, "", "", False)

        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(le, "run_bounded", side_effect=fake_run_bounded), \
                mock.patch.object(le, "_collect_engine_dirs", return_value={}):
            spec = le.HostSpec(host="192.0.2.21", os="windows")
            hp = le.HostPlan(spec, le.Cred(user="admin", password="pw"))
            le.run_windows_engine([hp], le.Cred(user="admin", password="pw"),
                                  ["winrm"], False, Path(d), 0, self._fake_args(ad))
        return captured["argv"]

    def test_ad_flag_forwarded_when_set(self):
        self.assertIn("--ad", self._capture_engine_argv(True))

    def test_ad_flag_absent_when_unset(self):
        self.assertNotIn("--ad", self._capture_engine_argv(False))


# ----------------------------------------------------------- argv partitioning
class TestPartitionLocal(unittest.TestCase):
    def test_shared_creds_go_to_both_local_only_stays_local(self):
        auto, local = aranum._partition_local(
            ["scan.gnmap", "--only", "ssh", "--local", "--self",
             "--transport", "ssh", "-u", "jay", "-p", "pw", "--dry-run"])
        self.assertNotIn("--local", auto)
        self.assertNotIn("--local", local)
        # local-only
        self.assertIn("--self", local)
        self.assertNotIn("--self", auto)
        self.assertIn("--transport", local)
        self.assertNotIn("--transport", auto)
        # auto-only
        self.assertIn("--only", auto)
        self.assertNotIn("--only", local)
        # shared creds + dry-run reach both
        for a in ("-u", "jay", "-p", "pw", "--dry-run"):
            self.assertIn(a, auto)
            self.assertIn(a, local)


# ---------------------------------------------------------- mixed-tree collect
class TestMixedTreeCollect(unittest.TestCase):
    def test_bulk_root_plus_service_dir_is_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # a bulk root with one host
            linux = root / "linux"
            (linux / "localhost").mkdir(parents=True)
            (linux / le.BULK_ROOT_MARKER).write_text(json.dumps({"writer": "self", "os": "linux"}))
            (linux / "localhost" / "_meta.json").write_text(json.dumps({"status": "OK", "host": "localhost"}))
            (linux / "localhost" / "linenum.txt").write_text("POSTURE|KRN-01|PASS|ok\n")
            # a service dir (auto-enum layout: <service>/<ip>/<file>)
            svc = root / "ssh" / "192.0.2.50"
            svc.mkdir(parents=True)
            (svc / "banner.txt").write_text("SSH-2.0-OpenSSH_7.4\n")
            col = report.collect(root, report._load_rules(None))
            self.assertEqual(col.mode, "mixed")


if __name__ == "__main__":
    unittest.main()
