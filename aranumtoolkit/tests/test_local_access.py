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
dash = _load("dash_mod_la", REPORT.parent / "report-dashboard.py")


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
    def _fake_args(self, ad, host_timeout=0):
        ns = mock.Mock()
        ns.ad = ad
        ns.parallel = 4
        ns.connect_timeout = 5
        ns.host_timeout = host_timeout
        return ns

    def _capture_engine_argv(self, ad):
        captured = {}

        def fake_run_bounded(argv, **kw):
            captured["argv"] = argv
            captured["kw"] = kw
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


# ===================================================================
# REVIEW-011 (Phase-6 peer) fixes — new-behavior coverage (Phase 7b)
# ===================================================================

class TestCleanExecOutputProbeSpan(unittest.TestCase):
    """#1: the compact probe reports privilege evidence on `[+]`/`[-]` lines,
    which collide with impacket's banner prefixes. clean_exec_output must keep
    everything inside the PROBE_HEADER..PROBE_END span and strip impacket noise
    only outside it."""

    def test_privilege_lines_survive_inside_probe_span(self):
        raw = "\n".join([
            "Impacket v0.13.1 - Copyright Fortra",       # banner (noise, outside)
            "[*] Requesting shares",                      # impacket status (noise)
            le.PROBE_HEADER,
            "[+] SeImpersonatePrivilege (ENABLED)",       # OUR evidence — must stay
            "[-] SeDebugPrivilege (disabled - can still be enabled)",
            "POSTURE|KRN-01|PASS|ok",
            le.PROBE_END,
            "[-] trailing impacket chatter",              # outside span → noise
        ])
        body, noise = le.clean_exec_output(raw)
        self.assertIn("[+] SeImpersonatePrivilege (ENABLED)", body)
        self.assertIn("[-] SeDebugPrivilege", body)
        self.assertIn("POSTURE|KRN-01|PASS|ok", body)
        # impacket banner/status lines before the header are still removed
        self.assertNotIn("Impacket v0.13.1", body)
        self.assertNotIn("Requesting shares", body)
        self.assertIn("Impacket v0.13.1 - Copyright Fortra", noise)
        # the line after PROBE_END is outside the span → classified as noise
        self.assertIn("trailing impacket chatter", noise)


class TestExecSupersededByFullEngine(unittest.TestCase):
    """#2: when a full-engine pathway (winrm/ssh) already claims a host, the
    executor routes by pathways[0] and never runs the compact probe. plan_host
    must keep pathways honest (no dead exec entry) and label the visibility row
    'superseded' rather than advertising it will run."""

    def test_winrm_primary_supersedes_exec(self):
        spec = le.HostSpec(host="192.0.2.21", os="windows")
        cred = le.Cred(user="admin", password="pw")
        probe, _ = _probe_or_refuse("wmiexec")
        hp = le.plan_host(spec, cred, {"winrm", "exec"}, "wmiexec", probe)
        self.assertEqual(hp.pathways, ["winrm"])  # exec not a dead pathway
        row = next(r.line() for r in hp.rows if "|wmiexec|compact|" in r.line())
        self.assertIn("superseded", row)

    def test_exec_sole_pathway_still_runs(self):
        # Regression guard: when exec is the only usable pathway it is appended
        # and the row advertises fits=yes (unchanged behavior).
        spec = le.HostSpec(host="192.0.2.21", os="windows")
        cred = le.Cred(user="admin", password="pw")
        probe, _ = _probe_or_refuse("wmiexec")
        hp = le.plan_host(spec, cred, {"exec"}, "wmiexec", probe)
        self.assertEqual(hp.pathways, ["wmiexec"])
        row = next(r.line() for r in hp.rows if "|wmiexec|compact|" in r.line())
        self.assertIn("fits=yes", row)
        self.assertNotIn("superseded", row)


class TestWindowsEngineHostTimeoutCap(unittest.TestCase):
    """#3: bulk-enum-windows.py has no --host-timeout; the orchestrator must
    enforce it as a subprocess wall-clock cap = host_timeout * group_size (0 =
    unbounded)."""

    def _cap_for(self, host_timeout, n_hosts):
        captured = {}

        def fake_run_bounded(argv, **kw):
            captured["timeout"] = kw.get("timeout")
            return (0, "", "", False)

        args = mock.Mock(ad=False, parallel=4, connect_timeout=5,
                         host_timeout=host_timeout)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(le, "run_bounded", side_effect=fake_run_bounded), \
                mock.patch.object(le, "_collect_engine_dirs", return_value={}):
            grp = [le.HostPlan(le.HostSpec(host=f"192.0.2.{i}", os="windows"),
                               le.Cred(user="a", password="pw")) for i in range(n_hosts)]
            le.run_windows_engine(grp, le.Cred(user="a", password="pw"),
                                  ["winrm"], False, Path(d), 0, args)
        return captured["timeout"]

    def test_cap_scales_with_group_size(self):
        self.assertEqual(self._cap_for(5, 3), 15)

    def test_zero_host_timeout_stays_unbounded(self):
        self.assertEqual(self._cap_for(0, 3), 0)


class TestRunBoundedExitRace(unittest.TestCase):
    """#10: a first-signal ProcessLookupError (the group exited between the
    timeout and the kill) must still reap buffered output, not raise
    UnboundLocalError."""

    def test_processlookup_returns_bound_output(self):
        calls = {"n": 0}

        class FakeProc:
            pid = 4242
            returncode = 0

            def communicate(self, input=None, timeout=None):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise subprocess.TimeoutExpired(cmd="x", timeout=timeout)
                return (b"partial-out", b"partial-err")

        with mock.patch.object(le.subprocess, "Popen", return_value=FakeProc()), \
                mock.patch.object(le.os, "killpg", side_effect=ProcessLookupError):
            rc, out, err, to = le.run_bounded(["x"], timeout=1)
        self.assertTrue(to)
        self.assertEqual(rc, 124)
        self.assertEqual(out, "partial-out")
        self.assertEqual(err, "partial-err")


class TestSelfScanCollectorError(unittest.TestCase):
    """#4: the linux self-scan must fold a non-zero collector rc into status,
    not report OK when the collector failed."""

    def test_missing_collector_script_is_collector_err(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            missing = str(Path(d) / "does-not-exist.sh")
            args = mock.Mock(host_timeout=0, linux_posture_script=missing,
                             linux_script=missing, windows_script=None, ad=False)
            rc = le.run_self_scan(out, args, le.Cred())
            self.assertEqual(rc, 0)
            meta = json.loads((out / "linux" / "localhost" / "_meta.json").read_text())
            self.assertEqual(meta["status"], "COLLECTOR_ERR")
            self.assertNotEqual(meta["rc"], 0)


class TestWindowsSelfScanScriptOverride(unittest.TestCase):
    """#8: the windows self-scan must honor --windows-script, symmetric with the
    linux --linux-script override."""

    def test_windows_script_override_is_read(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            override = Path(d) / "my-privesc.ps1"
            override.write_text("# SENTINEL-OVERRIDE-PRIVESC\n", encoding="utf-8")
            seen = {}

            def fake_payload(privesc_src, posture_src, ad=False):
                seen["privesc_src"] = privesc_src
                return "payload"

            args = mock.Mock(host_timeout=0, windows_script=str(override), ad=False)
            with mock.patch.object(le, "_self_scan_os", return_value="windows"), \
                    mock.patch.object(le, "_which_powershell", return_value="pwsh"), \
                    mock.patch.object(le.WE, "build_posture_payload",
                                      side_effect=fake_payload), \
                    mock.patch.object(le, "run_bounded",
                                      return_value=(0, "", "", False)):
                le.run_self_scan(out, args, le.Cred())
            self.assertIn("SENTINEL-OVERRIDE-PRIVESC", seen["privesc_src"])


class TestSkippedHostRecord(unittest.TestCase):
    """#5: a planned host with no usable pathway must leave a SKIPPED per-host
    record so an unreachable machine appears in the inventory."""

    def test_no_pathway_host_gets_skipped_meta(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            hp = le.HostPlan(le.HostSpec(host="192.0.2.99", os="linux"), le.Cred())
            hp.skip = "no-credentials"
            le.execute_plans([hp], out, {"ssh"}, None, None, False, mock.Mock())
            meta = json.loads((out / "linux" / "192.0.2.99" / "_meta.json").read_text())
            self.assertEqual(meta["status"], "SKIPPED")
            self.assertIn("no-credentials", meta["fail_reason"])


class TestExecPortWarning(unittest.TestCase):
    """#6: a non-default port on a host routed to an exec method is ignored by
    impacket; the tool must warn rather than silently connect to 445."""

    def test_nondefault_port_warns(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            spec = le.HostSpec(host="192.0.2.21", os="windows", port=139)
            hp = le.HostPlan(spec, le.Cred(user="admin", password="pw"))
            hp.pathways = ["wmiexec"]
            probe, _ = _probe_or_refuse("wmiexec")
            warned = []
            with mock.patch.object(le, "warn", side_effect=warned.append), \
                    mock.patch.object(le, "run_exec_probe",
                                      return_value={"status": "DEP_MISSING"}):
                le.execute_plans([hp], out, {"exec"}, "wmiexec", probe, False,
                                 mock.Mock())
            self.assertTrue(any("139" in w and "ignored" in w for w in warned))


class TestMixedHostServiceEvidence(unittest.TestCase):
    """#7: in a mixed tree a host that is both a bulk-posture host and an
    auto-enum service host must resolve its service card's evidence from the
    service dir, not be overridden by the bulk-posture files."""

    def test_service_card_resolves_service_dir_not_bulk(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # bulk-posture host "192.0.2.50"
            linux = root / "linux"
            (linux / "192.0.2.50").mkdir(parents=True)
            (linux / le.BULK_ROOT_MARKER).write_text(
                json.dumps({"writer": "local-enum.py", "os": "linux"}))
            (linux / "192.0.2.50" / "_meta.json").write_text(
                json.dumps({"status": "OK", "host": "192.0.2.50"}))
            (linux / "192.0.2.50" / "linenum.txt").write_text(
                "POSTURE|KRN-01|PASS|ok\n")
            # same host, a genuine ssh service dir
            svc = root / "ssh" / "192.0.2.50"
            svc.mkdir(parents=True)
            (svc / "banner.txt").write_text("SSH-2.0-OpenSSH_7.4\n")
            model = dash.build_index(root, bulk=True, rules_path=None)
            ssh_rows = [r for r in model["inventory"]
                        if r["host"] == "192.0.2.50" and r["service"] == "ssh"]
            self.assertTrue(ssh_rows, "expected an ssh inventory row for the host")
            ev = ssh_rows[0]["evidence_files"]
            self.assertTrue(any("ssh/192.0.2.50/banner.txt" in e for e in ev))
            self.assertFalse(any("linenum.txt" in e for e in ev),
                             "ssh card must not show bulk-posture files")


class TestPartitionLocalEquals(unittest.TestCase):
    """#9: _partition_local must route `--opt=value` forms, not only separate
    tokens."""

    def test_opt_equals_value_routes_like_separate_tokens(self):
        auto, local = aranum._partition_local(
            ["scan.gnmap", "--targets=hosts.txt", "--transport=ssh",
             "--only=http", "-u=jay"])
        # local-only value flag in =value form
        self.assertIn("--targets=hosts.txt", local)
        self.assertNotIn("--targets=hosts.txt", auto)
        self.assertIn("--transport=ssh", local)
        self.assertNotIn("--transport=ssh", auto)
        # auto-only flag unknown to the local layer
        self.assertIn("--only=http", auto)
        self.assertNotIn("--only=http", local)


if __name__ == "__main__":
    unittest.main()
