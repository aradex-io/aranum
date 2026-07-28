#!/usr/bin/env python3
"""test_ssh_triage.py — T3 unit tests for aranumtoolkit/network/ssh-triage.sh.

ADR-006 Workstream 1b: OS-aware SSH sweep dispatcher. ssh-triage.sh classifies
hosts (nxc-trusted label > SSH banner > one authenticated probe when creds are
present) and shells out to bulk-enum-linux.sh / bulk-enum-windows.py — it never
reimplements their SSH/WinRM logic.

Everything here runs against shims, not live hosts:
  - `nc` and `ssh` are replaced with tiny canned-output scripts on $PATH so
    banner grabs and the authenticated OS probe never touch a real socket.
  - `bulk-enum-linux.sh` / `bulk-enum-windows.py` are replaced with capture
    scripts on $PATH ahead of the real tools (ssh-triage.sh resolves both via
    `command -v` first, falling back to the sibling copy — see
    aranumtoolkit/network/ssh-triage.sh's _resolve_tool), so dispatch routing
    is verified without invoking the real bulk tools.

Run with: cd /srv/share/dev/aranum && python3 -m pytest tests/test_ssh_triage.py -x -q
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NETWORK = REPO / "aranumtoolkit" / "network"
SSH_TRIAGE = NETWORK / "ssh-triage.sh"
ENUM_SSH = NETWORK / "enum-ssh.sh"
LIB = NETWORK / "_lib.sh"
FIXTURE_GNMAP = NETWORK / "test.gnmap"
FIXTURE_XML = NETWORK / "test.xml"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run_bash(snippet: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run a bash snippet with _lib.sh + enum-ssh.sh sourced first."""
    full = f". '{LIB}'\n. '{ENUM_SSH}'\n{snippet}\n"
    return subprocess.run(
        ["bash", "-c", full], capture_output=True, text=True, timeout=timeout
    )


def _run_triage(
    args: list[str],
    *,
    cwd: Path,
    extra_path: Path | None = None,
    stdin_text: str | None = None,
    timeout: int = 20,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if extra_path is not None:
        env["PATH"] = f"{extra_path}:{env.get('PATH', '')}"
    return subprocess.run(
        ["bash", str(SSH_TRIAGE), *args],
        cwd=cwd,
        env=env,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _shim_dir(tmp_path: Path) -> Path:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    return d


# --------------------------------------------------------------------- banner -> OS
class TestBannerMapping(unittest.TestCase):
    """classify_ssh_os_from_banner (enum-ssh.sh) — the cheapest OS signal."""

    CASES = [
        ("SSH-2.0-OpenSSH_for_Windows_8.1", "windows"),
        ("SSH-2.0-OpenSSH_for_Windows_7.7", "windows"),
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "linux"),
        ("SSH-2.0-OpenSSH_7.4", "linux"),
        ("SSH-1.99-OpenSSH_3.9", "linux"),
        ("SSH-2.0-Sun_SSH_1.3", "linux"),
        ("SSH-2.0-dropbear_2019.78", "other"),
        ("SSH-2.0-ROSSSH", "other"),
        ("", "other"),
        ("garbage not a banner at all", "other"),
    ]

    def test_banner_mapping_table(self):
        for banner, expected in self.CASES:
            with self.subTest(banner=banner):
                r = _run_bash(f"classify_ssh_os_from_banner {banner!r}")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), expected)

    def test_direct_execution_of_enum_ssh_unchanged(self):
        """Sourcing must NOT run enum-ssh.sh's main body (no --targets given,
        parse_common_args would otherwise print usage and exit 1); direct
        execution must still behave exactly as before (usage + exit 1 with
        no args)."""
        r = subprocess.run(
            ["bash", str(ENUM_SSH)], capture_output=True, text=True, timeout=10
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("usage", (r.stdout + r.stderr).lower())


# --------------------------------------------------------------------- ssh_probe_args
class TestSSHProbeArgs(unittest.TestCase):
    """Canonical SSH-option spec (ADR-006 post-review BLOCKER 1/3): the
    authenticated classification probe must select KEY / PASS / KEY_THEN_PASS
    / agent-default explicitly, never by inferring mode from `-n "$SSH_PASS"`
    alone — that's exactly the 1a BatchMode+sshpass bug. Assert the built argv
    per mode, mirroring T1's regression test for bulk-enum-linux.sh."""

    def _probe_args(self, key: str, passwd: str) -> list[str]:
        snippet = f". '{SSH_TRIAGE}'\nTRIAGE_KEY={key!r} TRIAGE_PASS={passwd!r} ssh_probe_args"
        r = subprocess.run(
            ["bash", "-c", snippet], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.splitlines()

    def test_key_mode(self):
        argv = self._probe_args("/tmp/mykey", "")
        self.assertIn("BatchMode=yes", argv)
        self.assertNotIn("BatchMode=no", argv)
        self.assertIn("PreferredAuthentications=publickey", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("/tmp/mykey", argv)
        self.assertNotIn("PubkeyAuthentication=no", argv)

    def test_pass_mode_never_sets_batchmode_yes(self):
        argv = self._probe_args("", "hunter2")
        self.assertNotIn("BatchMode=yes", argv, "PASS mode must not suppress the sshpass prompt")
        self.assertIn("BatchMode=no", argv)
        self.assertIn("NumberOfPasswordPrompts=1", argv)
        self.assertIn("PreferredAuthentications=keyboard-interactive,password", argv)
        self.assertIn("PubkeyAuthentication=no", argv)

    def test_key_then_pass_mode_tries_key_first_no_pubkey_disable(self):
        argv = self._probe_args("/tmp/mykey", "hunter2")
        self.assertNotIn("BatchMode=yes", argv)
        self.assertIn("BatchMode=no", argv)
        self.assertIn("NumberOfPasswordPrompts=1", argv)
        self.assertIn(
            "PreferredAuthentications=publickey,keyboard-interactive,password", argv
        )
        self.assertNotIn(
            "PubkeyAuthentication=no", argv,
            "KEY_THEN_PASS must keep pubkey auth enabled so the key is tried first",
        )
        self.assertIn("/tmp/mykey", argv)
        self.assertIn("IdentitiesOnly=yes", argv)

    def test_agent_default_mode(self):
        argv = self._probe_args("", "")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("PreferredAuthentications=publickey", argv)
        self.assertNotIn("-i", argv)


# --------------------------------------------------------------------- CLI plumbing
class TestArgValidation(unittest.TestCase):
    def test_no_input_mode_and_no_stdin_pipe_fails(self):
        # /dev/null as stdin still reports isatty()==False in some CI shells;
        # force an explicit conflicting-mode case instead for a stable check.
        r = _run_triage(["--output", "/tmp/x"], cwd=REPO, stdin_text="")
        self.assertNotEqual(r.returncode, 0)

    def test_missing_output_fails(self, tmp_path=None):
        r = subprocess.run(
            ["bash", str(SSH_TRIAGE), "--nxc", str(FIXTURE_GNMAP)],
            cwd=REPO, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(r.returncode, 0)

    def test_two_input_modes_conflict(self):
        r = subprocess.run(
            ["bash", str(SSH_TRIAGE), "--targets", str(FIXTURE_GNMAP),
             "--nmap", str(FIXTURE_GNMAP), "--output", "/tmp/x"],
            cwd=REPO, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one", (r.stdout + r.stderr).lower())


# --------------------------------------------------------------------- nxc parsing
class TestNxcParsing(unittest.TestCase):
    NXC_INPUT = textwrap.dedent(
        """\
        SSH         10.0.0.5        22     10.0.0.5         [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10 (Linux; protocol 2.0)
        SSH         10.0.0.6        22     10.0.0.6         [*] SSH-2.0-OpenSSH_for_Windows_8.1 (Windows; protocol 2.0)
        SSH         10.0.0.7        22     10.0.0.7         [*] SSH-2.0-dropbear_2019.78
        not a SSH line, should be ignored
        """
    )

    def _noop_nc(self, bindir: Path) -> None:
        # nxc-labeled hosts short-circuit before any banner grab, but 10.0.0.7
        # has no OS label so it WILL hit grab_banner — make it deterministic
        # and network-free.
        _write_exec(bindir / "nc", "#!/usr/bin/env bash\nexit 1\n")

    def test_nxc_file_trusts_printed_os_label(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            self._noop_nc(bindir)
            nxc_file = tdp / "nxc.txt"
            nxc_file.write_text(self.NXC_INPUT)
            out = tdp / "out"
            r = _run_triage(
                ["--nxc", str(nxc_file), "--output", str(out), "--dry-run"],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = (out / "classification.tsv").read_text().splitlines()
            table = {row.split("\t")[0]: row.split("\t") for row in rows[1:]}
            self.assertEqual(table["10.0.0.5"][1], "linux")
            self.assertEqual(table["10.0.0.5"][2], "nxc")
            self.assertEqual(table["10.0.0.6"][1], "windows")
            self.assertEqual(table["10.0.0.6"][2], "nxc")
            # dropbear has no OS label in the nxc line -> falls through to
            # banner classification (shimmed nc refuses -> ambiguous -> other).
            self.assertEqual(table["10.0.0.7"][1], "other")

    def test_nxc_via_stdin_when_no_input_flag_given(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            self._noop_nc(bindir)
            out = tdp / "out"
            r = _run_triage(
                ["--output", str(out), "--dry-run"],
                cwd=tdp, extra_path=bindir, stdin_text=self.NXC_INPUT,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            content = (out / "classification.tsv").read_text()
            self.assertIn("10.0.0.5\tlinux\tnxc", content)
            self.assertIn("10.0.0.6\twindows\tnxc", content)


# --------------------------------------------------------------------- nmap input path
class TestNmapInput(unittest.TestCase):
    """Reuses the repo's existing test.gnmap/test.xml fixtures — both carry a
    2222/open entry, and nmap-parse.py's ssh category matches port 2222 as
    well as 22, so no new fixture is needed (ADR-006 T3 note)."""

    def _noop_nc(self, bindir: Path) -> None:
        _write_exec(bindir / "nc", "#!/usr/bin/env bash\nexit 1\n")

    def test_gnmap_extracts_ssh_category_host(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            self._noop_nc(bindir)
            out = tdp / "out"
            r = _run_triage(
                ["--nmap", str(FIXTURE_GNMAP), "--output", str(out), "--dry-run"],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            content = (out / "classification.tsv").read_text()
            self.assertIn("127.0.0.1:2222", content)

    def test_xml_extracts_ssh_category_host(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            self._noop_nc(bindir)
            out = tdp / "out"
            r = _run_triage(
                ["--nmap", str(FIXTURE_XML), "--output", str(out), "--dry-run"],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            content = (out / "classification.tsv").read_text()
            self.assertIn("127.0.0.1:2222", content)


# --------------------------------------------------------------------- dispatch routing
class TestDispatchRouting(unittest.TestCase):
    """Shim bulk-enum-linux.sh / bulk-enum-windows.py on PATH ahead of the
    real tools and verify ssh-triage.sh routes each classified host to the
    correct one, with creds forwarded verbatim."""

    def _shims(self, bindir: Path, capture: Path) -> None:
        _write_exec(
            bindir / "bulk-enum-linux.sh",
            f"#!/usr/bin/env bash\necho \"LINUX $*\" >> {capture}\nexit 0\n",
        )
        _write_exec(
            bindir / "bulk-enum-windows.py",
            f"#!/usr/bin/env bash\necho \"WINDOWS $*\" >> {capture}\nexit 0\n",
        )

    def test_mixed_hosts_route_to_correct_tool_with_creds_forwarded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            capture = tdp / "capture.log"
            self._shims(bindir, capture)

            nxc_file = tdp / "nxc.txt"
            nxc_file.write_text(
                "SSH   10.9.9.5   22   10.9.9.5   [*] SSH-2.0-OpenSSH_8.9p1 (Linux; protocol 2.0)\n"
                "SSH   10.9.9.6   22   10.9.9.6   [*] SSH-2.0-OpenSSH_for_Windows_8.1 (Windows; protocol 2.0)\n"
            )
            out = tdp / "out"
            r = _run_triage(
                ["--nxc", str(nxc_file), "--output", str(out),
                 "--user", "alice", "--pass", "s3cret", "--parallel", "8"],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)

            log = capture.read_text()
            self.assertIn("LINUX", log)
            self.assertIn("WINDOWS", log)
            linux_line = next(l for l in log.splitlines() if l.startswith("LINUX"))
            windows_line = next(l for l in log.splitlines() if l.startswith("WINDOWS"))

            self.assertIn("--user alice", linux_line)
            self.assertIn("--pass s3cret", linux_line)
            self.assertIn("--parallel 8", linux_line)
            self.assertIn("--output", linux_line)
            self.assertIn(str(out / "linux"), linux_line)

            self.assertIn("--transport ssh", windows_line)
            self.assertIn("--user alice", windows_line)
            self.assertIn(str(out / "windows"), windows_line)

            linux_targets = (out / "linux-targets.txt").read_text()
            windows_targets = (out / "windows-targets.txt").read_text()
            self.assertIn("10.9.9.5", linux_targets)
            self.assertNotIn("10.9.9.6", linux_targets)
            self.assertIn("10.9.9.6", windows_targets)
            self.assertNotIn("10.9.9.5", windows_targets)

    def test_targets_file_spec_preserved_verbatim_for_linux_dispatch(self):
        """A --targets line's inline user@host:port must reach
        bulk-enum-linux.sh untouched (it carries auth context ssh-triage.sh
        has no other way to express)."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            capture = tdp / "capture.log"
            self._shims(bindir, capture)
            _write_exec(bindir / "nc", "#!/usr/bin/env bash\necho 'SSH-2.0-OpenSSH_8.9p1'\n")

            targets = tdp / "targets.txt"
            targets.write_text("bob@10.7.7.7:2222\n")
            out = tdp / "out"
            r = _run_triage(
                ["--targets", str(targets), "--output", str(out)],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            linux_targets = (out / "linux-targets.txt").read_text().strip()
            self.assertEqual(linux_targets, "bob@10.7.7.7:2222")

    def test_dry_run_never_invokes_bulk_tools(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            capture = tdp / "capture.log"
            self._shims(bindir, capture)

            nxc_file = tdp / "nxc.txt"
            nxc_file.write_text(
                "SSH   10.9.9.5   22   10.9.9.5   [*] SSH-2.0-OpenSSH_8.9p1 (Linux; protocol 2.0)\n"
            )
            out = tdp / "out"
            r = _run_triage(
                ["--nxc", str(nxc_file), "--output", str(out), "--dry-run"],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("[DRY]", r.stdout)
            self.assertFalse(capture.exists(), "bulk tools must NOT run under --dry-run")


# --------------------------------------------------------------------- unknown-host handling
class TestUnknownHostHandling(unittest.TestCase):
    def test_ambiguous_banner_no_creds_is_other_and_not_dispatched(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            capture = tdp / "capture.log"
            _write_exec(
                bindir / "bulk-enum-linux.sh",
                f"#!/usr/bin/env bash\necho \"LINUX $*\" >> {capture}\nexit 0\n",
            )
            _write_exec(
                bindir / "bulk-enum-windows.py",
                f"#!/usr/bin/env bash\necho \"WINDOWS $*\" >> {capture}\nexit 0\n",
            )
            # Ambiguous banner (dropbear) and no creds anywhere -> "other".
            _write_exec(bindir / "nc", "#!/usr/bin/env bash\necho 'SSH-2.0-dropbear_2019.78'\n")

            targets = tdp / "targets.txt"
            targets.write_text("10.5.5.5\n")
            out = tdp / "out"
            r = _run_triage(
                ["--targets", str(targets), "--output", str(out)],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            content = (out / "classification.tsv").read_text()
            self.assertIn("10.5.5.5\tother\tbanner\tlow", content)
            self.assertFalse(capture.exists(), "an unclassified host must never be dispatched")
            self.assertTrue((out / "unknown-hosts.txt").exists())
            unknown = (out / "unknown-hosts.txt").read_text()
            self.assertIn("10.5.5.5", unknown)
            self.assertFalse((out / "linux-targets.txt").exists())
            self.assertFalse((out / "windows-targets.txt").exists())

    def test_ambiguous_banner_with_creds_escalates_to_auth_probe(self):
        """Ambiguous banner + creds present -> one authenticated probe
        (`uname -s || ver`) classifies definitively. Shims both `nc`
        (ambiguous banner) and `ssh` (canned uname/ver output) so no live
        host is touched."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            bindir = _shim_dir(tdp)
            capture = tdp / "capture.log"
            _write_exec(
                bindir / "bulk-enum-linux.sh",
                f"#!/usr/bin/env bash\necho \"LINUX $*\" >> {capture}\nexit 0\n",
            )
            _write_exec(bindir / "nc", "#!/usr/bin/env bash\necho 'SSH-2.0-dropbear_2019.78'\n")
            # Canned ssh: emit "Linux" only when the destination is our probe host.
            _write_exec(
                bindir / "ssh",
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    for a in "$@"; do
                        case "$a" in
                            *@10.6.6.6) echo "Linux"; exit 0 ;;
                        esac
                    done
                    exit 255
                    """
                ),
            )

            targets = tdp / "targets.txt"
            targets.write_text("10.6.6.6\n")
            out = tdp / "out"
            r = _run_triage(
                ["--targets", str(targets), "--output", str(out), "--user", "alice", "--key", "/tmp/nonexistent-key"],
                cwd=tdp, extra_path=bindir,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            content = (out / "classification.tsv").read_text()
            self.assertIn("10.6.6.6\tlinux\tauth-probe\thigh", content)
            self.assertTrue(capture.exists())
            self.assertIn("LINUX", capture.read_text())


if __name__ == "__main__":
    unittest.main()
