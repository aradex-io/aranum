#!/usr/bin/env python3
"""test_dispatcher_contract.py — fixture-based tests asserting that the
network/enum-*.sh dispatcher fleet honours the contract defined by
network/_lib.sh::parse_common_args.

These tests do NOT spin up live services — they exercise the dispatcher
against an empty targets file and an existing fixture, and assert:
  - rc == 0 (the contract is honoured on the no-work path)
  - $OUT directory exists and is writable (mkdir -p ran)
  - dispatchers that document a `_hints.txt` convention produce it

Coverage matrix is intentionally aligned with smoke.sh §10b.2 so any
divergence between the two surfaces shows up in test failure messages.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Dispatchers that wrote _hints.txt unconditionally as of v0.30.1, even with
# zero targets. (Mirrors smoke.sh §10b.2 HINTS_REQUIRED.)
HINTS_REQUIRED = [
    "backup", "cassandra", "consul", "flexnet", "hpc", "influxdb", "ipp",
    "kafka", "monitoring", "neo4j", "netbios-ns", "pop3", "imap", "print",
    "solr", "telnet", "vault", "zookeeper",
]

# Dispatchers that do NOT emit _hints.txt — either pre-convention (Tier-1)
# or because they early-return when a prerequisite system tool is missing.
HINTS_OPTIONAL = [
    "dns", "ftp", "kerberos", "ldap", "rdp", "smb", "smtp", "snmp", "ssh",
    "unknown", "winrm", "http", "https",
    # Tool-gated:
    "activemq", "ajp", "mqtt", "oracle", "sip", "rsync",
]

# Env-gated aggressive UDP — must refuse with rc=0 when ENUM_RUN_X is unset.
GATED = ["ike", "slp", "radius"]


class TestDispatcherContract(unittest.TestCase):
    """parse_common_args contract: every dispatcher accepts
    `--targets <file> --output <dir>` and exits 0 on empty input."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="aratool-dispatcher-test-")
        cls._empty_targets = Path(cls._tmp) / "empty.txt"
        cls._empty_targets.write_text("")

    @classmethod
    def tearDownClass(cls):
        # Best-effort cleanup; tmp dir is small.
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run(self, svc: str, env_extra: dict | None = None, timeout: int = 15):
        out_dir = Path(self._tmp) / f"out-{svc}"
        # Pristine OUT — exercise dispatcher's own mkdir -p
        if out_dir.exists():
            import shutil; shutil.rmtree(out_dir)
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        r = subprocess.run(
            ["bash", str(REPO / "network" / f"enum-{svc}.sh"),
             "--targets", str(self._empty_targets),
             "--output", str(out_dir)],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        return r, out_dir

    def test_hints_required_dispatchers(self):
        for svc in HINTS_REQUIRED:
            with self.subTest(dispatcher=svc):
                r, out_dir = self._run(svc)
                self.assertEqual(0, r.returncode,
                                 f"enum-{svc}.sh exited {r.returncode}; "
                                 f"stderr={r.stderr!r}")
                self.assertTrue(out_dir.is_dir(),
                                f"enum-{svc}.sh did not create $OUT directory")
                self.assertTrue((out_dir / "_hints.txt").is_file(),
                                f"enum-{svc}.sh did not write _hints.txt")

    def test_hints_optional_dispatchers(self):
        for svc in HINTS_OPTIONAL:
            with self.subTest(dispatcher=svc):
                r, out_dir = self._run(svc)
                self.assertEqual(0, r.returncode,
                                 f"enum-{svc}.sh exited {r.returncode}; "
                                 f"stderr={r.stderr!r}")
                self.assertTrue(out_dir.is_dir(),
                                f"enum-{svc}.sh did not create $OUT directory")

    def test_gated_dispatchers_refuse_without_env(self):
        """CLAUDE.md §9 invariant: E4 aggressive UDP probes must refuse to
        run unless their env gate is set, even with valid targets/output."""
        for svc in GATED:
            with self.subTest(dispatcher=svc):
                r, _ = self._run(svc)  # NO env_extra; gate is unset
                self.assertEqual(0, r.returncode,
                                 f"enum-{svc}.sh refusal path rc={r.returncode}; "
                                 f"expected 0 (informational refusal)")
                # Should print a "refuses" / "ENUM_RUN" / "--ike/--slp/--radius"
                # hint. err() in network/_lib.sh writes to stdout, not stderr,
                # so we union both streams when looking for the marker.
                combined = (r.stderr + r.stdout).lower()
                self.assertTrue(
                    any(token in combined for token in
                        ("refuses", "enum_run", svc)),
                    f"enum-{svc}.sh refusal didn't print expected hint: "
                    f"stdout={r.stdout!r} stderr={r.stderr!r}")


class TestParseCommonArgsRejection(unittest.TestCase):
    """parse_common_args (network/_lib.sh) must reject unknown args with
    rc=1 and an "unknown arg:" message, so dispatchers fail loudly when
    operators pass a typo'd flag rather than silently ignoring it."""

    def _run(self, args):
        r = subprocess.run(
            ["bash", "-c",
             f". {REPO}/network/_lib.sh && parse_common_args {args}"],
            capture_output=True, text=True, timeout=5,
        )
        return r

    def test_unknown_flag_rejected(self):
        r = self._run("--bogus --foo")
        self.assertEqual(1, r.returncode)
        self.assertIn("unknown arg", r.stdout + r.stderr)

    def test_missing_targets_rejected(self):
        r = self._run("--output /tmp/x")
        self.assertEqual(1, r.returncode)
        self.assertIn("usage:", r.stdout + r.stderr)

    def test_missing_output_rejected(self):
        r = self._run("--targets /tmp/x")
        self.assertEqual(1, r.returncode)
        self.assertIn("usage:", r.stdout + r.stderr)

    def test_missing_targets_file_rejected(self):
        r = self._run("--targets /tmp/does-not-exist-XYZ-zzz "
                      "--output /tmp/aratool-test-out-xxx")
        self.assertEqual(1, r.returncode)
        self.assertIn("targets file missing", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
