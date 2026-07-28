#!/usr/bin/env python3
"""test_bulk_enum_linux_auth.py — ADR-006 workstream 1a regression tests.

Fakes `ssh` and `sshpass` on $PATH with shims that record the exact argv they
were invoked with (one arg per line) and exit with a configurable rc / stderr.
The bulk-enum-linux.sh script is then run against a 1-host targets file in each
auth mode, and we ASSERT on the captured argv + the emitted _summary.tsv.

This makes the historical BatchMode/sshpass bug impossible to re-ship: the
password paths are proven to NOT carry `BatchMode=yes`, and the key-then-pass
path is proven to keep pubkey enabled while offering the key first.

Run: cd <repo> && python3 -m pytest tests/test_bulk_enum_linux_auth.py -x -q
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "aranumtoolkit" / "network" / "bulk-enum-linux.sh"

# Shim template: record argv (one per line), drain stdin, emit optional stderr,
# exit configurable rc. The argv-output path is baked in per shim instance.
SHIM = """#!/usr/bin/env bash
printf '%s\\n' "$@" >> {argv_file!r}
cat >/dev/null 2>&1 || true
if [ -n "${{SHIM_STDERR:-}}" ]; then printf '%s\\n' "$SHIM_STDERR" >&2; fi
# Optional sleep so the --host-timeout wrapper (coreutils `timeout`) can fire.
[ "${{SHIM_SLEEP:-0}}" != "0" ] && sleep "$SHIM_SLEEP"
exit "${{SHIM_RC:-0}}"
"""


def _make_shim(bindir: Path, name: str, argv_file: Path) -> None:
    p = bindir / name
    p.write_text(SHIM.format(argv_file=str(argv_file)))
    p.chmod(0o755)


def _run(tmp_path, *, key=False, password=False, shim_rc=0, shim_stderr="",
         shim_sleep=0, host_timeout=None):
    """Run bulk-enum-linux.sh once against a 1-host list with shimmed ssh/sshpass.

    Returns (proc, ssh_argv_lines, sshpass_argv_lines, summary_text).
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    ssh_argv = tmp_path / "ssh.argv"
    sshpass_argv = tmp_path / "sshpass.argv"
    _make_shim(bindir, "ssh", ssh_argv)
    _make_shim(bindir, "sshpass", sshpass_argv)

    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.99\n")
    outdir = tmp_path / "out"

    cmd = [
        "bash", str(SCRIPT),
        "--targets", str(targets),
        "-o", str(outdir),
        "--user", "tuser",
        "--no-preflight",       # keep exactly one invocation in the argv record
    ]
    if host_timeout is not None:
        cmd += ["--host-timeout", str(host_timeout)]
    if key:
        keyfile = tmp_path / "id_test"
        keyfile.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
        keyfile.chmod(0o600)
        cmd += ["--key", str(keyfile)]
    if password:
        cmd += ["--pass", "Hunter2!"]

    env = dict(os.environ)
    env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
    env["SHIM_RC"] = str(shim_rc)
    env["SHIM_STDERR"] = shim_stderr
    env["SHIM_SLEEP"] = str(shim_sleep)
    env["NO_COLOR"] = "1"

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)

    ssh_lines = ssh_argv.read_text().splitlines() if ssh_argv.exists() else []
    sshpass_lines = sshpass_argv.read_text().splitlines() if sshpass_argv.exists() else []
    summary = (outdir / "_summary.tsv").read_text() if (outdir / "_summary.tsv").exists() else ""
    return proc, ssh_lines, sshpass_lines, summary


# --------------------------------------------------------------------- argv: KEY
def test_key_mode_argv(tmp_path):
    proc, ssh_lines, sshpass_lines, _ = _run(tmp_path, key=True)
    assert proc.returncode == 0, proc.stderr
    # KEY mode goes straight through ssh — sshpass must NOT be invoked.
    assert sshpass_lines == [], f"sshpass should not run in KEY mode: {sshpass_lines}"
    assert "BatchMode=yes" in ssh_lines, ssh_lines
    assert "-i" in ssh_lines, ssh_lines
    assert "IdentitiesOnly=yes" in ssh_lines, ssh_lines


# --------------------------------------------------------------------- argv: PASS
def test_pass_mode_argv(tmp_path):
    proc, _ssh_lines, sshpass_lines, _ = _run(tmp_path, password=True)
    assert proc.returncode == 0, proc.stderr
    # PASS mode wraps ssh in sshpass — sshpass argv carries the ssh options.
    assert sshpass_lines, "sshpass must be invoked in PASS mode"
    assert "BatchMode=yes" not in sshpass_lines, sshpass_lines
    assert "NumberOfPasswordPrompts=1" in sshpass_lines, sshpass_lines
    assert "PubkeyAuthentication=no" in sshpass_lines, sshpass_lines


# --------------------------------------------------------------- argv: KEY_THEN_PASS
def test_key_then_pass_mode_argv(tmp_path):
    proc, _ssh_lines, sshpass_lines, _ = _run(tmp_path, key=True, password=True)
    assert proc.returncode == 0, proc.stderr
    assert sshpass_lines, "sshpass must be invoked in KEY_THEN_PASS mode"
    assert "-i" in sshpass_lines, sshpass_lines
    # Pubkey stays enabled so the key is tried first, password is the fallback.
    assert "PubkeyAuthentication=no" not in sshpass_lines, sshpass_lines
    assert "BatchMode=yes" not in sshpass_lines, sshpass_lines
    assert "NumberOfPasswordPrompts=1" in sshpass_lines, sshpass_lines


# --------------------------------------------------------------- status classification
def _status_for_host(summary: str, host: str = "10.0.0.99") -> str:
    for line in summary.splitlines():
        if line.startswith("#"):
            continue
        cols = line.split("\t")
        if cols and cols[0] == host:
            return cols[1]  # host<TAB>status<TAB>rc<TAB>...
    raise AssertionError(f"host {host} not in summary:\n{summary}")


def test_status_auth_fail(tmp_path):
    # rc 255 + "Permission denied" on stderr -> AUTH_FAIL
    proc, _s, _p, summary = _run(
        tmp_path, key=True, shim_rc=255,
        shim_stderr="Permission denied (publickey,password).")
    assert proc.returncode == 0, proc.stderr
    assert _status_for_host(summary) == "AUTH_FAIL", summary


def test_status_ok(tmp_path):
    # rc 0 -> OK
    _proc, _s, _p, summary = _run(tmp_path, key=True, shim_rc=0)
    assert _status_for_host(summary) == "OK", summary


def test_status_remote_err(tmp_path):
    # rc 1 (auth succeeded, remote bash exited non-zero) -> REMOTE_ERR
    _proc, _s, _p, summary = _run(tmp_path, key=True, shim_rc=1)
    assert _status_for_host(summary) == "REMOTE_ERR", summary


def test_status_host_timeout(tmp_path):
    # A host whose enum outruns --host-timeout is killed by coreutils `timeout`
    # (rc 124) and classified HOST_TIMEOUT — NOT retried, NOT a false AUTH_FAIL.
    if subprocess.run(["bash", "-c", "command -v timeout"],
                      capture_output=True).returncode != 0:
        pytest.skip("coreutils 'timeout' not available")
    _proc, _s, _p, summary = _run(tmp_path, key=True, shim_sleep=5, host_timeout=1)
    assert _status_for_host(summary) == "HOST_TIMEOUT", summary


def test_host_timeout_zero_disables_cap(tmp_path):
    # --host-timeout 0 must run WITHOUT the timeout wrapper (legacy behaviour):
    # a fast shim still returns OK, no HOST_TIMEOUT false-positive.
    _proc, _s, _p, summary = _run(tmp_path, key=True, shim_rc=0, host_timeout=0)
    assert _status_for_host(summary) == "OK", summary


# --------------------------------------------------------------- preflight (continues)
def test_preflight_auth_fail_continues(tmp_path):
    """--preflight on an AUTH_FAIL first host warns but must still complete
    the run (exit 0) and produce a summary."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _make_shim(bindir, "ssh", tmp_path / "ssh.argv")
    _make_shim(bindir, "sshpass", tmp_path / "sshpass.argv")
    targets = tmp_path / "t.txt"
    targets.write_text("10.0.0.99\n")
    outdir = tmp_path / "out"

    env = dict(os.environ)
    env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
    env["SHIM_RC"] = "255"
    env["SHIM_STDERR"] = "Permission denied (publickey)."
    env["NO_COLOR"] = "1"
    keyfile = tmp_path / "id_test"
    keyfile.write_text("fake\n")
    keyfile.chmod(0o600)

    proc = subprocess.run(
        ["bash", str(SCRIPT), "--targets", str(targets), "-o", str(outdir),
         "--user", "tuser", "--key", str(keyfile), "--preflight"],
        capture_output=True, text=True, timeout=60, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "auth failed against first host" in proc.stdout, proc.stdout
    assert (outdir / "_summary.tsv").exists()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-x", "-q"]))
