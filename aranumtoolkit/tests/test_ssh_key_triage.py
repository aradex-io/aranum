"""Tests for aranumtoolkit/network/ssh-key-triage.py.

Covers: key inventory + fingerprint parity with ssh-keygen, passphrase unlock,
the SAFETY-CRITICAL probe-argv shape (ADR-006 BLOCKER 3 key-probe row), matrix
assembly against a MOCKED ssh shim on PATH, and output schema.

No live SSH: `ssh` is shimmed on PATH; probes hit the shim, never a real host.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MODPATH = REPO / "aranumtoolkit" / "network" / "ssh-key-triage.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ssh_key_triage", MODPATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


skt = _load_module()

_HAVE_KEYGEN = shutil.which("ssh-keygen") is not None


def _keygen(path: Path, ktype: str, passphrase: str = "", comment: str = "t") -> None:
    argv = ["ssh-keygen", "-t", ktype, "-f", str(path), "-N", passphrase, "-C", comment, "-q"]
    if ktype == "rsa":
        argv[2:2] = []  # keep default bits (2048+) — fast enough
        argv += ["-b", "2048"]
    subprocess.run(argv, check=True, capture_output=True)


@pytest.fixture(scope="module")
def keydir(tmp_path_factory):
    if not _HAVE_KEYGEN:
        pytest.skip("ssh-keygen not available to generate test keys")
    d = tmp_path_factory.mktemp("keys")
    _keygen(d / "k_ed", "ed25519", comment="ed-test")
    _keygen(d / "k_rsa_enc", "rsa", passphrase="hunter2", comment="rsa-enc")
    return d


# ------------------------------------------------------------------ inventory
def test_inventory_types_and_bits(keydir):
    inv = {r["path"].rsplit("/", 1)[-1]: r for r in
           [skt.inventory_key(p, ["hunter2"]) for p in sorted(keydir.iterdir())
            if not p.name.endswith(".pub")]}
    assert inv["k_ed"]["type"] == "ed25519"
    assert inv["k_ed"]["encrypted"] is False
    assert inv["k_rsa_enc"]["type"] == "rsa"
    assert inv["k_rsa_enc"]["bits"] == 2048
    assert inv["k_ed"]["format"] == "openssh"
    for r in inv.values():
        assert r["fingerprint_sha256"] and r["fingerprint_sha256"].startswith("SHA256:")
        assert r["fingerprint_md5"] and r["fingerprint_md5"].startswith("MD5:")


def test_inventory_fingerprint_matches_ssh_keygen(keydir):
    ed = keydir / "k_ed"
    truth = subprocess.run(
        ["ssh-keygen", "-lf", str(ed) + ".pub"], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    rec = skt.inventory_key(ed, [])
    assert rec["fingerprint_sha256"] == truth


def test_encrypted_key_passphrase_unlock(keydir):
    rec = skt.inventory_key(keydir / "k_rsa_enc", ["nope", "hunter2"])
    assert rec["encrypted"] is True
    assert rec["unlocked"] is True


def test_encrypted_key_wrong_passphrase(keydir):
    rec = skt.inventory_key(keydir / "k_rsa_enc", ["wrong1", "wrong2"])
    assert rec["encrypted"] is True
    assert rec["unlocked"] is False


# ------------------------------------------------------------------ probe argv
def test_probe_argv_is_nondestructive_publickey_only():
    argv = skt.build_probe_argv(
        "/tmp/k", "root", "10.0.0.1", 22, "/tmp/kh", 8
    )
    joined = " ".join(argv)
    # BLOCKER 3 key-probe row assertions:
    assert "BatchMode=yes" in argv
    assert "IdentitiesOnly=yes" in argv
    assert "PasswordAuthentication=no" in argv
    # Pubkey auth must NOT be disabled — it's the whole probe.
    assert "PubkeyAuthentication=no" not in joined
    assert "PubkeyAuthentication=yes" in argv
    assert "PreferredAuthentications=publickey" in argv
    # one key per connection + per-engagement known_hosts silo
    assert argv[:2] == ["ssh", "-i"] or ("-i" in argv)
    assert "UserKnownHostsFile=/tmp/kh" in argv
    assert argv[-1] == "true"  # benign remote command


def test_probe_argv_ipv6_is_bare_for_openssh_destination():
    argv = skt.build_probe_argv("/tmp/k", "root", "2001:db8::1", 2222, "/tmp/kh", 8)
    assert "root@2001:db8::1" in argv
    assert "root@[2001:db8::1]" not in argv
    assert "2222" in argv


# ------------------------------------------------------------------ ssh shim
def _install_ssh_shim(bindir: Path, logfile: Path) -> None:
    """A fake `ssh` that records argv and accepts only 10.0.0.1."""
    shim = bindir / "ssh"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        'printf "%s\\n" "$*" >> "$FAKE_SSH_LOG"\n'
        'dest=""\n'
        'for a in "$@"; do case "$a" in *@*) dest="$a";; esac; done\n'
        'case "$dest" in\n'
        "  *10.0.0.1*) exit 0 ;;\n"
        '  *) echo "Permission denied (publickey)." >&2; exit 255 ;;\n'
        "esac\n"
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    _ = logfile  # created lazily by shim


def test_matrix_assembly_with_mocked_ssh(keydir, tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "ssh_argv.log"
    _install_ssh_shim(bindir, log)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_SSH_LOG", str(log))

    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n10.0.0.2\n")
    outdir = tmp_path / "out"

    rc = skt.main([
        "--keys", str(keydir),
        "--targets", str(targets),
        "--users", "root",
        "--passwords", str(_write(tmp_path / "pw.txt", "hunter2\n")),
        "--parallel", "2",
        "--connect-timeout", "3",
        "--output", str(outdir),
    ])
    assert rc == 0

    doc = json.loads((outdir / "key-triage.json").read_text())
    assert doc["tool"] == "ssh-key-triage"
    # The encrypted key is inventory-only even though its passphrase was
    # validated; only the directly probeable key consumes auth attempts.
    assert len(doc["matrix"]) == 2
    by_host = {}
    for m in doc["matrix"]:
        by_host.setdefault(m["host"], set()).add(m["accepted"])
    assert by_host["10.0.0.1"] == {True}
    assert by_host["10.0.0.2"] == {False}

    # the shim recorded the real argv — assert the safety-critical -o options
    argv_log = log.read_text()
    assert "BatchMode=yes" in argv_log
    assert "IdentitiesOnly=yes" in argv_log
    assert "PasswordAuthentication=no" in argv_log
    assert "PubkeyAuthentication=no" not in argv_log

    pairs = [json.loads(l) for l in (outdir / "authorized-pairs.jsonl").read_text().splitlines()]
    assert len(pairs) == 1
    assert pairs[0]["schema"] == skt.AUTHORIZED_PAIR_SCHEMA
    assert pairs[0]["user"] == "root" and pairs[0]["host"] == "10.0.0.1"
    assert pairs[0]["port"] == 22


def _write(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


# ------------------------------------------------------------------ schema / dry-run
def test_dry_run_produces_schema_no_probes(keydir, tmp_path, monkeypatch):
    # Guard: if a probe were attempted, this bogus ssh would blow up loudly.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    boom = bindir / "ssh"
    boom.write_text("#!/usr/bin/env bash\necho 'DRY-RUN MUST NOT PROBE' >&2\nexit 42\n")
    boom.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")

    targets = tmp_path / "t.txt"
    targets.write_text("10.0.0.9\n")
    outdir = tmp_path / "dry"
    rc = skt.main([
        "--keys", str(keydir),
        "--targets", str(targets),
        "--users", "root",
        "--dry-run",
        "--output", str(outdir),
    ])
    assert rc == 0
    doc = json.loads((outdir / "key-triage.json").read_text())
    for field in ("generated", "tool", "inventory", "targets", "users", "matrix", "params"):
        assert field in doc
    assert doc["matrix"] == []  # no probes on dry-run
    assert doc["planned_probes"] >= 1
    assert (outdir / "key-triage.md").is_file()
    assert (outdir / "authorized-pairs.jsonl").is_file()


def test_output_schema_fields_present_after_run(keydir, tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _install_ssh_shim(bindir, tmp_path / "log")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_SSH_LOG", str(tmp_path / "log"))
    targets = tmp_path / "t.txt"
    targets.write_text("10.0.0.1\n")
    outdir = tmp_path / "out2"
    skt.main([
        "--keys", str(keydir), "--targets", str(targets),
        "--users", "root", "--output", str(outdir),
        "--passwords", str(_write(tmp_path / "pw2.txt", "hunter2\n")),
    ])
    doc = json.loads((outdir / "key-triage.json").read_text())
    m = doc["matrix"][0]
    for field in ("key", "user", "host", "port", "rc", "status", "accepted"):
        assert field in m


def test_attempt_cap_applies_after_probeability_filter():
    inventory = skt.annotate_probeability([
        {"path": "/keys/00-invalid", "error": "bad key", "encrypted": False, "public_key": None},
        {"path": "/keys/01-valid", "error": None, "encrypted": False, "public_key": "ssh-ed25519 AAA"},
    ])
    plan = skt.build_probe_plan(inventory, ["alice"], [("host.test", 2222)], 1)
    assert plan == [("/keys/01-valid", "alice", "host.test", 2222)]
    assert inventory[0]["probe_skip_reason"].startswith("inventory error")


def test_unlocked_encrypted_key_is_inventory_only():
    inventory = skt.annotate_probeability([
        {"path": "/keys/enc", "error": None, "encrypted": True,
         "unlocked": True, "public_key": "ssh-rsa AAA"},
    ])
    assert inventory[0]["probeable"] is False
    assert "ssh-agent" in inventory[0]["probe_skip_reason"]


def test_global_rate_limiter_uses_one_start_timeline():
    state = {"now": 0.0}
    sleeps = []

    def clock():
        return state["now"]

    def sleeper(delay):
        sleeps.append(delay)
        state["now"] += delay

    limiter = skt.StartRateLimiter(0.5, clock=clock, sleeper=sleeper)
    starts = [limiter.wait(), limiter.wait(), limiter.wait(), limiter.wait()]
    assert starts == [0.0, 0.5, 1.0, 1.5]
    assert sleeps == [0.5, 0.5, 0.5]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
