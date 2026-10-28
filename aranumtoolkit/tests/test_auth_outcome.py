#!/usr/bin/env python3
"""Hermetic PLAN-002 A4 auth-outcome classification and reporting tests."""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
NETWORK = REPO / "aranumtoolkit" / "network"
REPORT_PATH = NETWORK / "report.py"
LOCAL_ENUM_PATH = NETWORK / "local-enum.py"
WINDOWS_BULK_PATH = NETWORK / "bulk-enum-windows.py"
LINUX_BULK_PATH = NETWORK / "bulk-enum-linux.sh"
FX5 = REPO / "aranumtoolkit" / "tests" / "fixtures" / "interop" / "FX-5"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


REPORT = _load("auth_outcome_report", REPORT_PATH)
LOCAL_ENUM = _load("auth_outcome_local_enum", LOCAL_ENUM_PATH)
WINDOWS_BULK = _load("auth_outcome_windows_bulk", WINDOWS_BULK_PATH)


def _write_host(root: Path, host: str, status: str, *, account: str = "svc-test",
                transport: str = "ssh", scope: str = "local", domain: str = "",
                credential_kind: str = "password") -> Path:
    hdir = root / host
    hdir.mkdir(parents=True)
    meta = {
        "host": host,
        "user": account,
        "port": "",
        "transport": transport,
        "status": status,
        "artifact_id": host,
        "protocol": "tcp",
        "domain": domain,
        "invocation": {
            "domain_arg": domain,
            "local_auth_flag": scope == "local",
            "username_form": "bare",
            "credential_kind": credential_kind,
            "auth_scope_declared": scope,
        },
    }
    (hdir / "_meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (hdir / "winenum.txt").write_text("synthetic bulk evidence\n", encoding="utf-8")
    return hdir


def _linux_status(tmp_path: Path, stderr: str, rc: int = 255) -> str:
    source = LINUX_BULK_PATH.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^classify_status\(\) \{\n.*?^\}\n", source)
    assert match is not None
    errfile = tmp_path / "ssh.err"
    errfile.write_text(stderr, encoding="utf-8")
    script = "set -uo pipefail\nSSH_PASS=x\n" + match.group(0) + '\nclassify_status "$1" "$2"\n'
    proc = subprocess.run(
        ["bash", "-c", script, "bash", str(rc), str(errfile)],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout.split("\t", 1)[0]


@pytest.mark.parametrize("marker", [
    "STATUS_ACCOUNT_LOCKED_OUT",
    "Account is locked out",
    "error 0xC0000234",
    "LDAP bind failed: data 775",
    "The referenced account is currently locked out",
])
def test_explicit_lockout_markers_win_all_bulk_classifiers(tmp_path: Path, marker: str):
    combined = marker + ": authentication failed"
    assert LOCAL_ENUM.classify_exec("", combined, False)[0] == "AUTH_LOCKOUT"
    assert WINDOWS_BULK._classify_ssh_result(
        255, combined, password_used=True)[0] == "AUTH_LOCKOUT"
    assert WINDOWS_BULK._classify_winrm(255, combined)[0] == "AUTH_LOCKOUT"
    assert _linux_status(tmp_path, combined) == "AUTH_LOCKOUT"


@pytest.mark.parametrize("message", [
    "Permission denied",
    "STATUS_LOGON_FAILURE",
    "Invalid credentials",
    "Too many authentication failures",
])
def test_non_lockout_auth_rejections_stay_auth_fail(tmp_path: Path, message: str):
    assert LOCAL_ENUM.classify_exec("", message, False)[0] == "AUTH_FAIL"
    assert WINDOWS_BULK._classify_ssh_result(
        255, message, password_used=True)[0] == "AUTH_FAIL"
    assert WINDOWS_BULK._classify_winrm(255, message)[0] == "AUTH_FAIL"
    assert _linux_status(tmp_path, message) == "AUTH_FAIL"


def test_lockout_marker_overrides_sshpass_incorrect_password_rc(tmp_path: Path):
    marker = "STATUS_ACCOUNT_LOCKED_OUT"
    assert WINDOWS_BULK._classify_ssh_result(
        5, marker, password_used=True)[0] == "AUTH_LOCKOUT"
    assert _linux_status(tmp_path, marker, rc=5) == "AUTH_LOCKOUT"


def test_windows_transport_fallthrough_stops_on_lockout(tmp_path: Path, monkeypatch):
    calls = []

    class LockedTransport:
        def run(self, target, script_text, args):
            calls.append("winrm")
            return WINDOWS_BULK.TransportResult(
                1, "", "STATUS_ACCOUNT_LOCKED_OUT", "AUTH_LOCKOUT", "account locked out")

    class MustNotRunTransport:
        def run(self, target, script_text, args):
            calls.append("ssh")
            raise AssertionError("transport fallthrough continued after lockout")

    monkeypatch.setitem(WINDOWS_BULK.TRANSPORT_CLASSES, "winrm", LockedTransport)
    monkeypatch.setitem(WINDOWS_BULK.TRANSPORT_CLASSES, "ssh", MustNotRunTransport)
    target = WINDOWS_BULK.Target(
        user="svc-test", host="win-lockout.invalid", port=5985, raw_spec="win-lockout.invalid")
    args = SimpleNamespace(
        resume=False, dry_run=False, auth="ntlm", tls=False, script="synthetic.ps1",
        invocation={}, domain="", nxc_extra_arg=[],
    )
    result = WINDOWS_BULK.run_one_host(
        target, "Write-Output synthetic", args, tmp_path, ["winrm", "ssh"])
    assert result.status == "AUTH_LOCKOUT"
    assert calls == ["winrm"]


def test_status_to_outcome_mapping_and_skipped_omission(tmp_path: Path):
    cases = [
        ("192.0.2.1", "OK", "success"),
        ("192.0.2.2", "AUTH_LOCKOUT", "lockout"),
        ("192.0.2.3", "AUTH_FAIL", "failure"),
        ("192.0.2.4", "UNREACHABLE", "error"),
        ("192.0.2.5", "TIMEOUT", "error"),
        ("192.0.2.6", "HOST_TIMEOUT", "error"),
        ("192.0.2.7", "REMOTE_ERR", "error"),
        ("192.0.2.8", "DEP_MISSING", "error"),
        ("192.0.2.9", "COLLECTOR_ERR", "error"),
        ("192.0.2.10", "SKIPPED", None),
    ]
    for host, status, _outcome in cases:
        _write_host(tmp_path, host, status)

    actual = {item["host"]: item["outcome"] for item in REPORT._auth_outcomes(tmp_path)}
    assert actual == {host: outcome for host, _status, outcome in cases if outcome is not None}


def test_fx5_yields_exact_reuse_records_and_contexts():
    actual = REPORT._auth_outcomes(FX5)
    assert [(item["host"], item["transport"], item["outcome"])
            for item in actual] == [
        ("10.0.0.1", "exec", "success"),
        ("10.0.0.2", "exec", "success"),
        ("10.0.0.3", "exec", "lockout"),
        ("10.0.0.4", "winrm", "success"),
    ]
    for item in actual[:3]:
        assert item["auth_context"]["scope"] == "local"
        assert item["auth_context"]["account_label"] == "svc-local"
        assert item["auth_context"]["domain"] is None
        assert item["auth_context"]["local_host"] == item["host"]
    domain_context = actual[3]["auth_context"]
    assert domain_context["scope"] == "domain"
    assert domain_context["account_label"] == "dom-user"
    assert domain_context["domain"] == "CORP.LOCAL"
    assert domain_context["local_host"] is None


def test_no_credential_attempts_are_recorded_not_dropped(tmp_path: Path):
    _write_host(tmp_path, "198.51.100.1", "OK", account="", transport="ssh",
                scope="local", credential_kind="none")
    _write_host(tmp_path, "198.51.100.2", "AUTH_FAIL", account="", transport="smb",
                scope="local", credential_kind="none")
    actual = {item["host"]: item["outcome"] for item in REPORT._auth_outcomes(tmp_path)}
    assert actual == {"198.51.100.1": "anonymous", "198.51.100.2": "null-session"}


def test_malformed_metadata_is_skipped_without_fabrication(tmp_path: Path):
    hdir = tmp_path / "203.0.113.5"
    hdir.mkdir()
    (hdir / "_meta.json").write_text("{not-json", encoding="utf-8")
    (hdir / "winenum.txt").write_text("synthetic\n", encoding="utf-8")
    assert REPORT._auth_outcomes(tmp_path) == []


def test_no_bulk_tree_yields_empty_auth_outcomes(tmp_path: Path):
    (tmp_path / "inventory.json").write_text("{}", encoding="utf-8")
    assert REPORT._auth_outcomes(tmp_path) == []


def test_report_redacts_auth_outcome_host_and_embedded_context(tmp_path: Path):
    _write_host(tmp_path, "203.0.113.7", "OK", account="dom-user", transport="winrm",
                scope="domain", domain="CORP.INVALID")
    proc = subprocess.run(
        [sys.executable, str(REPORT_PATH), str(tmp_path), "--findings-only", "--redact"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    item = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))["auth_outcomes"][0]
    serialized = json.dumps(item)
    for secret in ("203.0.113.7", "dom-user", "CORP.INVALID"):
        assert secret not in serialized
    assert item["host"].startswith("<TARGET-")
    assert item["auth_context"]["account_label"].startswith("<TARGET-")
    assert item["auth_context"]["domain"].startswith("<TARGET-")
    assert item["auth_context"]["local_host"] is None
    assert item["auth_context"]["invocation"]["domain_arg"] == item["auth_context"]["domain"]
