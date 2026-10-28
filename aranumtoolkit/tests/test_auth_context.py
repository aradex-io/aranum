"""PLAN-002 A3 auth-scope mapping, invocation carrier, and report stamping."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
NETWORK = REPO / "aranumtoolkit" / "network"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AUTH = _load("a3_auth_scope", NETWORK / "auth_scope.py")
REPORT = _load("a3_report", NETWORK / "report.py")
LOCAL = _load("a3_local_enum", NETWORK / "local-enum.py")


def test_family_for_registry_tool_lists():
    assert AUTH.family_for(["curl", "nxc", "impacket"]) == "nxc"
    assert AUTH.family_for(["wmiexec"]) == "impacket"
    assert AUTH.family_for(["ldapsearch"]) == "ldap"
    assert AUTH.family_for(["ssh"]) == "ssh"
    assert AUTH.family_for(["curl"]) == "other"


@pytest.mark.parametrize("scope", ["local", "domain", "machine"])
@pytest.mark.parametrize("family", ["nxc", "impacket", "ldap", "ssh"])
def test_declared_scope_family_mapping_and_context(scope, family):
    mapped = AUTH.apply(family, scope, domain="LAB.INVALID", user="alice",
                        host="host.invalid")
    expected = {
        ("nxc", "local"): (["--local-auth"], "alice", None, None, False),
        ("nxc", "domain"): (["-d", "LAB.INVALID"], "alice", None, None, False),
        ("nxc", "machine"): (["-d", "LAB.INVALID"], "alice$", None, None, False),
        ("impacket", "local"): ([], "alice", "host.invalid/alice", None, False),
        ("impacket", "domain"): ([], "alice", "LAB.INVALID/alice", None, False),
        ("impacket", "machine"): ([], "alice", "LAB.INVALID/alice$", None, False),
        ("ldap", "local"): ([], "alice", None, None, True),
        ("ldap", "domain"): ([], "alice", None, "alice@LAB.INVALID", False),
        ("ldap", "machine"): ([], "alice", None, "alice@LAB.INVALID", False),
        ("ssh", "local"): ([], "alice", None, None, False),
        ("ssh", "domain"): ([], "alice", None, None, False),
        ("ssh", "machine"): ([], "alice", None, None, False),
    }[(family, scope)]
    assert (mapped["extra_args"], mapped["username"], mapped["principal"],
            mapped["bind"], mapped["skip"]) == expected

    invocation = {"domain_arg": "LAB.INVALID", "local_auth_flag": scope == "local",
                  "username_form": "bare", "credential_kind": "password",
                  "auth_scope_declared": scope}
    context = REPORT._auth_context(invocation, account_label=mapped["username"],
                                   host="host.invalid", domain="LAB.INVALID",
                                   dispatcher="ldap" if family == "ldap" else family)
    assert context["scope"] == scope
    assert context["scope_basis"] == "declared"
    assert context["domain"] == ("LAB.INVALID" if scope in {"domain", "machine"} else None)
    assert context["local_host"] == ("host.invalid" if scope == "local" else None)


def _bash_nxc(scope: str, domain: str = "LAB.INVALID") -> list[str]:
    script = r'''
set -uo pipefail
SCRIPT_DIR="$1"
. "$SCRIPT_DIR/_lib.sh"
ENUM_USER=alice ENUM_PASS=pw ENUM_HASH="" ENUM_DOMAIN="$2" ENUM_AUTH_SCOPE="$3"
args=()
nxc_creds_array args
printf '%s\n' "${args[@]}"
'''
    proc = subprocess.run(["bash", "-c", script, "a3", str(NETWORK), domain, scope],
                          check=True, text=True, capture_output=True)
    return proc.stdout.splitlines()


def test_real_nxc_builder_local_domain_machine_and_no_inference():
    assert _bash_nxc("local") == ["-u", "alice", "-p", "pw", "--local-auth"]
    assert _bash_nxc("domain") == ["-u", "alice", "-p", "pw", "-d", "LAB.INVALID"]
    assert _bash_nxc("machine") == ["-u", "alice$", "-p", "pw", "-d", "LAB.INVALID"]
    assert _bash_nxc("", "WORKSTATION") == ["-u", "alice", "-p", "pw"]


def test_bare_domain_has_null_scope_and_no_nxc_domain_arg():
    assert _bash_nxc("", "WORKSTATION") == ["-u", "alice", "-p", "pw"]
    context = REPORT._auth_context(
        _invocation(domain="WORKSTATION"), account_label="alice",
        host="host.invalid", domain="WORKSTATION", dispatcher="smb")
    assert context["scope"] is None
    assert context["domain"] is None


def test_real_python_builders_use_table_without_shape_inference():
    cred = LOCAL.Cred(user="alice", password="pw", domain="LAB.INVALID")
    assert LOCAL._win_user(cred) == "alice"
    args = SimpleNamespace(auth_scope="machine", local_auth=False)
    assert LOCAL._win_user(cred, args) == "alice$"
    argv, _ = LOCAL.exec_argv("wmiexec.py", "wmiexec", "host.invalid", cred, "whoami",
                              "domain")
    assert "LAB.INVALID/alice:pw@host.invalid" in argv
    shaped = LOCAL.Cred(user=r"HOST\admin", password="pw", domain="WORKSTATION")
    argv, _ = LOCAL.exec_argv("wmiexec.py", "wmiexec", "host.invalid", shaped, "whoami")
    assert "HOST/admin:pw@host.invalid" in argv


@pytest.mark.parametrize(("scope", "expected_user", "expected_extra"), [
    ("local", "alice", "--nxc-extra-arg=--local-auth"),
    ("domain", "alice", "--nxc-extra-arg=-d"),
    ("machine", "alice$", "--nxc-extra-arg=-d"),
])
def test_windows_engine_forwards_mapped_nxc_values(tmp_path, monkeypatch, scope,
                                                   expected_user, expected_extra):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        target_path = Path(argv[argv.index("--targets") + 1])
        captured["target"] = target_path.read_text().strip()
        return 0, "", "", False

    monkeypatch.setattr(LOCAL, "run_bounded", fake_run)
    monkeypatch.setattr(LOCAL, "_collect_engine_dirs", lambda *a, **k: {})
    cred = LOCAL.Cred(user="alice", password="pw", domain="LAB.INVALID")
    plan = LOCAL.HostPlan(LOCAL.HostSpec(host="host.invalid", os="windows"), cred)
    args = SimpleNamespace(auth_scope=scope, local_auth=False, parallel=1,
                           connect_timeout=1, host_timeout=0, ad=False)
    LOCAL.run_windows_engine([plan], cred, ["winrm"], False, tmp_path, 1, args)
    assert captured["target"].startswith(f"{expected_user}@host.invalid")
    assert expected_extra in captured["argv"]
    if scope in {"domain", "machine"}:
        assert "--nxc-extra-arg=LAB.INVALID" in captured["argv"]


@pytest.mark.parametrize("entry", [
    [sys.executable, str(REPO / "aranum.py"), "local", "--self", "--dry-run",
     "--auth-scope", "domain"],
    [sys.executable, str(NETWORK / "local-enum.py"), "--self", "--dry-run", "-o"],
])
def test_domain_scope_without_domain_is_usage_error(tmp_path, entry):
    cmd = list(entry)
    if cmd[-1] == "-o":
        cmd += [str(tmp_path), "--auth-scope", "domain"]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    assert proc.returncode == 2
    assert "requires a non-empty -d/--domain" in proc.stderr


def _invocation(scope=None, *, domain="WORKSTATION", user_form="bare", kind="password",
                local=False):
    return {"domain_arg": domain, "local_auth_flag": local,
            "username_form": user_form, "credential_kind": kind,
            "auth_scope_declared": scope}


def test_domain_arg_and_username_shape_never_infer_scope():
    for host in ("one.invalid", "two.invalid"):
        context = REPORT._auth_context(
            _invocation(user_form="backslash"), account_label=r"HOST\admin",
            host=host, domain="WORKSTATION", dispatcher="smb")
        assert context["scope"] is None
        assert context["domain"] is None
        assert context["local_host"] == host
        assert context["scope_basis"] == "invoked"


def test_identity_tuple_cardinality_by_scope():
    domain_contexts = [REPORT._auth_context(
        _invocation("domain", domain="LAB.INVALID"), account_label="alice",
        host=f"h{i}.invalid", domain="LAB.INVALID", dispatcher="smb") for i in range(10)]
    local_contexts = [REPORT._auth_context(
        _invocation("local", domain=""), account_label="alice", host=f"h{i}.invalid",
        domain="", dispatcher="smb") for i in range(2)]
    identity = lambda c: (c["account_label"], c["scope"], c["domain"], c["local_host"])
    assert len({identity(c) for c in domain_contexts}) == 1
    assert len({identity(c) for c in local_contexts}) == 2


def test_credentialed_dispatcher_stamping_and_logical_user_slot(tmp_path):
    (tmp_path / "stages").mkdir()
    inv = _invocation("domain", domain="LAB.INVALID")
    (tmp_path / "stages" / "run.json").write_text(
        json.dumps({"invocation": inv, "account_label": "alice"}))
    finding = REPORT._structured_finding("host.invalid", "445", "smb", "high", "SMB signing disabled",
                                         "smb/host.invalid/x.txt", {"defaults": {}, "services": {}},
                                         "tcp", "rule-a")
    stamped = REPORT.finalize_findings(tmp_path, [finding])[0]
    assert stamped["auth_context"]["account_label"] == "alice"
    assert stamped["auth_context"]["scope"] == "domain"
    expected = REPORT._logical_finding_id("rule-a", stamped["evidence_identity"],
                                          "host.invalid", "445", "smb", "alice", "")
    assert stamped["logical_id"] == expected
    plain = REPORT._structured_finding("host.invalid", "80", "http", "high", "EXPOSED admin",
                                       "http/host.invalid/x.txt", {"defaults": {}, "services": {}},
                                       "tcp", "rule-b")
    plain = REPORT.finalize_findings(tmp_path, [plain])[0]
    assert plain["auth_context"] is None
    assert plain["logical_id"] == REPORT._logical_finding_id(
        "rule-b", plain["evidence_identity"], "host.invalid", "80", "http")


def test_ldap_local_scope_skips_auth_but_runs_anonymous_and_reports_coverage(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    calls = tmp_path / "ldap.calls"
    fake = tools / "ldapsearch"
    fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$LDAP_CALLS\"\nprintf 'anonymous-rootdse\\n'\n")
    fake.chmod(0o755)
    targets = tmp_path / "targets.txt"
    targets.write_text("dc.invalid:389\n")
    out = tmp_path / "out"
    service_out = out / "ldap"
    env = os.environ.copy()
    env.update({"PATH": f"{tools}:/usr/bin:/bin", "LDAP_CALLS": str(calls),
                "ENUM_USER": "alice", "ENUM_PASS": "pw", "ENUM_HASH": "",
                "ENUM_DOMAIN": "", "ENUM_AUTH_SCOPE": "local", "ENUM_DC_IP": "",
                "ENUM_PARALLEL": "1"})
    proc = subprocess.run(["bash", str(NETWORK / "enum-ldap.sh"), "--targets", str(targets),
                           "--output", str(service_out)], env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    assert "-D" not in calls.read_text()
    assert "anonymous-rootdse" in (service_out / "dc.invalid" / "ldap_rootDSE_anon_389.txt").read_text()
    skipped = json.loads((service_out / "dc.invalid" / "_skipped-checks.json").read_text())
    assert skipped and {item["reason"] for item in skipped} == {"scope-local-no-domain-bind"}
    inventory = {"entries": [{"ip": "dc.invalid", "port": "389", "proto": "tcp",
                               "categories": ["ldap"]}]}
    (out / "inventory.json").write_text(json.dumps(inventory))
    coverage = REPORT._coverage(out, [])
    assert coverage[0]["skipped_checks"] == skipped


def test_dry_run_carries_invocation_in_run_and_local_stages(tmp_path):
    scan = REPO / "aranumtoolkit" / "tests" / "fixtures" / "services" / "closed-and-filtered.xml"
    out = tmp_path / "result"
    common = ["-u", "x", "-d", "Y", "--auth-scope", "domain", "--dry-run"]
    run = subprocess.run(["bash", str(NETWORK / "auto-enum.sh"), "-i", str(scan),
                          "-o", str(out), *common], text=True, capture_output=True)
    assert run.returncode == 0, run.stderr
    targets = tmp_path / "targets.txt"
    targets.write_text("x@host.invalid os=windows via=winrm\n")
    local = subprocess.run([sys.executable, str(NETWORK / "local-enum.py"),
                            "--targets", str(targets), "-o", str(out), *common],
                           text=True, capture_output=True)
    assert local.returncode == 0, local.stderr
    for stage in ("run", "local"):
        invocation = json.loads((out / "stages" / f"{stage}.json").read_text())["invocation"]
        assert set(invocation) == {"domain_arg", "local_auth_flag", "username_form",
                                   "credential_kind", "auth_scope_declared"}
        assert invocation["domain_arg"] == "Y"
        assert invocation["auth_scope_declared"] == "domain"
        assert invocation["credential_kind"] == "none"
