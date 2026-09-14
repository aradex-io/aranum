"""Offline R2 Linux/Windows host predicate and OT scheduler regressions."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
APT = REPO / "standalones" / "linux" / "apt-source-check.sh"
WIN = REPO / "standalones" / "windows"
OT = REPO / "standalones" / "ot"
PWSH = shutil.which("pwsh")


def _run_apt(root: Path, *, apt_config: Path | None = None):
    env = dict(os.environ)
    env["ARANUM_APT_ROOT"] = str(root)
    if apt_config is None:
        env.pop("APT_CONFIG", None)
    else:
        env["APT_CONFIG"] = str(apt_config)
    return subprocess.run(["bash", str(APT)], capture_output=True, text=True,
                          timeout=15, env=env)


def _apt_tree(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "etc/apt/apt.conf.d").mkdir(parents=True)
    return root


def test_apt_writable_file_is_counted_without_clean_contradiction(tmp_path):
    root = _apt_tree(tmp_path)
    hit = root / "etc/apt/apt.conf.d/99-test"
    hit.write_text("APT::Update::Pre-Invoke {};")
    hit.chmod(0o666)
    proc = _run_apt(root)
    assert proc.returncode == 0
    assert "WRITABLE file:" in proc.stdout
    assert "No writable apt config" not in proc.stdout


def test_apt_config_alternate_path_is_counted(tmp_path):
    root = _apt_tree(tmp_path)
    cfg = tmp_path / "alternate.conf"; cfg.write_text("x"); cfg.chmod(0o600)
    proc = _run_apt(root, apt_config=cfg)
    assert "APT_CONFIG file WRITABLE" in proc.stdout
    assert "No writable apt config" not in proc.stdout


def test_apt_file_and_alternate_config_are_both_counted(tmp_path):
    root = _apt_tree(tmp_path)
    hit = root / "etc/apt/apt.conf.d/99-test"
    hit.write_text("APT::Update::Pre-Invoke {};"); hit.chmod(0o666)
    cfg = tmp_path / "alternate.conf"; cfg.write_text("x"); cfg.chmod(0o600)
    proc = _run_apt(root, apt_config=cfg)
    assert proc.returncode == 0
    assert "WRITABLE file:" in proc.stdout
    assert "APT_CONFIG file WRITABLE" in proc.stdout
    assert "No writable apt config" not in proc.stdout


def test_apt_no_writable_surface_emits_only_clean_conclusion(tmp_path):
    root = _apt_tree(tmp_path)
    proc = _run_apt(root)
    assert "WRITABLE" not in proc.stdout
    assert "No writable apt config" in proc.stdout


def _pwsh(script: str):
    if not PWSH:
        pytest.skip("pwsh unavailable")
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=20)


def test_windows_service_command_parser_and_loader_candidates():
    helper = WIN / "Get-UnquotedServices.ps1"
    command = (
        f". '{helper}' -LibraryOnly; "
        "$q=Get-ServiceExecutablePath '\"C:\\Program Files\\Vendor\\svc.exe\" -d'; "
        "$u=@(Get-UnquotedLoaderCandidates 'C:\\Program Files\\Foo Bar\\app.exe -s'); "
        "[pscustomobject]@{quoted=$q;candidates=$u} | ConvertTo-Json -Compress"
    )
    proc = _pwsh(command)
    assert proc.returncode == 0, proc.stderr
    assert '"quoted":"C:\\\\Program Files\\\\Vendor\\\\svc.exe"' in proc.stdout
    assert "C:\\\\Program.exe" in proc.stdout
    assert "C:\\\\Program Files\\\\Foo.exe" in proc.stdout


def test_windows_aggregate_uses_regex_credentials_and_interpolated_sysvol():
    aggregate = WIN / "Invoke-PrivEscEnum.ps1"
    source = aggregate.read_text()
    credential_line = next(line for line in source.splitlines() if "api[_-]?key" in line)
    assert "-SimpleMatch" not in credential_line
    proc = _pwsh(
        f". '{aggregate}' -LibraryOnly; "
        "Get-SysvolRoot -UserDnsDomain 'corp.example' -UserDomain 'CORP' -ComputerName 'WS1'; "
        "if ($null -eq (Get-SysvolRoot -UserDnsDomain '' -UserDomain 'WS1' -ComputerName 'WS1')) {'NONE'}"
    )
    assert proc.returncode == 0, proc.stderr
    assert "\\\\corp.example\\SYSVOL" in proc.stdout
    assert "NONE" in proc.stdout


def test_adcs_esc1_enrollment_predicate_requires_low_privilege_effective_allow():
    adcs = WIN / "Get-ADCSMisconfig.ps1"
    enroll = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    ps = f"""
. '{adcs}' -LibraryOnly
function Ace($id,$rights,$type,$obj) {{ [pscustomobject]@{{IdentityReference=$id;ActiveDirectoryRights=$rights;AccessControlType=$type;ObjectType=[Guid]$obj}} }}
$allow=[pscustomobject]@{{Access=@(Ace 'Authenticated Users' 'ExtendedRight' 'Allow' '{enroll}')}}
$admin=[pscustomobject]@{{Access=@(Ace 'BUILTIN\\Administrators' 'GenericAll' 'Allow' '00000000-0000-0000-0000-000000000000')}}
$denied=[pscustomobject]@{{Access=@(Ace 'Domain Users' 'ExtendedRight' 'Allow' '{enroll}', Ace 'Domain Users' 'ExtendedRight' 'Deny' '{enroll}')}}
"allow=$(Test-LowPrivilegeEnrollment $allow) admin=$(Test-LowPrivilegeEnrollment $admin) denied=$(Test-LowPrivilegeEnrollment $denied)"
"""
    proc = _pwsh(ps)
    assert proc.returncode == 0, proc.stderr
    assert "allow=True admin=False denied=False" in proc.stdout


def test_windows_docs_state_only_esc1_2_4_local_coverage():
    wiki = (REPO / "wiki/windows.md").read_text()
    assert "local ADSI coverage for ADCS ESC1, ESC2, and ESC4" in wiki
    assert "ADCS ESC1–ESC8 misconfigurations" not in wiki


def test_ot_scheduler_bounds_workers_and_uses_one_global_start_gate(tmp_path):
    if not shutil.which("flock"):
        pytest.skip("flock unavailable")
    targets = tmp_path / "targets"; targets.write_text("a\nb\nc\nd\n")
    current = tmp_path / "current"; current.write_text("0\n")
    maximum = tmp_path / "maximum"; maximum.write_text("0\n")
    rates = tmp_path / "rates"; lock = tmp_path / "lock"
    script = f"""
. '{OT / '_lib.sh'}'
export OT_MAX_PARALLEL=2
ot_throttle_sleep() {{ echo tick >> '{rates}'; }}
probe() {{
  {{ flock 9; c=$(cat '{current}'); c=$((c+1)); echo "$c" > '{current}'; m=$(cat '{maximum}'); [ "$c" -gt "$m" ] && echo "$c" > '{maximum}'; }} 9>'{lock}'
  /usr/bin/sleep 0.08
  {{ flock 9; c=$(cat '{current}'); echo $((c-1)) > '{current}'; }} 9>'{lock}'
}}
ot_run_targets '{targets}' probe
"""
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert int(maximum.read_text()) <= 2
    assert len(rates.read_text().splitlines()) == 3
    for dispatcher in OT.glob("enum-*.sh"):
        text = dispatcher.read_text()
        assert 'ot_run_targets "$TARGETS"' in text
        assert "ot_throttle_sleep" not in text


def test_ot_rate_gate_persists_across_dispatcher_processes(tmp_path):
    target = tmp_path / "one.target"; target.write_text("one\n")
    state = tmp_path / "global-rate.state"
    rate_log = tmp_path / "rate.log"
    command = f"""
. '{OT / '_lib.sh'}'
ot_throttle_sleep() {{ echo tick >> '{rate_log}'; }}
probe() {{ :; }}
ot_run_targets '{target}' probe
"""
    env = dict(os.environ)
    env["OT_RATE_STATE_FILE"] = str(state)
    for _ in range(2):
        proc = subprocess.run(["bash", "-c", command], capture_output=True, text=True,
                              timeout=10, env=env)
        assert proc.returncode == 0, proc.stdout + proc.stderr
    assert rate_log.read_text().splitlines() == ["tick"]
    orchestrator = (OT / "ot-enum.sh").read_text()
    assert 'OT_RATE_STATE_FILE="$OT_RATE_STATE_FILE"' in orchestrator


def test_ot_scheduler_without_flock_forces_serial_and_preserves_start_floor(tmp_path):
    targets = tmp_path / "targets"; targets.write_text("a\nb\nc\nd\n")
    starts = tmp_path / "starts"
    path_bin = tmp_path / "path-bin"; path_bin.mkdir()
    # Build a real PATH with the scheduler's portable dependencies but no flock.
    for command in ("awk", "date", "dirname", "mktemp", "rm", "sleep"):
        source = shutil.which(command)
        assert source, f"required test command missing: {command}"
        (path_bin / command).symlink_to(source)
    assert not (path_bin / "flock").exists()

    script = f"""
. '{OT / '_lib.sh'}'
export OT_MAX_PARALLEL=4
probe() {{
  {sys.executable!r} -c 'import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); p.open("a").write(str(time.monotonic_ns()) + "\\n")' '{starts}'
}}
ot_run_targets '{targets}' probe
"""
    env = dict(os.environ)
    env["PATH"] = str(path_bin)
    proc = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True,
                          timeout=10, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "forcing serial OT scheduling" in proc.stderr
    observed = [int(value) for value in starts.read_text().splitlines()]
    assert len(observed) == 4, "no authorized target may be skipped"
    intervals = [right - left for left, right in zip(observed, observed[1:])]
    assert all(interval >= 500_000_000 for interval in intervals), intervals
