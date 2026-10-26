#!/usr/bin/env python3
"""test_host_posture.py — PLAN-001 S3: host-posture collectors + posture model.

Covers, per the S3 test plan:
  * the Linux collector run for real on this host and against hermetic
    ARANUM_POSTURE_ROOT fixtures (sshd_config + Include, login.defs, sysctls,
    passwd/shadow, mounts);
  * the Windows collector under pwsh: off-Windows NA for every id, the AD
    helper functions against fixture inputs, the -AdChecks consent gate (no
    LDAP/ADSI call without it), mocked host checks, and 7-only syntax absence;
  * the report.py posture parser and domain lattice (D3.3);
  * GATE 1 posture-KB coverage (every collector id has KB test+fix) and
    GATE 2 strict-parser field-injection rejection (split cap).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
LIN = REPO / "standalones" / "linux" / "host-posture.sh"
WINPS = REPO / "standalones" / "windows" / "Invoke-HostPosture.ps1"
NET = REPO / "aranumtoolkit" / "network"
KB_PATH = NET / "finding-kb.json"
PWSH = shutil.which("pwsh")
ANCHOR = re.compile(r"^POSTURE\|[A-Z0-9-]+\|(PASS|FAIL|WARN|INFO|NA|ERR)\|")
# The quoted-literal / _p_emit extraction the M7 harness (v2) uses.
ID_QUOTED = re.compile(r"['\"]((?:LIN|WIN|AD)-[A-Z0-9][A-Z0-9-]*)['\"]")
ID_EMIT = re.compile(r"_p_emit\s+['\"]?((?:LIN|AD)-[A-Z0-9][A-Z0-9-]*)")


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_posture", NET / "report.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["report_mod_posture"] = mod
    spec.loader.exec_module(mod)
    mod._FINDING_KB_CACHE = None
    mod._FINDING_KB_CACHE_PATH = None
    os.environ.pop("ARANUM_FINDING_KB", None)
    return mod


RPT = _load_report()
KB_CHECKS = json.loads(KB_PATH.read_text())["checks"]


def _posture_lines(text: str) -> "list[tuple[str, str, str]]":
    out = []
    for line in text.splitlines():
        if line.startswith("POSTURE|"):
            assert ANCHOR.match(line), f"collector emitted a line failing the anchor: {line!r}"
            _, cid, st, detail = line.split("|", 3)
            out.append((cid, st, detail))
    return out


# ============================================================ Linux collector
def _run_lin(root: "Path | None" = None):
    env = dict(os.environ)
    if root is not None:
        env["ARANUM_POSTURE_ROOT"] = str(root)
    return subprocess.run(["bash", str(LIN)], capture_output=True, text=True,
                          timeout=120, env=env, stdin=subprocess.DEVNULL)


# A non-root user legitimately cannot evaluate these; ERR is the honest answer.
_NONROOT_ERR_OK = {"LIN-ACCT-EMPTYPW", "LIN-ACCT-NOPASSWD", "LIN-FIREWALL",
                   "LIN-SSH-HOSTKEY-PERMS", "LIN-AD-KEYTAB", "LIN-BOOT-SECUREBOOT"}


def test_linux_collector_real_run():
    proc = _run_lin()
    assert proc.returncode == 0, proc.stderr
    lines = _posture_lines(proc.stdout)
    ids = [c for c, _, _ in lines]
    assert len(lines) >= 30
    assert len(ids) == len(set(ids)), "duplicate check id emitted"
    unknown = [c for c in ids if c not in KB_CHECKS]
    assert not unknown, f"ids unknown to the KB: {unknown}"
    lin_kb = {c for c, v in KB_CHECKS.items() if v["os"] == "linux"}
    assert set(ids) == lin_kb, "every Linux KB check must be emitted exactly once"
    errs = {c for c, st, _ in lines if st == "ERR"}
    if os.geteuid() == 0:
        assert not errs, f"ERR as root: {errs}"
    else:
        assert errs <= _NONROOT_ERR_OK, f"ERR a non-root run could have satisfied: {errs - _NONROOT_ERR_OK}"


@pytest.fixture
def lin_root(tmp_path):
    r = tmp_path / "root"
    (r / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (r / "etc/ssh/sshd_config").write_text(
        "Include /etc/ssh/sshd_config.d/*.conf\n"
        "PermitRootLogin=yes\n"            # Keyword=value form
        "PasswordAuthentication no\n"
        "PermitEmptyPasswords yes\n"
        "Match User bob\n"
        "  PasswordAuthentication yes\n")  # inside Match: must be ignored
    # Included first, so first-value-wins makes these effective.
    (r / "etc/ssh/sshd_config.d/10-x.conf").write_text(
        "X11Forwarding no\nCiphers aes256-cbc,aes256-gcm@openssh.com\nMaxAuthTries 3\n")
    (r / "etc/login.defs").write_text("PASS_MAX_DAYS 90\nUMASK 027\n")
    for rel, val in (("kernel/yama/ptrace_scope", "0"), ("kernel/randomize_va_space", "2"),
                     ("fs/suid_dumpable", "0"), ("net/ipv4/ip_forward", "1")):
        p = r / "proc/sys" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(val + "\n")
    (r / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n"
                                  "alice:x:1000:1000::/home/alice:/bin/bash\n")
    (r / "etc/passwd").chmod(0o644)
    (r / "etc/shadow").write_text("root:$6$x:1::::::\nalice::1::::::\n")
    (r / "etc/shadow").chmod(0o640)
    (r / "proc/mounts").write_text("tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
                                   "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n")
    return r


def test_linux_collector_hermetic_specific_results(lin_root):
    proc = _run_lin(lin_root)
    assert proc.returncode == 0, proc.stderr
    got = {c: (st, d) for c, st, d in _posture_lines(proc.stdout)}
    assert got["LIN-SSH-ROOTLOGIN"] == ("FAIL", "PermitRootLogin yes (sshd_config)")
    assert got["LIN-SSH-PASSAUTH"][0] == "PASS"         # Match-block override ignored
    assert got["LIN-SSH-EMPTYPW"][0] == "FAIL"
    assert got["LIN-SSH-X11"] == ("PASS", "X11Forwarding no (sshd_config)")  # from Include
    assert got["LIN-SSH-MAXAUTH"][0] == "PASS"
    assert got["LIN-SSH-CIPHERS"][0] == "WARN" and "aes256-cbc" in got["LIN-SSH-CIPHERS"][1]
    assert got["LIN-ACCT-UMASK"][0] == "PASS" and got["LIN-ACCT-AGING"][0] == "PASS"
    assert got["LIN-SYSCTL-PTRACE"] == ("WARN", "kernel.yama.ptrace_scope=0")
    assert got["LIN-SYSCTL-ASLR"][0] == "PASS"
    assert got["LIN-SYSCTL-IPFWD"][0] == "WARN"
    assert got["LIN-ACCT-UID0"] == ("FAIL", "uid 0: toor")
    assert got["LIN-ACCT-EMPTYPW"] == ("FAIL", "empty password: alice")
    assert got["LIN-FILE-SHADOW"][0] == "PASS"
    assert got["LIN-MNT-TMP"][0] == "PASS"
    assert got["LIN-MNT-SHM"] == ("WARN", "/dev/shm missing: noexec")
    # Hermetic mode runs no live commands: package state is NA, not guessed.
    assert got["LIN-PKG-SECUPDATES"][0] == "NA"


def test_linux_collector_flattens_pipes_in_detail(lin_root):
    # An attacker-influenced value containing | must not add a field.
    (lin_root / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\nev|il:x:0:0::/:/bin/sh\n")
    got = {c: (st, d) for c, st, d in _posture_lines(_run_lin(lin_root).stdout)}
    assert got["LIN-ACCT-UID0"] == ("FAIL", "uid 0: ev il")


def test_linux_collector_survives_concatenation_and_stdin():
    # D3.4 delivery: appended after another script on one stdin stream, the
    # posture body must run and must not consume the remaining stream.
    payload = "echo before\n" + LIN.read_text() + "\necho after-posture\n"
    proc = subprocess.run(["bash", "-s"], input=payload, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0
    assert proc.stdout.startswith("before\n")
    assert proc.stdout.rstrip().endswith("after-posture")
    assert len(_posture_lines(proc.stdout)) >= 30


# ============================================================ Windows collector
def _pwsh_file(tmp_path: Path, body: str, *args: str):
    if not PWSH:
        pytest.skip("pwsh unavailable")
    script = tmp_path / "t.ps1"
    script.write_text(body)
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script), *args],
                          capture_output=True, text=True, timeout=120)


def _lib(body: str) -> str:
    return f". '{WINPS}' -LibraryOnly\n{body}\n"


def test_windows_collector_off_windows_is_all_na(tmp_path):
    for extra in ((), ("-AdChecks",)):
        if not PWSH:
            pytest.skip("pwsh unavailable")
        proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(WINPS), *extra],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        lines = _posture_lines(proc.stdout)
        win_kb = {c for c, v in KB_CHECKS.items() if v["os"] == "windows"}
        assert {c for c, _, _ in lines} == win_kb
        assert len(lines) == len(win_kb) == 56
        assert all(st == "NA" and d == "not windows" for _, st, d in lines)


def test_windows_ad_helpers_against_fixtures(tmp_path):
    body = _lib(r"""
$r = [ordered]@{}
$enabledSvc  = @{ samaccountname='svc_sql'; useraccountcontrol=512; serviceprincipalname=@('MSSQLSvc/db:1433'); objectclass=@('top','person','user') }
$disabledSvc = @{ samaccountname='svc_old'; useraccountcontrol=514; serviceprincipalname=@('HTTP/old'); objectclass=@('user') }
$computer    = @{ samaccountname='WS01$'; useraccountcontrol=4096; serviceprincipalname=@('HOST/ws01'); objectclass=@('user','computer') }
$krbtgt      = @{ samaccountname='krbtgt'; useraccountcontrol=514; serviceprincipalname=@('kadmin/changepw'); objectclass=@('user') }
$noSpn       = @{ samaccountname='bob'; useraccountcontrol=512; objectclass=@('user') }
$r.roast = @(@($enabledSvc,$disabledSvc,$computer,$krbtgt,$noSpn) | Where-Object { Test-RoastableUser $_ } | ForEach-Object { $_.samaccountname })
$r.asrep = @(@(@{useraccountcontrol=(512 + 0x400000)}, @{useraccountcontrol=(514 + 0x400000)}, @{useraccountcontrol=512}) | Where-Object { Test-AsRepUser $_ }).Count
$dc  = @{ samaccountname='DC01$'; useraccountcontrol=(0x2000 + 0x80000) }
$srv = @{ samaccountname='APP01$'; useraccountcontrol=(0x1000 + 0x80000) }
$off = @{ samaccountname='OLD01$'; useraccountcontrol=(0x1000 + 0x80000 + 2) }
$r.unconstrained = @(@($dc,$srv,$off) | Where-Object { Test-UnconstrainedNonDc $_ } | ForEach-Object { $_.samaccountname })
$r.distinct = Measure-DistinctMember @(@{distinguishedname='CN=A,DC=corp'}, @{distinguishedname='cn=a,dc=corp'}, @{distinguishedname='CN=B,DC=corp'})
# Signed LowPart (IADsLargeInteger shape): high=0x01D00000, low=-1 => 0x01D00000FFFFFFFF
$li = [pscustomobject]@{ HighPart = 30408704; LowPart = -1 }
$r.large = ConvertFrom-LargeInteger $li
$now = [datetime]::new(2026,10,25,0,0,0,[DateTimeKind]::Utc)
$r.age = Get-FileTimeAgeDays ($now.AddDays(-400).ToFileTimeUtc()) -Now $now
$r.ageNever = (Get-FileTimeAgeDays 0 -Now $now) -eq $null
$r.ldapNull = (Resolve-LdapSigningStatus $null $null).AranumPostureStatus
$r.ldap1 = (Resolve-LdapSigningStatus 1 0).AranumPostureStatus
$r.ldap2 = (Resolve-LdapSigningStatus 2 2).AranumPostureStatus
$r.dns = ConvertTo-DnsDomain 'DC=Corp,DC=Example,DC=Local'
$r | ConvertTo-Json -Compress
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    r = json.loads(proc.stdout.strip().splitlines()[-1])
    assert r["roast"] == ["svc_sql"]                 # disabled/computer/krbtgt/no-SPN excluded
    assert r["asrep"] == 1                           # disabled AS-REP account excluded
    assert r["unconstrained"] == ["APP01$"]          # DC and disabled excluded
    assert r["distinct"] == 2                        # same DN (case-insensitive) counted once
    assert r["large"] == 0x01D00000FFFFFFFF
    assert r["age"] == 400 and r["ageNever"] is True
    assert (r["ldapNull"], r["ldap1"], r["ldap2"]) == ("NA", "FAIL", "PASS")
    assert r["dns"] == "corp.example.local"


def test_windows_ad_checks_consent_gate_issues_no_ldap(tmp_path):
    body = _lib(r"""
$script:calls = 0
function Invoke-LdapSearch { $script:calls++; throw 'LDAP must not be called' }
function Get-RootDse { $script:calls++; throw 'RootDSE must not be called' }
$ctx = @{ ComputerName='WS01'; PartOfDomain=$true; Domain='corp.local'; IsDC=$false; Build=19045 }
Invoke-AdPostureChecks -Context $ctx
"CALLS=$script:calls"
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    lines = _posture_lines(proc.stdout)
    ad_kb = {c for c, v in KB_CHECKS.items() if v["scope"] == "domain"}
    assert {c for c, _, _ in lines} == ad_kb and len(lines) == 15
    assert all(st == "NA" and d == "ad checks not requested" for _, st, d in lines)
    assert "CALLS=0" in proc.stdout


def test_windows_ad_checks_enabled_with_fixture_directory(tmp_path):
    body = _lib(r"""
function Get-RootDse { @{ defaultNamingContext='DC=corp,DC=local'; schemaNamingContext='CN=Schema,CN=Configuration,DC=corp,DC=local'; dnsHostName='dc01.corp.local'; domainFunctionality=6; forestFunctionality=6 } }
function Invoke-LdapSearch {
  param([string]$SearchRoot, [string]$Filter, [string[]]$Properties, [string]$Scope = 'Subtree', [int]$TimeoutSeconds = 30)
  if ($Filter -eq '(objectClass=domainDNS)') { return @{ minpwdlength=7; lockoutthreshold=0; maxpwdage=[long]-36288000000000; 'ms-ds-machineaccountquota'=10; objectsid=$null } }
  if ($Filter -like '*sAMAccountName=krbtgt*') { return @{ pwdlastset=[datetime]::UtcNow.AddDays(-500).ToFileTimeUtc() } }
  if ($Filter -like '*servicePrincipalName=*') {
    @{ samaccountname='svc_sql'; useraccountcontrol=512; serviceprincipalname=@('MSSQLSvc/db'); objectclass=@('user') }
    @{ samaccountname='svc_off'; useraccountcontrol=514; serviceprincipalname=@('HTTP/x'); objectclass=@('user') }
    return }
  return @()
}
$ctx = @{ ComputerName='WS01'; PartOfDomain=$true; Domain='corp.local'; IsDC=$false; Build=19045 }
Invoke-AdPostureChecks -Enabled -Context $ctx
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    got = {c: (st, d) for c, st, d in _posture_lines(proc.stdout)}
    assert len(got) == 15
    # Every determined AD line carries the domain/observer tag the parser keys on.
    assert all(d.startswith("domain=corp.local observer=ws01 ") for st, d in got.values())
    assert got["AD-PWPOL-MINLEN"][0] == "FAIL" and got["AD-PWPOL-LOCKOUT"][0] == "FAIL"
    assert got["AD-MAQ"][0] == "WARN" and got["AD-KRBTGT-AGE"][0] == "FAIL"
    assert got["AD-KERBEROASTABLE"][0] == "FAIL" and "count=1 sample=svc_sql" in got["AD-KERBEROASTABLE"][1]
    assert got["AD-FUNC-LEVEL"][0] == "WARN"
    assert got["AD-LDAP-SIGNING"][0] == "NA"         # not a DC: never a false PASS
    assert got["AD-DA-MEMBERS"][0] == "ERR"          # domain SID unreadable in fixture


def test_windows_host_checks_mocked_registry(tmp_path):
    body = _lib(r"""
$script:Reg = @{
 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential' = 1
 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature' = 0
 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections' = 0
 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication' = 0
 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel' = 5
}
function Get-RegValue { param([string]$Path,[string]$Name) $k = $Path + '|' + $Name; if ($script:Reg.ContainsKey($k)) { return $script:Reg[$k] }; return $null }
function Get-Service { param([string]$Name) [pscustomobject]@{ Name=$Name; Status='Stopped' } }
function Get-HotFix { @([pscustomobject]@{ InstalledOn = (Get-Date).AddDays(-3) }) }
function Get-CimInstance { param($ClassName,$Namespace,$Filter) throw 'no cim' }
function Get-ItemProperty { param($LiteralPath,$Name,$ErrorAction) [pscustomobject]@{ AutoAdminLogon='1'; DefaultPassword='S3cretValue!' } }
$ctx = @{ ComputerName='WS01'; PartOfDomain=$false; Domain='WORKGROUP'; IsDC=$false; Build=19045; Caption='Windows 10'; ProductType=1 }
Invoke-HostPostureChecks -Context $ctx
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    got = {c: (st, d) for c, st, d in _posture_lines(proc.stdout)}
    assert len(got) == 41 and all(c.startswith("WIN-") for c in got)
    assert got["WIN-CRED-WDIGEST"] == ("FAIL", "UseLogonCredential=1")
    assert got["WIN-SMB-SRVSIGN"][0] == "FAIL"
    assert got["WIN-RDP-NLA"][0] == "FAIL"
    assert got["WIN-CRED-LMCOMPAT"] == ("PASS", "LmCompatibilityLevel=5")
    assert got["WIN-PATCH-AGE"][0] == "PASS"
    assert got["WIN-CRED-CACHEDLOGONS"][0] == "NA"   # workgroup
    assert got["WIN-AUTOLOGON"] == ("FAIL", "Winlogon DefaultPassword present (value not shown)")
    assert "S3cretValue" not in proc.stdout          # the secret is never printed
    # A provider failure is ERR, never a silent PASS.
    assert got["WIN-CRED-CREDGUARD"][0] == "ERR"


def test_windows_collector_has_no_ps7_only_syntax(tmp_path):
    body = r"""
$path = $args[0]
$bytes = [System.IO.File]::ReadAllBytes($path)
foreach ($enc in @([System.Text.Encoding]::UTF8, [System.Text.Encoding]::GetEncoding(1252))) {
  $tok = $null; $err = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($enc.GetString($bytes), [ref]$tok, [ref]$err)
  "PARSE_ERRORS=$($err.Count)"
}
$n = @($ast.FindAll({ param($x) $x.GetType().Name -in @('TernaryExpressionAst','PipelineChainAst') }, $true)).Count
$t = @($tok | Where-Object { $_.Kind -in @('QuestionQuestion','QuestionDot','QuestionLBracket','AndAnd','OrOr','QuestionQuestionEquals') }).Count
"PS7_NODES=$n PS7_TOKENS=$t"
"""
    proc = _pwsh_file(tmp_path, body, str(WINPS))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.count("PARSE_ERRORS=0") == 2
    assert "PS7_NODES=0 PS7_TOKENS=0" in proc.stdout
    assert all(b < 0x80 for b in WINPS.read_bytes()), "collector must be pure ASCII"


# ============================================================ report.py parser / model
def _bulk_tree(tmp_path: Path, hosts: "dict[str, tuple[str, str]]") -> Path:
    """hosts: dirname -> (ip, winenum|linenum file content)."""
    out = tmp_path / "out"
    for name, (ip, text) in hosts.items():
        d = out / name
        d.mkdir(parents=True)
        (d / "_meta.json").write_text(json.dumps({"host": ip, "port": 22, "status": "OK"}))
        fname = "linenum.txt" if name.startswith("lin") else "winenum.txt"
        (d / fname).write_text(text)
    return out


def _collect(out: Path):
    diags: list = []
    rules = RPT._compose_rules(RPT._load_rules(None), RPT._AD_DEPTH_RULES)
    return RPT.collect(out, rules, diagnostics=diags), diags


def _posture_findings(col):
    return [f for f in col.findings if f["service"] == "posture"]


def test_parser_fail_is_finding_pass_is_posture_only(tmp_path):
    out = _bulk_tree(tmp_path, {"lin1": ("10.0.0.21",
        "POSTURE|LIN-SSH-ROOTLOGIN|FAIL|PermitRootLogin yes (sshd_config)\n"
        "POSTURE|LIN-SYSCTL-ASLR|PASS|kernel.randomize_va_space=2\n"
        "POSTURE|LIN-ACCT-NOPASSWD|WARN|NOPASSWD rules: 2\n")})
    col, diags = _collect(out)
    pf = {f["rule_id"]: f for f in _posture_findings(col)}
    assert set(pf) == {"LIN-SSH-ROOTLOGIN", "LIN-ACCT-NOPASSWD"}
    f = pf["LIN-SSH-ROOTLOGIN"]
    assert f["severity"] == KB_CHECKS["LIN-SSH-ROOTLOGIN"]["sev_fail"]
    assert (f["kb_match"], f["category"], f["scope"]) == ("rule", "linlocal", "host")
    assert f["posture_status"] == "FAIL" and f["host"] == "10.0.0.21"
    assert pf["LIN-ACCT-NOPASSWD"]["severity"] == KB_CHECKS["LIN-ACCT-NOPASSWD"]["sev_warn"]
    # Posture lines bypass the regex rules: "NOPASSWD" would otherwise be graded
    # by a linenum rule and double count.
    assert not [x for x in col.findings if x["service"] == "linenum"]
    rec = col.posture["hosts"]["10.0.0.21"]["checks"]
    assert rec["LIN-SYSCTL-ASLR"] == {"status": "PASS", "detail": "kernel.randomize_va_space=2"}
    assert col.per_host["10.0.0.21"]["os"] == "linux"
    assert col.per_host["10.0.0.21"]["verdict"] == KB_CHECKS["LIN-SSH-ROOTLOGIN"]["sev_fail"]
    assert not diags


def test_parser_quarantines_malformed_unknown_duplicate_untagged(tmp_path):
    out = _bulk_tree(tmp_path, {"win1": ("10.0.0.31",
        "POSTURE|WIN-SMB-SRVSIGN|FAIL|RequireSecuritySignature=0\n"
        "POSTURE|win-lower|FAIL|x\n"
        "POSTURE|WIN-SMB-SRVSIGN|PASS|again\n"
        "POSTURE|WIN-NOT-A-CHECK|FAIL|x\n"
        "POSTURE|WIN-NR-LLMNR|MAYBE|x\n"
        "POSTURE|AD-ASREP|FAIL|count=3 (no domain tag)\n")})
    col, diags = _collect(out)
    q = [d for d in diags if d["type"] == "posture_quarantine"]
    assert len(q) == 5 and len(diags) == 5
    reasons = " ".join(d["error"] for d in q)
    for frag in ("malformed", "duplicate", "unknown posture check id WIN-NOT-A-CHECK",
                 "without a domain= tag"):
        assert frag in reasons
    pf = _posture_findings(col)
    assert [f["rule_id"] for f in pf] == ["WIN-SMB-SRVSIGN"]   # quarantined lines never findings
    assert col.posture["hosts"]["10.0.0.31"]["checks"]["WIN-SMB-SRVSIGN"]["status"] == "FAIL"


def test_quarantine_does_not_mark_report_partial(tmp_path):
    out = _bulk_tree(tmp_path, {"lin1": ("10.0.0.21", "POSTURE|LIN-BOGUS|FAIL|x\n"
                                         "POSTURE|LIN-SSH-X11|WARN|X11Forwarding yes\n")})
    proc = subprocess.run([sys.executable, str(NET / "report.py"), str(out), "--findings-only"],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    fj = json.loads((out / "findings.json").read_text())
    assert "partial" not in fj and fj["posture_quarantine"][0]["error"].startswith("unknown")
    pj = json.loads((out / "posture.json").read_text())
    assert pj["hosts"]["10.0.0.21"]["checks"]["LIN-SSH-X11"]["status"] == "WARN"
    assert fj["summary"]["posture"]["hosts"] == 1 and fj["summary"]["posture"]["warn"] == 1


def _dom(host_status: "list[tuple[str, str]]", check="AD-PWPOL-MINLEN"):
    hosts = {}
    for i, (ip, st) in enumerate(host_status):
        hosts[f"win{i}"] = (ip, f"POSTURE|{check}|{st}|domain=corp.local observer=h{i} minPwdLength=x\n")
    return hosts


def test_domain_check_from_two_hosts_is_one_canonical_finding(tmp_path):
    col, _ = _collect(_bulk_tree(tmp_path, _dom([("10.0.0.31", "FAIL"), ("10.0.0.32", "FAIL")])))
    pf = _posture_findings(col)
    assert len(pf) == 1
    f = pf[0]
    assert (f["host"], f["scope"], f["posture_scope"]) == ("corp.local", "domain", "domain")
    assert [o["host"] for o in f["observed_from"]] == ["10.0.0.31", "10.0.0.32"]
    assert all(set(o) == {"host", "status", "detail"} for o in f["observed_from"])
    assert len(f["evidence_paths"]) == 2
    # Domain findings never count toward a host's verdict or the host list.
    assert not col.per_host
    assert "corp.local" not in RPT._summary(col.findings)["hosts"]


@pytest.mark.parametrize("statuses,expect,conflict", [
    (("PASS", "ERR"), "PASS", False),     # determined beats undetermined
    (("PASS", "FAIL"), "FAIL", True),     # worst determined + conflict note
    (("ERR", "NA"), "ERR", False),        # nothing determined, an observer errored
    (("NA", "NA"), "NA", False),
    (("INFO", "NA"), "INFO", False),      # INFO is determined (least severe)
    (("WARN", "PASS", "INFO"), "WARN", True),
])
def test_domain_status_lattice(tmp_path, statuses, expect, conflict):
    hs = [(f"10.0.0.{40 + i}", st) for i, st in enumerate(statuses)]
    col, _ = _collect(_bulk_tree(tmp_path, _dom(hs)))
    rec = col.domains["corp.local"]["checks"]["AD-PWPOL-MINLEN"]
    assert rec["status"] == expect
    assert [(o["host"], o["status"]) for o in rec["observed_from"]] == hs   # every observer kept
    assert rec["detail"].startswith("conflict: ") is conflict
    if conflict:
        assert "10.0.0.40=" + statuses[0] in rec["detail"]
    n = len(_posture_findings(col))
    assert n == (1 if expect in ("FAIL", "WARN") else 0)


def test_redact_scrubs_posture_json(tmp_path):
    hosts = _dom([("10.0.0.31", "FAIL"), ("10.0.0.32", "PASS")])
    hosts["lin9"] = ("10.0.0.99", "POSTURE|LIN-SYSCTL-ASLR|PASS|seen from 10.0.0.99\n")
    out = _bulk_tree(tmp_path, hosts)
    proc = subprocess.run([sys.executable, str(NET / "report.py"), str(out), "--findings-only", "--redact"],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    for name in ("posture.json", "findings.json"):
        text = (out / name).read_text()
        assert "10.0.0." not in text and "corp.local" not in text, name
    assert json.loads((out / "posture.json").read_text())["redacted"] is True


# ============================================================ GATE 1 — posture-KB coverage
def _collector_ids(text: str) -> "set[str]":
    return set(ID_QUOTED.findall(text)) | set(ID_EMIT.findall(text))


def _uncovered(ids: "set[str]", checks: dict) -> "list[str]":
    return sorted(i for i in ids if not (isinstance(checks.get(i), dict)
                                         and checks[i].get("test") and checks[i].get("fix")))


def test_gate_every_collector_id_has_kb_test_and_fix():
    lin = _collector_ids(LIN.read_text())
    win = _collector_ids(WINPS.read_text())
    # Anti-vacuous: the extraction must actually find the collectors' ids.
    assert len(lin) >= 30 and len(win) >= 35, (len(lin), len(win))
    assert _uncovered(lin | win, KB_CHECKS) == []
    # And the KB carries no check that no collector emits.
    assert set(KB_CHECKS) == lin | win
    assert all(KB_CHECKS[i]["scope"] == "domain" for i in win if i.startswith("AD-"))


def test_gate_coverage_goes_red_on_an_unknown_id(tmp_path):
    mutated = tmp_path / "host-posture.sh"
    mutated.write_text(LIN.read_text().replace(
        "_p_emit LIN-AD-JOINED", "_p_emit LIN-FAKE-CHECK PASS x\n    _p_emit LIN-AD-JOINED", 1))
    assert _uncovered(_collector_ids(mutated.read_text()), KB_CHECKS) == ["LIN-FAKE-CHECK"]


# ============================================================ GATE 2 — field injection
def test_gate_parser_keeps_injected_pipes_inside_detail(tmp_path):
    line = "POSTURE|LIN-SSH-ROOTLOGIN|PASS|a|FAIL|b"
    assert RPT._parse_posture_line(line) == ("LIN-SSH-ROOTLOGIN", "PASS", "a|FAIL|b")
    out = _bulk_tree(tmp_path, {"lin1": ("10.0.0.21", line + "\n")})
    col, diags = _collect(out)
    assert not _posture_findings(col) and not diags
    assert col.posture["hosts"]["10.0.0.21"]["checks"]["LIN-SSH-ROOTLOGIN"] == \
        {"status": "PASS", "detail": "a|FAIL|b"}
    # Anchor rejects an injected status/id shape outright.
    for bad in ("POSTURE|LIN-SSH-ROOTLOGIN|PASS", "POSTURE|LIN-SSH-ROOTLOGIN|FAIL x|y",
                "POSTURE|LIN-SSH|ROOTLOGIN|FAIL|y", " POSTURE|LIN-SSH-ROOTLOGIN|FAIL|y"):
        assert RPT._parse_posture_line(bad) is None, bad
