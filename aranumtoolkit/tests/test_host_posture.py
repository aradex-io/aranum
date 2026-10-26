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


def test_windows_ldap_signing_grades_both_policies(tmp_path):
    # R2: signing required alone is not compliant -- channel binding is graded too, and
    # PASS needs both. An absent CBT value on a DC is "not enforced" (FAIL), not NA.
    body = _lib(r"""
foreach ($c in @(@($null,$null), @(2,$null), @(2,0), @(2,1), @(2,2), @(1,2), @(0,$null),
                 @(2,3), @(2,-1), @(3,2), @(-1,2))) {
  $r = Resolve-LdapSigningStatus $c[0] $c[1]
  'ROW|' + [string]$c[0] + '|' + [string]$c[1] + '|' + $r.AranumPostureStatus
}
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    rows = [ln.split("|")[1:] for ln in proc.stdout.splitlines() if ln.startswith("ROW|")]
    assert rows == [["", "", "NA"], ["2", "", "FAIL"], ["2", "0", "FAIL"], ["2", "1", "WARN"],
                    ["2", "2", "PASS"], ["1", "2", "FAIL"], ["0", "", "FAIL"],
                    # round 2: out-of-domain enum values are ERR, never a fall-through PASS
                    ["2", "3", "ERR"], ["2", "-1", "ERR"], ["3", "2", "ERR"], ["-1", "2", "ERR"]]


def test_windows_get_regvalue_separates_absent_from_error(tmp_path):
    # R4: absent key/value -> $null (documented default applies); any other read failure
    # throws so the check reports ERR instead of the absent-value default.
    body = _lib(r"""
function Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction)
  if ($LiteralPath -eq 'HKLM:\nokey') { throw (New-Object System.Management.Automation.ItemNotFoundException 'no key') }
  if ($LiteralPath -eq 'HKLM:\denied') { throw (New-Object System.UnauthorizedAccessException 'Requested registry access is not allowed.') }
  [pscustomobject]@{ Present = 0 } }
'MISSINGKEY=' + ($null -eq (Get-RegValue 'HKLM:\nokey' 'X'))
'MISSINGVAL=' + ($null -eq (Get-RegValue 'HKLM:\k' 'Absent'))
'PRESENT=' + (Get-RegValue 'HKLM:\k' 'Present')
try { Get-RegValue 'HKLM:\denied' 'X'; 'DENIED=returned' } catch { 'DENIED=threw' }
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    for want in ("MISSINGKEY=True", "MISSINGVAL=True", "PRESENT=0", "DENIED=threw"):
        assert want in proc.stdout, (want, proc.stdout)


def test_windows_registry_access_denied_never_grades_pass(tmp_path):
    # R4 end-to-end: every registry read is denied. No registry-backed check may PASS --
    # each one that used to default absent->PASS must now be ERR.
    body = _lib(r"""
function Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction)
  throw (New-Object System.UnauthorizedAccessException 'Requested registry access is not allowed.') }
function Get-Service { param([string]$Name) [pscustomobject]@{ Name=$Name; Status='Running' } }
function Get-HotFix { @([pscustomobject]@{ InstalledOn = (Get-Date).AddDays(-3) }) }
function Get-CimInstance { param($ClassName,$Namespace,$Filter) throw 'no cim' }
$ctx = @{ ComputerName='WS01'; PartOfDomain=$false; Domain='WORKGROUP'; IsDC=$false; Build=19045; Caption='Windows 10'; ProductType=1 }
Invoke-HostPostureChecks -Context $ctx
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    got = {c: (st, d) for c, st, d in _posture_lines(proc.stdout)}
    assert len(got) == 41
    for cid in ("WIN-SMB-V1", "WIN-PS-V2", "WIN-CRED-NOLMHASH", "WIN-UAC-LUA",
                "WIN-CRED-WDIGEST", "WIN-RDP-ENABLED", "WIN-AUTOLOGON"):
        assert got[cid][0] == "ERR", (cid, got[cid])
    passed = sorted(c for c, (st, _) in got.items() if st == "PASS")
    assert passed == ["WIN-PATCH-AGE"], passed     # the only non-registry PASS in this fixture


@pytest.mark.parametrize("val,want", [(7, "ERR"), (-1, "ERR"), (5, "PASS"), (4, "WARN"), (2, "FAIL")])
def test_windows_lmcompat_out_of_domain_is_err(tmp_path, val, want):
    # Round 2 sweep (enumerated policy, fall-through PASS): LmCompatibilityLevel is 0..5;
    # anything else is ERR, never graded as the PASS end of the scale.
    body = _lib(r"""
function Get-RegValue { param([string]$Path, [string]$Name)
  if ($Name -eq 'LmCompatibilityLevel') { return %d }
  return $null }
function Get-Service { param([string]$Name) [pscustomobject]@{ Name=$Name; Status='Running' } }
function Get-HotFix { @([pscustomobject]@{ InstalledOn = (Get-Date).AddDays(-3) }) }
function Get-CimInstance { param($ClassName,$Namespace,$Filter) throw 'no cim' }
$ctx = @{ ComputerName='WS01'; PartOfDomain=$false; Domain='WORKGROUP'; IsDC=$false; Build=19045; Caption='Windows 10'; ProductType=1 }
Invoke-HostPostureChecks -Context $ctx
""" % val)
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    got = {c: st for c, st, _ in _posture_lines(proc.stdout)}
    assert got["WIN-CRED-LMCOMPAT"] == want, got.get("WIN-CRED-LMCOMPAT")


def test_windows_get_regpolicy_validates_the_documented_domain(tmp_path):
    # REVIEW-010 round-3 escalation: one validated reader for every enumerated/boolean
    # policy. Absent -> $null; in-domain (DWORD or REG_SZ digits) -> int; anything else
    # throws, so the calling check grades ERR.
    body = _lib(r"""
foreach ($c in @(@('absent', $null), @('two', 2), @('twostr', ' 2 '), @('three', 3), @('neg', -1), @('word', 'abc'))) {
  $script:fake = $c[1]
  function Get-RegValue { param([string]$Path, [string]$Name) return $script:fake }
  try { $r = Get-RegPolicy 'HKLM:\X' 'V' @(0,1,2); 'ROW|' + $c[0] + '|ok|' + (Format-RegText $r) }
  catch { 'ROW|' + $c[0] + '|throw|' + $_.Exception.Message }
}
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    rows = {ln.split("|")[1]: ln.split("|")[2:] for ln in proc.stdout.splitlines() if ln.startswith("ROW|")}
    assert rows["absent"] == ["ok", "unset"]
    assert rows["two"] == ["ok", "2"] and rows["twostr"] == ["ok", "2"]
    for k in ("three", "neg", "word"):
        assert rows[k][0] == "throw" and "outside documented values (0,1,2)" in rows[k][1], (k, rows[k])


@pytest.mark.parametrize("fuzz", ["99", "-1", "'x'"])
def test_gate_out_of_domain_registry_values_never_grade_pass(tmp_path, fuzz):
    # GATE (REVIEW-010 round-3 escalation, structural). Every registry read the host
    # checks make is discovered at run time, then fuzzed ONE AT A TIME out of domain
    # while every other read is absent (always valid) -- so an early throw can never
    # mask a later read. For each read: some check must grade ERR naming that value,
    # and no check may PASS that did not already PASS with everything absent.
    body = _lib(r"""
$script:fuzzKey = ''
$script:keys = New-Object System.Collections.ArrayList
function Get-RegValue { param([string]$Path, [string]$Name)
  $k = $Path + '!' + $Name
  if ($script:keys -notcontains $k) { [void]$script:keys.Add($k) }
  if ($k -eq $script:fuzzKey) { return %(f)s }
  return $null }
function Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction)
  $k = [string]$LiteralPath + '!AutoAdminLogon'
  if ($script:keys -notcontains $k) { [void]$script:keys.Add($k) }
  if ($k -eq $script:fuzzKey) { return [pscustomobject]@{ AutoAdminLogon = %(f)s } }
  return [pscustomobject]@{} }
function Get-Service { param([string]$Name) [pscustomobject]@{ Name=$Name; Status='Running' } }
function Get-HotFix { @([pscustomobject]@{ InstalledOn = (Get-Date).AddDays(-3) }) }
function Get-CimInstance { param($ClassName,$Namespace,$Filter) throw 'no cim' }
function Get-ChildItem { param($LiteralPath, $ErrorAction) @() }
$ctx = @{ ComputerName='WS01'; PartOfDomain=$true; Domain='corp.local'; IsDC=$false; Build=19045; Caption='Windows 10'; ProductType=1 }
function Invoke-Run { $script:AranumPostureSeen = @{}; @(Invoke-HostPostureChecks -Context $ctx | Where-Object { $_ -like 'POSTURE|*' }) }
foreach ($l in (Invoke-Run)) { 'BASE|' + $l }
foreach ($k in @($script:keys)) {
  $script:fuzzKey = $k
  foreach ($l in (Invoke-Run)) { 'FUZZ|' + $k + '|' + $l }
}
""" % {"f": fuzz})
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    base, runs = {}, {}
    for ln in proc.stdout.splitlines():
        if ln.startswith("BASE|POSTURE|"):
            _, _, cid, st, d = ln.split("|", 4)
            base[cid] = st
        elif ln.startswith("FUZZ|"):
            _, key, _, cid, st, d = ln.split("|", 5)
            runs.setdefault(key, {})[cid] = (st, d)
    assert len(base) == 41
    # Anti-vacuous: the discovery really saw the registry surface (37 policy reads,
    # PowerShellVersion, UBR, AutoAdminLogon), including fallback/second reads.
    assert len(runs) >= 39, sorted(runs)
    for must in ("HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer!AlwaysInstallElevated",
                 "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service!allow_unencrypted"):
        assert must in runs, must
    shown = {"99": "99", "-1": "-1", "'x'": "x"}[fuzz]
    for key, got in runs.items():
        name = key.split("!", 1)[1]
        if name == "UBR":          # informational build suffix in a detail, never graded
            continue
        errs = [c for c, (st, d) in got.items()
                if st == "ERR" and (name + "=" + shown) in d and "outside documented values" in d]
        assert errs, (key, {c: v for c, v in got.items() if v[0] != base.get(c)})
        new_pass = sorted(c for c, (st, _) in got.items() if st == "PASS" and base.get(c) != "PASS")
        assert new_pass == [], (key, new_pass)


def test_windows_rootdse_uses_the_bounded_searcher(tmp_path):
    # R5: RootDSE is read through Invoke-LdapSearch (ClientTimeout/ServerTimeLimit), with
    # the collector's -TimeoutSeconds threaded through -- not an unbounded DirectoryEntry.
    body = _lib(r"""
function Invoke-LdapSearch {
  param([string]$SearchRoot, [string]$Filter, [string[]]$Properties, [string]$Scope = 'Subtree', [int]$TimeoutSeconds = 30)
  if ($SearchRoot -eq 'RootDSE') {
    $script:rdse = 'RDSE|' + $Scope + '|' + $TimeoutSeconds + '|' + $Filter
    return @{ defaultnamingcontext='DC=corp,DC=local'; schemanamingcontext='CN=Schema,CN=Configuration,DC=corp,DC=local'; dnshostname='dc01.corp.local'; domainfunctionality='7'; forestfunctionality='7' }
  }
  throw 'directory unavailable' }
$ctx = @{ ComputerName='WS01'; PartOfDomain=$true; Domain='corp.local'; IsDC=$false; Build=19045 }
Invoke-AdPostureChecks -Enabled -Context $ctx -TimeoutSeconds 7
$script:rdse
""")
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    assert "RDSE|Base|7|(objectClass=*)" in proc.stdout
    got = {c: (st, d) for c, st, d in _posture_lines(proc.stdout)}
    assert got["AD-FUNC-LEVEL"] == ("PASS", "domain=corp.local observer=ws01 domainFunctionality=7 forestFunctionality=7")


@pytest.mark.parametrize("mode", ["clm", "rootdse_err"])
def test_windows_ad_lines_are_domain_tagged_before_discovery(tmp_path, mode):
    # R6: once membership is known, the CLM-NA and RootDSE-ERR lines carry the fallback
    # domain/observer tag, so the parser files an all-ERR/NA domain instead of losing it.
    # CLM must be in force BEFORE the collector loads: functions defined in FullLanguage
    # keep running in FullLanguage, so setting it afterwards would not constrain them.
    run = r"""
$ctx = @{ ComputerName='WS01'; PartOfDomain=$true; Domain='Corp.Local'; IsDC=$false; Build=19045 }
Invoke-AdPostureChecks -Enabled -Context $ctx
"""
    if mode == "clm":
        body = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n" + _lib(run)
    else:
        body = _lib("function Get-RootDse { throw 'server down' }\n" + run)
    proc = _pwsh_file(tmp_path, body)
    assert proc.returncode == 0, proc.stderr
    lines = _posture_lines(proc.stdout)
    want = "NA" if mode == "clm" else "ERR"
    assert len(lines) == 15 and all(st == want for _, st, _ in lines)
    assert all(d.startswith("domain=corp.local observer=ws01 ") for _, _, d in lines)
    # ... and the parser keeps the domain (canonical status = that ERR/NA).
    root = _bulk_tree(tmp_path, {"ws01": ("10.0.0.21", "\n".join(
        f"POSTURE|{c}|{st}|{d}" for c, st, d in lines) + "\n")})
    col, _ = _collect(root)
    dom = col.domains["corp.local"]
    assert len(dom["checks"]) == 15 and all(v["status"] == want for v in dom["checks"].values())

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


_PSSA_51 = r"""
if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { 'PSSA_MISSING'; return }
$profiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework',
              'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework')
$settings = @{
  IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes')
  Rules = @{
    PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
    PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = $profiles }
    PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = $profiles }
  }
}
foreach ($p in $args) {
  $r = @(Invoke-ScriptAnalyzer -Path $p -Settings $settings)
  'PSSA|' + (Split-Path -Leaf $p) + '|' + $r.Count + '|' + (($r | ForEach-Object { $_.RuleName }) -join ',')
}
"""


def test_windows_collector_and_payload_pass_pssa_51_profiles(tmp_path):
    # R9: the real Windows PowerShell 5.1 compatibility profiles (Win10 1809 + Server
    # 2016), not only a PS7-token deny-list. A canary of three PS7-only constructs
    # must trip all three rules in the same run, so a silent analyzer cannot pass.
    canary = tmp_path / "canary.ps1"
    canary.write_text("$b = $null ?? 'x'\n$x = Get-Content -Path 'x' -AsByteStream\n"
                      "$j = [System.Text.Json.JsonSerializer]::Serialize($b)\n")
    bw = _load_bulk_win()
    payload = tmp_path / "payload.ps1"
    payload.write_text(bw.build_posture_payload(bw.DEFAULT_SCRIPT.read_text(), WINPS.read_text(), ad=True))
    driver = tmp_path / "pssa.ps1"
    driver.write_text(_PSSA_51)
    proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(driver),
                           str(canary), str(WINPS), str(payload)],
                          capture_output=True, text=True, timeout=600)
    if "PSSA_MISSING" in proc.stdout:
        pytest.fail("PSScriptAnalyzer missing: the 5.1 profile gate is required whenever pwsh is "
                    "present (Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser)")
    assert proc.returncode == 0, proc.stderr
    rows = {r.split("|")[1]: r.split("|")[2:] for r in proc.stdout.splitlines() if r.startswith("PSSA|")}
    assert set(rows["canary.ps1"][1].split(",")) == {
        "PSUseCompatibleSyntax", "PSUseCompatibleCommands", "PSUseCompatibleTypes"}
    assert rows[WINPS.name] == ["0", ""], rows[WINPS.name]
    assert rows["payload.ps1"] == ["0", ""], rows["payload.ps1"]

def test_redactor_folds_case_for_identities_but_leaves_non_ip_tokens_verbatim():
    # Round 2 NEW-1: case-folding is for identity lookup only. A colon token that is
    # not an IP address (uppercase MAC) must come back byte-for-byte, while the same
    # host in two cases still maps to one token.
    r = RPT.Redactor(True)
    r.set_known_hosts(["dc01.corp.local"])
    out = r("mac AA:BB:CC:DD:EE:FF host DC01.CORP.LOCAL and dc01.corp.local ip FE80::1")
    assert "AA:BB:CC:DD:EE:FF" in out
    assert "DC01" not in out and "dc01" not in out and "FE80::1" not in out.upper()
    assert out.count("<TARGET-1>") == 2, out


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


def test_redact_covers_every_posture_identity(tmp_path):
    # R3: identities that never appear in the scan metadata -- an observer (ws01), a
    # Kerberos realm, an AD trust partner, a differently-cased domain, and a name that
    # only a quarantined line carries -- are all scrubbed, in every output.
    win = "\n".join([
        "POSTURE|AD-PWPOL-MINLEN|FAIL|domain=corp.local observer=ws01 minPwdLength=7",
        "POSTURE|AD-TRUSTS|INFO|domain=corp.local observer=ws01 count=1 trusts=partner.example:3",
        "POSTURE|WIN-DOMAIN-JOINED|INFO|domain=CORP.LOCAL role=member",
        "POSTURE|WIN-BOGUS|FAIL|secret-dc.hidden.lan answered",
    ]) + "\n"
    lin = ("POSTURE|LIN-AD-JOINED|INFO|joined realm=CORP.EXAMPLE via=sssd\n"
           "POSTURE|LIN-SYSCTL-ASLR|FAIL|kernel.randomize_va_space=0 seen by WS01 in corp.example\n")
    out = _bulk_tree(tmp_path, {"win1": ("10.0.0.31", win), "lin9": ("10.0.0.99", lin)})
    proc = subprocess.run([sys.executable, str(NET / "report.py"), str(out), "--redact", "--sarif"],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode in (0, 1), proc.stderr
    leaks = ("10.0.0.", "corp.local", "ws01", "partner.example", "corp.example",
             "secret-dc", "hidden.lan")
    for name in ("posture.json", "findings.json", "findings.sarif", "report.md"):
        text = (out / name).read_text().lower()
        assert not [t for t in leaks if t in text], (name, [t for t in leaks if t in text])
        assert "<target-" in text, name                 # redacted, not merely absent
    fj = json.loads((out / "findings.json").read_text())
    q = fj["posture_quarantine"]
    assert len(q) == 1 and q[0]["error"] == "unknown posture check id WIN-BOGUS"
    assert q[0]["line"].startswith("<redacted untrusted line: ")
    # Case variants of one identity collapse to one token.
    pj = json.loads((out / "posture.json").read_text())
    (dom,) = pj["domains"]
    joined = pj["hosts"]
    assert any(c["detail"] == f"domain={dom} role=member"
               for h in joined.values() for cid, c in h["checks"].items() if cid == "WIN-DOMAIN-JOINED")


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


# ============================================================ D3.4 delivery
BULK_LIN = NET / "bulk-enum-linux.sh"
BULK_WIN = NET / "bulk-enum-windows.py"
# A privesc stand-in with both hazards the --with-posture wrapper must
# neutralise: it reads stdin (would swallow the appended collector when the
# payload is streamed to `bash -s`) and it exits (would stop the session).
_STUB_LINENUM = "#!/usr/bin/env bash\necho LIN-START\ncat >/dev/null\necho LIN-END\nexit 0\n"


def _lin_project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / "aranumtoolkit/network").mkdir(parents=True)
    (root / "standalones/linux").mkdir(parents=True)
    for f in ("bulk-enum-linux.sh", "_lib.sh"):
        shutil.copy(NET / f, root / "aranumtoolkit/network" / f)
    (root / "standalones/linux/linenum-fast.sh").write_text(_STUB_LINENUM)
    shutil.copy(LIN, root / "standalones/linux/host-posture.sh")
    (tmp_path / "t.txt").write_text("127.0.0.1\n")
    return root


def _lin_dry(root: Path, out: Path, *extra: str):
    return subprocess.run(["bash", str(root / "aranumtoolkit/network/bulk-enum-linux.sh"),
                           "--targets", str(root.parent / "t.txt"), "-o", str(out),
                           "-u", "x", "--dry-run", *extra],
                          capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)


def test_bulk_linux_with_posture_payload_survives_stdin_reader_and_exit(tmp_path):
    root = _lin_project(tmp_path)
    out = tmp_path / "out"
    proc = _lin_dry(root, out, "--with-posture")
    assert proc.returncode == 0, proc.stderr
    payload = (out / "_payload.sh").read_text()
    # Execute the exact shipped bytes the way the ssh transport does.
    run = subprocess.run(["bash", "-s", "--", "-v"], input=payload, capture_output=True,
                         text=True, timeout=120)
    assert run.returncode == 0, run.stderr
    assert run.stdout.startswith("LIN-START\nLIN-END\n")
    assert len(_posture_lines(run.stdout)) >= 30
    # Negative control: naive concatenation loses the collector to the reader.
    naive = subprocess.run(["bash", "-s", "--", "-v"], input=_STUB_LINENUM + LIN.read_text(),
                           capture_output=True, text=True, timeout=120)
    assert _posture_lines(naive.stdout) == []


def test_bulk_linux_default_payload_is_unchanged(tmp_path):
    root = _lin_project(tmp_path)
    out = tmp_path / "out"
    assert _lin_dry(root, out).returncode == 0
    assert not (out / "_payload.sh").exists()
    assert "with-posture" not in (out / "run.log").read_text()


def _load_bulk_win():
    spec = importlib.util.spec_from_file_location("bulk_enum_windows_posture", BULK_WIN)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bulk_enum_windows_posture"] = mod   # dataclasses resolve via sys.modules
    spec.loader.exec_module(mod)
    return mod


def test_bulk_windows_payload_shape_and_ad_flag():
    bw = _load_bulk_win()
    priv, post = "\ufeff[CmdletBinding()]\r\nparam([switch]$Q)\r\n\r\n'p'\r\n", WINPS.read_text()
    for ad, tail in ((False, ""), (True, " -AdChecks")):
        pay = bw.build_posture_payload(priv, post, ad=ad)
        # Literal blocks only: ConstrainedLanguage blocks [scriptblock]::Create().
        assert "[scriptblock]::Create" not in pay and "FromBase64String" not in pay
        first, second = pay.split("\n}\n\n& {\n", 1)
        assert first == "& {\n[CmdletBinding()]\nparam([switch]$Q)\n\n'p'"   # BOM + CRLF normalised
        assert second == post.rstrip("\n") + "\n}" + tail + "\n\n"          # blank line after each


def test_bulk_windows_ad_requires_with_posture(tmp_path):
    (tmp_path / "t.txt").write_text("u@10.0.0.5\n")
    proc = subprocess.run([sys.executable, str(BULK_WIN), "--targets", str(tmp_path / "t.txt"),
                           "-o", str(tmp_path / "out"), "--dry-run", "--ad"],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2 and "--ad only applies with --with-posture" in proc.stderr


def test_bulk_windows_payload_parses_under_51_rules_and_runs_over_stdin(tmp_path):
    bw = _load_bulk_win()
    priv = "[CmdletBinding()]\nparam([switch]$Q)\n\nfunction Get-X {\n\n  'PRIV-RAN'\n}\n\nGet-X\n"
    pay = tmp_path / "payload.ps1"
    pay.write_text(bw.build_posture_payload(priv, WINPS.read_text(), ad=True))
    check = r"""
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
    proc = _pwsh_file(tmp_path, check, str(pay))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.count("PARSE_ERRORS=0") == 2 and "PS7_NODES=0 PS7_TOKENS=0" in proc.stdout
    # Ship it the way the ssh transport does: `powershell -Command -` on stdin.
    # Ship it the way the ssh transport does, in FullLanguage and in
    # ConstrainedLanguage (AppLocker/WDAC hosts): both blocks must run.
    clm = tmp_path / "clm.ps1"
    clm.write_text("$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n\n" + pay.read_text())
    for script in (pay, clm):
        with script.open() as fh:
            run = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", "-"],
                                 stdin=fh, capture_output=True, text=True, timeout=180)
        assert "PRIV-RAN" in run.stdout, (script.name, run.stdout[-500:])
        lines = _posture_lines(run.stdout)
        assert len(lines) == 56, (script.name, len(lines))
        assert sum(1 for c, _, _ in lines if c.startswith("AD-")) == 15
