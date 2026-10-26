<#
.SYNOPSIS
    Read-only localhost hardening posture collector (aranum PLAN-001 D3.2).
.DESCRIPTION
    Emits one line per check, strict ASCII framing parsed by network/report.py:
        POSTURE|<check-id>|<PASS|FAIL|WARN|INFO|NA|ERR>|<detail>
    ERR means the check could not run (permission, missing provider) - never a PASS.
    Host checks (WIN-*) read the local registry, CIM and service state only.
    Domain checks (AD-*) run ONLY with -AdChecks: bounded, paged, read-only LDAP
    against the host's own domain controller (RootDSE), page size 1000 and a
    per-query timeout. Without -AdChecks no directory query is issued and every
    AD-* check reports NA. Every AD line carries "domain=<dns> observer=<host>".
    Check ids and KB guidance: network/finding-kb.json (`checks`).
.PARAMETER AdChecks
    Opt in to read-only domain posture queries against this host's own DC.
.PARAMETER LdapTimeoutSeconds
    Per-query LDAP server/client time limit (default 30).
.PARAMETER LibraryOnly
    Define the functions and return without running (unit tests).
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-HostPosture.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-HostPosture.ps1 -AdChecks
.NOTES
    Authorized testing only. Enumeration only: no writes, no persistence.
#>
[CmdletBinding()]
param(
    [switch]$AdChecks,
    [int]$LdapTimeoutSeconds = 30,
    [switch]$LibraryOnly
)

$script:AranumPostureSeen = @{}
$script:AranumHostCheckIds = @(
    'WIN-OS-BUILD', 'WIN-PATCH-AGE', 'WIN-FW-DOMAIN', 'WIN-FW-PRIVATE', 'WIN-FW-PUBLIC',
    'WIN-DEF-RTP', 'WIN-DEF-TAMPER', 'WIN-DEF-SIGAGE', 'WIN-BITLOCKER', 'WIN-SECUREBOOT',
    'WIN-SMB-V1', 'WIN-SMB-SRVSIGN', 'WIN-SMB-CLISIGN', 'WIN-NR-LLMNR', 'WIN-NR-NBTNS',
    'WIN-NR-WPAD', 'WIN-LDAP-CLISIGN', 'WIN-ANON-RESTRICT', 'WIN-PS-V2', 'WIN-PS-SBLOG',
    'WIN-PS-TRANSCRIPT', 'WIN-PS-LANGMODE', 'WIN-RDP-ENABLED', 'WIN-RDP-NLA',
    'WIN-CRED-RUNASPPL', 'WIN-CRED-CREDGUARD', 'WIN-CRED-WDIGEST', 'WIN-CRED-LMCOMPAT',
    'WIN-CRED-NOLMHASH', 'WIN-CRED-CACHEDLOGONS', 'WIN-UAC-LUA', 'WIN-UAC-CONSENT',
    'WIN-UAC-LATFP', 'WIN-AIE', 'WIN-ACCT-ADMINS', 'WIN-ACCT-GUEST', 'WIN-AUTOLOGON',
    'WIN-LAPS', 'WIN-SVC-SPOOLER', 'WIN-WINRM-HTTP', 'WIN-DOMAIN-JOINED'
)
$script:AranumAdCheckIds = @(
    'AD-PWPOL-MINLEN', 'AD-PWPOL-LOCKOUT', 'AD-PWPOL-MAXAGE', 'AD-KRBTGT-AGE',
    'AD-KERBEROASTABLE', 'AD-ASREP', 'AD-UNCONSTRAINED', 'AD-ADMINCOUNT', 'AD-DA-MEMBERS',
    'AD-PROTECTED-USERS', 'AD-MAQ', 'AD-FUNC-LEVEL', 'AD-LDAP-SIGNING', 'AD-TRUSTS',
    'AD-LAPS-SCHEMA'
)

# ------------------------------------------------------------------ framing
function Write-PostureLine {
    param([string]$Id, [string]$Status, [string]$Detail)
    if ($script:AranumPostureSeen.ContainsKey($Id)) { return }
    $script:AranumPostureSeen[$Id] = $true
    $d = [string]$Detail
    $d = $d -replace '[\|\r\n]', ' '
    $d = $d -replace '[\x00-\x1f\x7f]', ' '
    Write-Output ('POSTURE|{0}|{1}|{2}' -f $Id, $Status, $d)
}

function New-PostureResult {
    param([string]$Status, [string]$Detail)
    return @{ AranumPostureStatus = $Status; AranumPostureDetail = $Detail }
}

function Invoke-PostureCheck {
    # Runs one check block; emits exactly one line for $Id. The block returns a
    # New-PostureResult; any other output is ignored; an exception becomes ERR.
    param([string]$Id, [scriptblock]$Block, [string]$Prefix = '')
    try {
        $result = & $Block | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('AranumPostureStatus') } |
            Select-Object -Last 1
        if ($null -eq $result) {
            Write-PostureLine $Id 'ERR' ($Prefix + 'check returned no result')
        } else {
            Write-PostureLine $Id $result.AranumPostureStatus ($Prefix + $result.AranumPostureDetail)
        }
    } catch {
        Write-PostureLine $Id 'ERR' ($Prefix + 'check failed: ' + $_.Exception.Message)
    }
}

# ------------------------------------------------------------------ helpers
function Test-IsWindowsOS {
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Get-RegValue {
    # $null ONLY when the key or the value is genuinely absent, so the caller may apply
    # the documented default. Any other failure (access denied, provider unavailable)
    # THROWS, and the enclosing Invoke-PostureCheck reports ERR: a read that failed must
    # never grade as the absent-value default, which for many checks is PASS.
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
    if ($null -eq $item) { return $null }
    $p = $item.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Format-RegText {
    param($Value)
    if ($null -eq $Value) { return 'unset' }
    return [string]$Value
}

function Get-PostureContext {
    $ctx = @{ ComputerName = [string]$env:COMPUTERNAME; PartOfDomain = $false; Domain = '';
              IsDC = $false; Build = 0; Caption = ''; ProductType = 0 }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $ctx.PartOfDomain = [bool]$cs.PartOfDomain
        $ctx.Domain = [string]$cs.Domain
        if ($cs.DomainRole -ge 4) { $ctx.IsDC = $true }
    } catch { }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $ctx.Build = [int]$os.BuildNumber
        $ctx.Caption = [string]$os.Caption
        $ctx.ProductType = [int]$os.ProductType
        if ($ctx.ProductType -eq 2) { $ctx.IsDC = $true }
    } catch { }
    return $ctx
}

# ---- AD helpers (named so tests can AST-extract and drive them with fixtures) ----
function ConvertFrom-LargeInteger {
    # Int64 from a DirectorySearcher Int64, an [ADSI] IADsLargeInteger COM object,
    # or any object exposing HighPart/LowPart (LowPart is a signed Int32).
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [long] -or $Value -is [int]) { return [long]$Value }
    $high = $null
    $low = $null
    if ($Value.PSObject.Properties['HighPart'] -and $Value.PSObject.Properties['LowPart']) {
        $high = $Value.HighPart
        $low = $Value.LowPart
    } else {
        $t = $Value.GetType()
        $high = $t.InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
        $low = $t.InvokeMember('LowPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
    }
    $lowU = [long]$low
    if ($lowU -lt 0) { $lowU = $lowU + 4294967296 }
    return ([long]$high * 4294967296) + $lowU
}

function Get-FileTimeAgeDays {
    # Days since a FILETIME (100ns ticks since 1601 UTC); $null for never/unset.
    param($FileTime, [datetime]$Now = [datetime]::UtcNow)
    $ft = ConvertFrom-LargeInteger $FileTime
    if ($null -eq $ft -or $ft -le 0 -or $ft -eq [long]::MaxValue) { return $null }
    return [math]::Floor(($Now - [datetime]::FromFileTimeUtc($ft)).TotalDays)
}

function Get-EntryValue {
    param($Entry, [string]$Name)
    $k = $Name.ToLower()
    if ($Entry -is [hashtable]) {
        if ($Entry.ContainsKey($k)) { return $Entry[$k] }
        return $null
    }
    $p = $Entry.PSObject.Properties[$k]
    if ($p) { return $p.Value }
    return $null
}

function Test-EntryEnabled {
    param($Entry)
    $uac = [long](Get-EntryValue $Entry 'useraccountcontrol')
    return (($uac -band 2) -eq 0)
}

function Test-RoastableUser {
    # Enabled user (not computer, not krbtgt) with at least one SPN.
    param($Entry)
    $spn = @(Get-EntryValue $Entry 'serviceprincipalname') | Where-Object { $_ }
    if ($spn.Count -eq 0) { return $false }
    $classes = @(Get-EntryValue $Entry 'objectclass')
    if ($classes -contains 'computer') { return $false }
    $sam = [string](Get-EntryValue $Entry 'samaccountname')
    if ($sam -eq 'krbtgt' -or $sam.EndsWith('$')) { return $false }
    return (Test-EntryEnabled $Entry)
}

function Test-AsRepUser {
    param($Entry)
    $uac = [long](Get-EntryValue $Entry 'useraccountcontrol')
    return ((($uac -band 0x400000) -ne 0) -and (Test-EntryEnabled $Entry))
}

function Test-UnconstrainedNonDc {
    # TRUSTED_FOR_DELEGATION, enabled, and not a DC (SERVER_TRUST_ACCOUNT 0x2000).
    param($Entry)
    $uac = [long](Get-EntryValue $Entry 'useraccountcontrol')
    if (($uac -band 0x80000) -eq 0) { return $false }
    if (($uac -band 0x2000) -ne 0) { return $false }
    return (Test-EntryEnabled $Entry)
}

function Measure-DistinctMember {
    # Count distinct members by distinguishedName (case-insensitive) so a user
    # reached through several nested groups is counted once.
    param($Entries)
    $seen = @{}
    foreach ($e in @($Entries)) {
        if ($null -eq $e) { continue }
        $dn = [string](Get-EntryValue $e 'distinguishedname')
        if ($dn) { $seen[$dn.ToLower()] = $true }
    }
    return $seen.Count
}

function Resolve-LdapSigningStatus {
    # Both policies are graded; PASS needs signing required (LDAPServerIntegrity=2) AND
    # channel binding always enforced (LdapEnforceChannelBinding=2). $ServerIntegrity
    # $null = not a DC observer -> NA (never a false PASS). $ChannelBinding $null = the
    # value is absent on the DC (an unreadable value throws upstream -> ERR): absent means
    # not enforced, so LDAPS relay stays open.
    param($ServerIntegrity, $ChannelBinding)
    if ($null -eq $ServerIntegrity) {
        return (New-PostureResult 'NA' 'LDAPServerIntegrity not readable from this observer (run on a DC)')
    }
    $cb = 'unset'
    if ($null -ne $ChannelBinding) { $cb = [string]$ChannelBinding }
    $detail = 'LDAPServerIntegrity=' + $ServerIntegrity + ' LdapEnforceChannelBinding=' + $cb
    # Both are enumerated policies: a value outside the documented domain is ERR,
    # never a fall-through PASS (si 0..2, cb 0..2).
    $si = [int]$ServerIntegrity
    if ($si -lt 0 -or $si -gt 2) { return (New-PostureResult 'ERR' ($detail + ' (LDAPServerIntegrity outside 0..2)')) }
    if ($null -ne $ChannelBinding) {
        $cbv = [int]$ChannelBinding
        if ($cbv -lt 0 -or $cbv -gt 2) { return (New-PostureResult 'ERR' ($detail + ' (LdapEnforceChannelBinding outside 0..2)')) }
    }
    if ($si -lt 2) { return (New-PostureResult 'FAIL' $detail) }
    if ($null -eq $ChannelBinding -or $cbv -eq 0) {
        return (New-PostureResult 'FAIL' ($detail + ' (LDAPS relay: channel binding not enforced)'))
    }
    if ($cbv -eq 1) {
        return (New-PostureResult 'WARN' ($detail + ' (channel binding only when supported)'))
    }
    return (New-PostureResult 'PASS' $detail)
}

function ConvertTo-DnsDomain {
    param([string]$DistinguishedName)
    $parts = @($DistinguishedName -split ',' | Where-Object { $_ -match '^\s*DC=' } |
        ForEach-Object { ($_ -replace '^\s*DC=', '').Trim() })
    return ($parts -join '.').ToLower()
}

function ConvertTo-PlainEntry {
    # SearchResult.Properties (ResultPropertyCollection) -> hashtable, lowercase keys.
    param($Properties)
    $h = @{}
    foreach ($name in $Properties.PropertyNames) {
        $vals = @($Properties[$name])
        if ($vals.Count -eq 1) { $h[([string]$name).ToLower()] = $vals[0] }
        else { $h[([string]$name).ToLower()] = $vals }
    }
    return $h
}

function Invoke-LdapSearch {
    # Bounded, paged, read-only directory query.
    param([string]$SearchRoot, [string]$Filter, [string[]]$Properties,
          [string]$Scope = 'Subtree', [int]$TimeoutSeconds = 30)
    $entry = New-Object System.DirectoryServices.DirectoryEntry('LDAP://' + $SearchRoot)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SearchScope = $Scope
    $searcher.ServerTimeLimit = New-TimeSpan -Seconds $TimeoutSeconds
    $searcher.ClientTimeout = New-TimeSpan -Seconds ($TimeoutSeconds + 5)
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) { ConvertTo-PlainEntry $r.Properties }
    } finally {
        $results.Dispose()
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function Get-RootDse {
    # Through the same bounded DirectorySearcher as every other query (ClientTimeout +
    # ServerTimeLimit), not a bare DirectoryEntry property read, which has no timeout.
    param([int]$TimeoutSeconds = 30)
    $e = @(Invoke-LdapSearch -SearchRoot 'RootDSE' -Filter '(objectClass=*)' -Scope Base -TimeoutSeconds $TimeoutSeconds `
        -Properties @('defaultNamingContext', 'schemaNamingContext', 'dnsHostName', 'domainFunctionality', 'forestFunctionality'))
    if ($e.Count -eq 0) { throw 'RootDSE returned no entry' }
    return @{
        defaultNamingContext = [string](Get-EntryValue $e[0] 'defaultnamingcontext')
        schemaNamingContext  = [string](Get-EntryValue $e[0] 'schemanamingcontext')
        dnsHostName          = [string](Get-EntryValue $e[0] 'dnshostname')
        domainFunctionality  = [int]([string](Get-EntryValue $e[0] 'domainfunctionality'))
        forestFunctionality  = [int]([string](Get-EntryValue $e[0] 'forestfunctionality'))
    }
}

# ------------------------------------------------------------------ host checks
function Invoke-HostPostureChecks {
    param([hashtable]$Context)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    Invoke-PostureCheck 'WIN-OS-BUILD' {
        $ubr = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
        $role = 'workstation'
        if ($Context.ProductType -eq 3) { $role = 'server' }
        if ($Context.IsDC) { $role = 'dc' }
        $build = [string]$Context.Build
        if ($null -ne $ubr) { $build = $build + '.' + $ubr }
        New-PostureResult 'INFO' ('os=' + $Context.Caption + ' build=' + $build + ' role=' + $role)
    }

    Invoke-PostureCheck 'WIN-PATCH-AGE' {
        $dates = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
            ForEach-Object { [datetime]$_.InstalledOn })
        if ($dates.Count -eq 0) { return (New-PostureResult 'ERR' 'no hotfix install dates readable') }
        $newest = ($dates | Sort-Object -Descending | Select-Object -First 1)
        $age = [math]::Floor(((Get-Date) - $newest).TotalDays)
        $detail = 'newest hotfix ' + $newest.ToString('yyyy-MM-dd') + ' age_days=' + $age
        if ($age -gt 90) { return (New-PostureResult 'FAIL' $detail) }
        if ($age -gt 45) { return (New-PostureResult 'WARN' $detail) }
        New-PostureResult 'PASS' $detail
    }

    $fwSvc = $null
    try { $fwSvc = Get-Service -Name mpssvc -ErrorAction Stop } catch { }
    $profiles = @(
        @{ Id = 'WIN-FW-DOMAIN'; Key = 'DomainProfile'; Pol = 'DomainProfile'; Bad = 'WARN' },
        @{ Id = 'WIN-FW-PRIVATE'; Key = 'StandardProfile'; Pol = 'PrivateProfile'; Bad = 'WARN' },
        @{ Id = 'WIN-FW-PUBLIC'; Key = 'PublicProfile'; Pol = 'PublicProfile'; Bad = 'FAIL' }
    )
    foreach ($fp in $profiles) {
        Invoke-PostureCheck $fp.Id {
            if ($fwSvc -and $fwSvc.Status -ne 'Running') {
                return (New-PostureResult $fp.Bad ('firewall service mpssvc ' + $fwSvc.Status))
            }
            $pol = Get-RegValue ('HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\' + $fp.Pol) 'EnableFirewall'
            $loc = Get-RegValue ('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $fp.Key) 'EnableFirewall'
            $src = 'local'
            $val = $loc
            if ($null -ne $pol) { $val = $pol; $src = 'policy' }
            if ($null -eq $val) { return (New-PostureResult 'ERR' 'EnableFirewall not readable') }
            if ([int]$val -eq 1) { return (New-PostureResult 'PASS' ('enabled (' + $src + ')')) }
            New-PostureResult $fp.Bad ('disabled (' + $src + ')')
        }
    }

    $mp = $null
    $mpNote = ''
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mpNote = $_.Exception.Message }
    } else { $mpNote = 'Defender module absent' }
    $passive = $false
    if ($mp -and $mp.PSObject.Properties['AMRunningMode'] -and ([string]$mp.AMRunningMode -match 'Passive|EDR')) { $passive = $true }
    Invoke-PostureCheck 'WIN-DEF-RTP' {
        if (-not $mp) { return (New-PostureResult 'NA' ('defender not present: ' + $mpNote)) }
        if ($passive) { return (New-PostureResult 'NA' ('defender in ' + $mp.AMRunningMode + ' (third-party AV)')) }
        if ($mp.RealTimeProtectionEnabled) { return (New-PostureResult 'PASS' 'real-time protection on') }
        New-PostureResult 'FAIL' 'real-time protection off'
    }
    Invoke-PostureCheck 'WIN-DEF-TAMPER' {
        if (-not $mp) { return (New-PostureResult 'NA' 'defender not present') }
        if (-not $mp.PSObject.Properties['IsTamperProtected']) { return (New-PostureResult 'NA' 'tamper state not reported by this build') }
        if ($mp.IsTamperProtected) { return (New-PostureResult 'PASS' 'tamper protection on') }
        New-PostureResult 'WARN' 'tamper protection off'
    }
    Invoke-PostureCheck 'WIN-DEF-SIGAGE' {
        if (-not $mp) { return (New-PostureResult 'NA' 'defender not present') }
        $age = [int]$mp.AntivirusSignatureAge
        if ($age -gt 7) { return (New-PostureResult 'WARN' ('signature age ' + $age + ' days')) }
        New-PostureResult 'PASS' ('signature age ' + $age + ' days')
    }

    Invoke-PostureCheck 'WIN-BITLOCKER' {
        $drive = [string]$env:SystemDrive
        try {
            $vol = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter ("DriveLetter='" + $drive + "'") -ErrorAction Stop
            if ($vol -and [int]$vol.ProtectionStatus -eq 1) { return (New-PostureResult 'PASS' ($drive + ' protection on')) }
            if ($vol) { return (New-PostureResult 'WARN' ($drive + ' protection off')) }
        } catch { }
        try {
            $shell = New-Object -ComObject Shell.Application
            $code = $shell.NameSpace($drive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
            if ($code -eq 1 -or $code -eq 3 -or $code -eq 5) { return (New-PostureResult 'PASS' ($drive + ' protection on (shell state ' + $code + ')')) }
            if ($code -eq 2) { return (New-PostureResult 'WARN' ($drive + ' protection off')) }
        } catch { }
        New-PostureResult 'ERR' 'BitLocker state not readable without elevation'
    }

    Invoke-PostureCheck 'WIN-SECUREBOOT' {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
        if ($null -eq $v) { return (New-PostureResult 'INFO' 'legacy BIOS or Secure Boot state key absent') }
        if ([int]$v -eq 1) { return (New-PostureResult 'PASS' 'UEFISecureBootEnabled=1') }
        New-PostureResult 'WARN' 'UEFISecureBootEnabled=0'
    }

    $lmSrv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lmWks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Invoke-PostureCheck 'WIN-SMB-V1' {
        $v = Get-RegValue $lmSrv 'SMB1'
        if ($null -ne $v) {
            if ([int]$v -eq 0) { return (New-PostureResult 'PASS' 'SMB1=0') }
            return (New-PostureResult 'FAIL' ('SMB1=' + $v))
        }
        $start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\srv' 'Start'
        if ($null -ne $start -and [int]$start -ne 4) { return (New-PostureResult 'FAIL' ('SMB1 server driver srv.sys Start=' + $start)) }
        New-PostureResult 'PASS' 'SMB1 server driver absent or disabled'
    }
    Invoke-PostureCheck 'WIN-SMB-SRVSIGN' {
        $v = Get-RegValue $lmSrv 'RequireSecuritySignature'
        $src = 'registry'
        if ($null -eq $v) {
            try { $v = [int][bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature; $src = 'SmbServerConfiguration' } catch { }
        }
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'PASS' ('RequireSecuritySignature=1 (' + $src + ')')) }
        New-PostureResult 'FAIL' ('RequireSecuritySignature=' + (Format-RegText $v) + ' (' + $src + ')')
    }
    Invoke-PostureCheck 'WIN-SMB-CLISIGN' {
        $v = Get-RegValue $lmWks 'RequireSecuritySignature'
        $src = 'registry'
        if ($null -eq $v) {
            try { $v = [int][bool](Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature; $src = 'SmbClientConfiguration' } catch { }
        }
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'PASS' ('RequireSecuritySignature=1 (' + $src + ')')) }
        New-PostureResult 'WARN' ('RequireSecuritySignature=' + (Format-RegText $v) + ' (' + $src + ')')
    }

    Invoke-PostureCheck 'WIN-NR-LLMNR' {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        if ($null -ne $v -and [int]$v -eq 0) { return (New-PostureResult 'PASS' 'EnableMulticast=0') }
        New-PostureResult 'FAIL' ('LLMNR not disabled by policy (EnableMulticast=' + (Format-RegText $v) + ')')
    }
    Invoke-PostureCheck 'WIN-NR-NBTNS' {
        $ads = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop)
        $on = @($ads | Where-Object { [int]$_.TcpipNetbiosOptions -ne 2 })
        if ($on.Count -gt 0) { return (New-PostureResult 'WARN' ([string]$on.Count + ' of ' + $ads.Count + ' IP adapters with NetBIOS not disabled')) }
        New-PostureResult 'PASS' ('NetBIOS disabled on ' + $ads.Count + ' IP adapters')
    }
    Invoke-PostureCheck 'WIN-NR-WPAD' {
        $dis = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'
        if ($null -ne $dis -and [int]$dis -eq 1) { return (New-PostureResult 'PASS' 'DisableWpad=1') }
        $start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' 'Start'
        if ($null -ne $start -and [int]$start -eq 4) { return (New-PostureResult 'PASS' 'WinHttpAutoProxySvc disabled') }
        New-PostureResult 'WARN' ('WPAD discovery possible (WinHttpAutoProxySvc Start=' + (Format-RegText $start) + ')')
    }
    Invoke-PostureCheck 'WIN-LDAP-CLISIGN' {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity'
        if ($null -ne $v -and [int]$v -ge 2) { return (New-PostureResult 'PASS' ('LDAPClientIntegrity=' + $v)) }
        $shown = '1 (default)'
        if ($null -ne $v) { $shown = (Format-RegText $v) }
        New-PostureResult 'WARN' ('LDAPClientIntegrity=' + $shown)
    }
    Invoke-PostureCheck 'WIN-ANON-RESTRICT' {
        $sam = Get-RegValue $lsa 'RestrictAnonymousSAM'
        $eia = Get-RegValue $lsa 'EveryoneIncludesAnonymous'
        $ra = Get-RegValue $lsa 'RestrictAnonymous'
        $detail = 'RestrictAnonymousSAM=' + (Format-RegText $sam) + ' RestrictAnonymous=' + (Format-RegText $ra) + ' EveryoneIncludesAnonymous=' + (Format-RegText $eia)
        if (($null -ne $sam -and [int]$sam -eq 0) -or ($null -ne $eia -and [int]$eia -eq 1)) { return (New-PostureResult 'WARN' $detail) }
        New-PostureResult 'PASS' $detail
    }

    $psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Invoke-PostureCheck 'WIN-PS-V2' {
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion'
        if ($v -and ([string]$v).StartsWith('2')) { return (New-PostureResult 'WARN' ('PowerShell ' + $v + ' engine installed')) }
        New-PostureResult 'PASS' 'PowerShell 2.0 engine not installed'
    }
    Invoke-PostureCheck 'WIN-PS-SBLOG' {
        $v = Get-RegValue ($psPol + '\ScriptBlockLogging') 'EnableScriptBlockLogging'
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'PASS' 'EnableScriptBlockLogging=1') }
        New-PostureResult 'WARN' 'script-block logging not enabled by policy'
    }
    Invoke-PostureCheck 'WIN-PS-TRANSCRIPT' {
        $v = Get-RegValue ($psPol + '\Transcription') 'EnableTranscripting'
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'PASS' 'EnableTranscripting=1') }
        New-PostureResult 'WARN' 'transcription not enabled by policy'
    }
    Invoke-PostureCheck 'WIN-PS-LANGMODE' {
        New-PostureResult 'INFO' ('LanguageMode=' + [string]$ExecutionContext.SessionState.LanguageMode)
    }

    $rdpDeny = $null
    $rdpErr = ''
    try {
        $rdpDeny = Get-RegValue $tsPol 'fDenyTSConnections'
        if ($null -eq $rdpDeny) { $rdpDeny = Get-RegValue $ts 'fDenyTSConnections' }
    } catch { $rdpErr = $_.Exception.Message }
    $rdpOn = ($null -ne $rdpDeny -and [int]$rdpDeny -eq 0)
    Invoke-PostureCheck 'WIN-RDP-ENABLED' {
        if ($rdpErr) { throw ('fDenyTSConnections unreadable: ' + $rdpErr) }
        if ($rdpOn) { return (New-PostureResult 'INFO' 'RDP enabled (fDenyTSConnections=0)') }
        New-PostureResult 'INFO' ('RDP disabled (fDenyTSConnections=' + (Format-RegText $rdpDeny) + ')')
    }
    Invoke-PostureCheck 'WIN-RDP-NLA' {
        if ($rdpErr) { throw ('fDenyTSConnections unreadable: ' + $rdpErr) }
        if (-not $rdpOn) { return (New-PostureResult 'NA' 'RDP disabled') }
        $v = Get-RegValue $tsPol 'UserAuthentication'
        if ($null -eq $v) { $v = Get-RegValue ($ts + '\WinStations\RDP-Tcp') 'UserAuthentication' }
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'PASS' 'NLA required') }
        New-PostureResult 'FAIL' ('NLA not required (UserAuthentication=' + (Format-RegText $v) + ')')
    }

    Invoke-PostureCheck 'WIN-CRED-RUNASPPL' {
        $v = Get-RegValue $lsa 'RunAsPPL'
        if ($null -ne $v -and ([int]$v -eq 1 -or [int]$v -eq 2)) { return (New-PostureResult 'PASS' ('RunAsPPL=' + $v)) }
        New-PostureResult 'WARN' ('RunAsPPL=' + (Format-RegText $v))
    }
    Invoke-PostureCheck 'WIN-CRED-CREDGUARD' {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        if (@($dg.SecurityServicesRunning) -contains 1) { return (New-PostureResult 'PASS' 'Credential Guard running') }
        New-PostureResult 'WARN' 'Credential Guard not running'
    }
    Invoke-PostureCheck 'WIN-CRED-WDIGEST' {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'FAIL' 'UseLogonCredential=1') }
        if ($null -eq $v -and $Context.Build -gt 0 -and $Context.Build -lt 9600) { return (New-PostureResult 'FAIL' ('UseLogonCredential unset on pre-8.1 build ' + $Context.Build + ' (default on)')) }
        New-PostureResult 'PASS' ('UseLogonCredential=' + (Format-RegText $v))
    }
    Invoke-PostureCheck 'WIN-CRED-LMCOMPAT' {
        $v = Get-RegValue $lsa 'LmCompatibilityLevel'
        if ($null -eq $v) { return (New-PostureResult 'WARN' 'LmCompatibilityLevel unset (default 3)') }
        if ([int]$v -lt 0 -or [int]$v -gt 5) { return (New-PostureResult 'ERR' ('LmCompatibilityLevel=' + $v + ' (outside 0..5)')) }
        if ([int]$v -lt 3) { return (New-PostureResult 'FAIL' ('LmCompatibilityLevel=' + $v)) }
        if ([int]$v -lt 5) { return (New-PostureResult 'WARN' ('LmCompatibilityLevel=' + $v)) }
        New-PostureResult 'PASS' ('LmCompatibilityLevel=' + $v)
    }
    Invoke-PostureCheck 'WIN-CRED-NOLMHASH' {
        $v = Get-RegValue $lsa 'NoLMHash'
        if ($null -ne $v -and [int]$v -eq 0) { return (New-PostureResult 'FAIL' 'NoLMHash=0') }
        New-PostureResult 'PASS' ('NoLMHash=' + (Format-RegText $v))
    }
    Invoke-PostureCheck 'WIN-CRED-CACHEDLOGONS' {
        if (-not $Context.PartOfDomain) { return (New-PostureResult 'NA' 'not domain-joined') }
        $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
        $n = 10
        if ($null -ne $v) { $n = [int]((Format-RegText $v)) }
        if ($n -gt 4) { return (New-PostureResult 'WARN' ('CachedLogonsCount=' + $n)) }
        New-PostureResult 'PASS' ('CachedLogonsCount=' + $n)
    }

    Invoke-PostureCheck 'WIN-UAC-LUA' {
        $v = Get-RegValue $sys 'EnableLUA'
        if ($null -ne $v -and [int]$v -eq 0) { return (New-PostureResult 'FAIL' 'EnableLUA=0') }
        New-PostureResult 'PASS' ('EnableLUA=' + (Format-RegText $v))
    }
    Invoke-PostureCheck 'WIN-UAC-CONSENT' {
        $v = Get-RegValue $sys 'ConsentPromptBehaviorAdmin'
        if ($null -ne $v -and [int]$v -eq 0) { return (New-PostureResult 'WARN' 'ConsentPromptBehaviorAdmin=0') }
        New-PostureResult 'PASS' ('ConsentPromptBehaviorAdmin=' + (Format-RegText $v))
    }
    Invoke-PostureCheck 'WIN-UAC-LATFP' {
        $v = Get-RegValue $sys 'LocalAccountTokenFilterPolicy'
        if ($null -ne $v -and [int]$v -eq 1) { return (New-PostureResult 'WARN' 'LocalAccountTokenFilterPolicy=1') }
        New-PostureResult 'PASS' ('LocalAccountTokenFilterPolicy=' + (Format-RegText $v))
    }
    Invoke-PostureCheck 'WIN-AIE' {
        $m = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
        $u = Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
        if ($null -ne $m -and $null -ne $u -and [int]$m -eq 1 -and [int]$u -eq 1) { return (New-PostureResult 'FAIL' 'AlwaysInstallElevated=1 in HKLM and HKCU') }
        New-PostureResult 'PASS' ('HKLM=' + (Format-RegText $m) + ' HKCU=' + (Format-RegText $u))
    }

    Invoke-PostureCheck 'WIN-ACCT-ADMINS' {
        $names = @()
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $names = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
        } else {
            $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $gname = ($sid.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
            $grp = [ADSI]('WinNT://./' + $gname + ',group')
            $names = @($grp.Invoke('Members') | ForEach-Object { [string]$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
        }
        $shown = ($names | Select-Object -First 10) -join ','
        New-PostureResult 'INFO' ('count=' + $names.Count + ' members=' + $shown)
    }
    Invoke-PostureCheck 'WIN-ACCT-GUEST' {
        $g = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=TRUE AND SID LIKE '%-501'" -ErrorAction Stop)
        if ($g.Count -eq 0) { return (New-PostureResult 'NA' 'no local Guest account (domain controller?)') }
        if ($g[0].Disabled) { return (New-PostureResult 'PASS' 'Guest disabled') }
        New-PostureResult 'FAIL' ('Guest enabled (' + $g[0].Name + ')')
    }
    Invoke-PostureCheck 'WIN-AUTOLOGON' {
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $item = Get-ItemProperty -LiteralPath $wl -ErrorAction Stop
        $hasPw = ($null -ne $item.PSObject.Properties['DefaultPassword']) -and ([string]$item.DefaultPassword).Length -gt 0
        if ($hasPw) { return (New-PostureResult 'FAIL' 'Winlogon DefaultPassword present (value not shown)') }
        if ([string]$item.AutoAdminLogon -eq '1') { return (New-PostureResult 'WARN' 'AutoAdminLogon=1 without stored DefaultPassword') }
        New-PostureResult 'PASS' 'no AutoLogon configured'
    }
    Invoke-PostureCheck 'WIN-LAPS' {
        if (-not $Context.PartOfDomain) { return (New-PostureResult 'NA' 'not domain-joined') }
        $b1 = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory'
        $b2 = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' 'BackupDirectory'
        $legacy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
        if (($null -ne $b1 -and [int]$b1 -gt 0) -or ($null -ne $b2 -and [int]$b2 -gt 0)) { return (New-PostureResult 'PASS' 'Windows LAPS policy BackupDirectory set') }
        if ($null -ne $legacy -and [int]$legacy -eq 1) { return (New-PostureResult 'PASS' 'legacy LAPS AdmPwdEnabled=1') }
        New-PostureResult 'WARN' 'no LAPS policy'
    }
    Invoke-PostureCheck 'WIN-SVC-SPOOLER' {
        $s = Get-Service -Name Spooler -ErrorAction Stop
        if ($s.Status -ne 'Running') { return (New-PostureResult 'PASS' ('Spooler ' + $s.Status)) }
        if ($Context.IsDC) { return (New-PostureResult 'WARN' 'Spooler running on a domain controller') }
        New-PostureResult 'INFO' 'Spooler running'
    }
    Invoke-PostureCheck 'WIN-WINRM-HTTP' {
        $s = $null
        try { $s = Get-Service -Name WinRM -ErrorAction Stop } catch { }
        if (-not $s -or $s.Status -ne 'Running') { return (New-PostureResult 'NA' 'WinRM not running') }
        $u1 = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencrypted'
        $u2 = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service' 'allow_unencrypted'
        if (($null -ne $u1 -and [int]$u1 -eq 1) -or ($null -ne $u2 -and [int]$u2 -eq 1)) { return (New-PostureResult 'FAIL' 'AllowUnencrypted=1') }
        $ls = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -ErrorAction Stop | ForEach-Object { $_.PSChildName })
        $https = @($ls | Where-Object { $_ -match '\+HTTPS$' })
        $http = @($ls | Where-Object { $_ -match '\+HTTP$' })
        if ($https.Count -gt 0) { return (New-PostureResult 'PASS' ('HTTPS listener present (' + $https.Count + ')')) }
        if ($http.Count -gt 0) { return (New-PostureResult 'WARN' 'HTTP listener only (no TLS)') }
        New-PostureResult 'PASS' 'no WinRM listeners'
    }
    Invoke-PostureCheck 'WIN-DOMAIN-JOINED' {
        if (-not $Context.PartOfDomain) { return (New-PostureResult 'INFO' 'workgroup') }
        $role = 'member'
        if ($Context.IsDC) { $role = 'dc' }
        New-PostureResult 'INFO' ('domain=' + $Context.Domain.ToLower() + ' role=' + $role)
    }
}

# ------------------------------------------------------------------ AD checks
function Invoke-AdPostureChecks {
    param([switch]$Enabled, [hashtable]$Context, [int]$TimeoutSeconds = 30)
    if (-not $Enabled) {
        foreach ($id in $script:AranumAdCheckIds) { Write-PostureLine $id 'NA' 'ad checks not requested' }
        return
    }
    if (-not $Context.PartOfDomain) {
        foreach ($id in $script:AranumAdCheckIds) { Write-PostureLine $id 'NA' 'not domain-joined' }
        return
    }
    # Membership is confirmed: from here on every line carries a domain/observer tag so
    # the parser files it under the domain (an all-ERR/NA domain must still appear). The
    # fallback tag uses the joined domain; RootDSE's naming context replaces it below.
    $observer = ' observer=' + $Context.ComputerName.ToLower() + ' '
    $tag = 'domain=' + $Context.Domain.ToLower() + $observer
    if ([string]$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        foreach ($id in $script:AranumAdCheckIds) { Write-PostureLine $id 'NA' ($tag + 'ConstrainedLanguage: ADSI unavailable') }
        return
    }
    $rootDse = $null
    try { $rootDse = Get-RootDse -TimeoutSeconds $TimeoutSeconds } catch {
        foreach ($id in $script:AranumAdCheckIds) { Write-PostureLine $id 'ERR' ($tag + 'RootDSE unavailable: ' + $_.Exception.Message) }
        return
    }
    $dn = $rootDse.defaultNamingContext
    $tag = 'domain=' + (ConvertTo-DnsDomain $dn) + $observer
    $t = $TimeoutSeconds

    $dom = $null
    $domErr = ''
    try {
        $dom = @(Invoke-LdapSearch -SearchRoot $dn -Filter '(objectClass=domainDNS)' -Scope Base -TimeoutSeconds $t `
            -Properties @('minPwdLength', 'lockoutThreshold', 'maxPwdAge', 'ms-DS-MachineAccountQuota', 'objectSid'))[0]
    } catch { $domErr = $_.Exception.Message }

    Invoke-PostureCheck 'AD-PWPOL-MINLEN' -Prefix $tag {
        if (-not $dom) { throw ('domain object unreadable: ' + $domErr) }
        $n = [int](Get-EntryValue $dom 'minpwdlength')
        if ($n -lt 8) { return (New-PostureResult 'FAIL' ('minPwdLength=' + $n)) }
        if ($n -lt 14) { return (New-PostureResult 'WARN' ('minPwdLength=' + $n)) }
        New-PostureResult 'PASS' ('minPwdLength=' + $n)
    }
    Invoke-PostureCheck 'AD-PWPOL-LOCKOUT' -Prefix $tag {
        if (-not $dom) { throw ('domain object unreadable: ' + $domErr) }
        $n = [int](Get-EntryValue $dom 'lockoutthreshold')
        if ($n -eq 0) { return (New-PostureResult 'FAIL' 'lockoutThreshold=0 (no lockout)') }
        if ($n -gt 10) { return (New-PostureResult 'WARN' ('lockoutThreshold=' + $n)) }
        New-PostureResult 'PASS' ('lockoutThreshold=' + $n)
    }
    Invoke-PostureCheck 'AD-PWPOL-MAXAGE' -Prefix $tag {
        if (-not $dom) { throw ('domain object unreadable: ' + $domErr) }
        $raw = ConvertFrom-LargeInteger (Get-EntryValue $dom 'maxpwdage')
        if ($null -eq $raw -or $raw -eq 0 -or $raw -eq [long]::MinValue) { return (New-PostureResult 'INFO' 'maxPwdAge=never') }
        New-PostureResult 'INFO' ('maxPwdAge_days=' + [math]::Floor([math]::Abs($raw) / 864000000000))
    }
    Invoke-PostureCheck 'AD-MAQ' -Prefix $tag {
        if (-not $dom) { throw ('domain object unreadable: ' + $domErr) }
        $n = [int](Get-EntryValue $dom 'ms-ds-machineaccountquota')
        if ($n -gt 0) { return (New-PostureResult 'WARN' ('ms-DS-MachineAccountQuota=' + $n)) }
        New-PostureResult 'PASS' 'ms-DS-MachineAccountQuota=0'
    }
    Invoke-PostureCheck 'AD-KRBTGT-AGE' -Prefix $tag {
        $k = @(Invoke-LdapSearch -SearchRoot $dn -Filter '(&(objectClass=user)(sAMAccountName=krbtgt))' -Properties @('pwdLastSet') -TimeoutSeconds $t)
        if ($k.Count -eq 0) { return (New-PostureResult 'ERR' 'krbtgt not found') }
        $age = Get-FileTimeAgeDays (Get-EntryValue $k[0] 'pwdlastset')
        if ($null -eq $age) { return (New-PostureResult 'ERR' 'krbtgt pwdLastSet unset') }
        if ($age -gt 365) { return (New-PostureResult 'FAIL' ('krbtgt_pwd_age_days=' + $age)) }
        if ($age -gt 180) { return (New-PostureResult 'WARN' ('krbtgt_pwd_age_days=' + $age)) }
        New-PostureResult 'PASS' ('krbtgt_pwd_age_days=' + $age)
    }
    $acctProps = @('sAMAccountName', 'userAccountControl', 'servicePrincipalName', 'objectClass', 'distinguishedName')
    Invoke-PostureCheck 'AD-KERBEROASTABLE' -Prefix $tag {
        $rows = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties $acctProps `
            -Filter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
        $hits = @($rows | Where-Object { Test-RoastableUser $_ })
        $names = ($hits | Select-Object -First 5 | ForEach-Object { [string](Get-EntryValue $_ 'samaccountname') }) -join ','
        if ($hits.Count -gt 0) { return (New-PostureResult 'FAIL' ('count=' + $hits.Count + ' sample=' + $names)) }
        New-PostureResult 'PASS' 'count=0'
    }
    Invoke-PostureCheck 'AD-ASREP' -Prefix $tag {
        $rows = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties $acctProps `
            -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
        $hits = @($rows | Where-Object { Test-AsRepUser $_ })
        $names = ($hits | Select-Object -First 5 | ForEach-Object { [string](Get-EntryValue $_ 'samaccountname') }) -join ','
        if ($hits.Count -gt 0) { return (New-PostureResult 'FAIL' ('count=' + $hits.Count + ' sample=' + $names)) }
        New-PostureResult 'PASS' 'count=0'
    }
    Invoke-PostureCheck 'AD-UNCONSTRAINED' -Prefix $tag {
        $rows = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties $acctProps `
            -Filter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
        $hits = @($rows | Where-Object { Test-UnconstrainedNonDc $_ })
        $names = ($hits | Select-Object -First 5 | ForEach-Object { [string](Get-EntryValue $_ 'samaccountname') }) -join ','
        if ($hits.Count -gt 0) { return (New-PostureResult 'FAIL' ('count=' + $hits.Count + ' sample=' + $names)) }
        New-PostureResult 'PASS' 'count=0 (DCs excluded)'
    }
    Invoke-PostureCheck 'AD-ADMINCOUNT' -Prefix $tag {
        $rows = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties @('distinguishedName') `
            -Filter '(&(objectCategory=person)(objectClass=user)(adminCount=1))')
        New-PostureResult 'INFO' ('count=' + (Measure-DistinctMember $rows))
    }
    $domSid = $null
    if ($dom) {
        try { $domSid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]](Get-EntryValue $dom 'objectsid'), 0)).Value } catch { }
    }
    Invoke-PostureCheck 'AD-DA-MEMBERS' -Prefix $tag {
        if (-not $domSid) { throw 'domain SID unreadable' }
        $g = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties @('distinguishedName') -Filter ('(objectSid=' + $domSid + '-512)'))
        if ($g.Count -eq 0) { return (New-PostureResult 'ERR' 'Domain Admins group not found') }
        $gdn = [string](Get-EntryValue $g[0] 'distinguishedname')
        $m = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties @('distinguishedName') `
            -Filter ('(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:=' + $gdn + '))'))
        $n = Measure-DistinctMember $m
        if ($n -gt 5) { return (New-PostureResult 'WARN' ('recursive_members=' + $n)) }
        New-PostureResult 'INFO' ('recursive_members=' + $n)
    }
    Invoke-PostureCheck 'AD-PROTECTED-USERS' -Prefix $tag {
        if (-not $domSid) { throw 'domain SID unreadable' }
        $g = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties @('distinguishedName') -Filter ('(objectSid=' + $domSid + '-525)'))
        if ($g.Count -eq 0) { return (New-PostureResult 'WARN' 'Protected Users group absent (pre-2012R2 domain)') }
        $gdn = [string](Get-EntryValue $g[0] 'distinguishedname')
        $m = @(Invoke-LdapSearch -SearchRoot $dn -TimeoutSeconds $t -Properties @('distinguishedName') `
            -Filter ('(memberOf:1.2.840.113556.1.4.1941:=' + $gdn + ')'))
        $n = Measure-DistinctMember $m
        if ($n -eq 0) { return (New-PostureResult 'WARN' 'Protected Users has no members') }
        New-PostureResult 'PASS' ('members=' + $n)
    }
    Invoke-PostureCheck 'AD-FUNC-LEVEL' -Prefix $tag {
        $d = [int]$rootDse.domainFunctionality
        $f = [int]$rootDse.forestFunctionality
        if ($d -lt 7) { return (New-PostureResult 'WARN' ('domainFunctionality=' + $d + ' forestFunctionality=' + $f)) }
        New-PostureResult 'PASS' ('domainFunctionality=' + $d + ' forestFunctionality=' + $f)
    }
    Invoke-PostureCheck 'AD-LDAP-SIGNING' -Prefix $tag {
        $si = $null
        $cb = $null
        if ($Context.IsDC) {
            $si = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
            $cb = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
            if ($null -eq $si) { $si = 1 }
        }
        Resolve-LdapSigningStatus $si $cb
    }
    Invoke-PostureCheck 'AD-TRUSTS' -Prefix $tag {
        $rows = @(Invoke-LdapSearch -SearchRoot ('CN=System,' + $dn) -TimeoutSeconds $t -Properties @('name', 'trustDirection') `
            -Filter '(objectClass=trustedDomain)')
        $desc = ($rows | Select-Object -First 5 | ForEach-Object { [string](Get-EntryValue $_ 'name') + ':' + [string](Get-EntryValue $_ 'trustdirection') }) -join ','
        New-PostureResult 'INFO' ('count=' + $rows.Count + ' trusts=' + $desc)
    }
    Invoke-PostureCheck 'AD-LAPS-SCHEMA' -Prefix $tag {
        $rows = @(Invoke-LdapSearch -SearchRoot $rootDse.schemaNamingContext -TimeoutSeconds $t -Properties @('lDAPDisplayName') `
            -Filter '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))')
        $names = ($rows | ForEach-Object { [string](Get-EntryValue $_ 'ldapdisplayname') }) -join ','
        if ($rows.Count -gt 0) { return (New-PostureResult 'PASS' ('schema=' + $names)) }
        New-PostureResult 'WARN' 'no LAPS attributes in schema'
    }
}

# ------------------------------------------------------------------ main
function Invoke-HostPosture {
    param([switch]$AdChecks, [int]$LdapTimeoutSeconds = 30)
    Write-Output '== aranum host posture (windows) =='
    if (-not (Test-IsWindowsOS)) {
        foreach ($id in ($script:AranumHostCheckIds + $script:AranumAdCheckIds)) { Write-PostureLine $id 'NA' 'not windows' }
        return
    }
    $ctx = Get-PostureContext
    Invoke-HostPostureChecks -Context $ctx
    Invoke-AdPostureChecks -Enabled:$AdChecks -Context $ctx -TimeoutSeconds $LdapTimeoutSeconds
}

if ($LibraryOnly) { return }
Invoke-HostPosture -AdChecks:$AdChecks -LdapTimeoutSeconds $LdapTimeoutSeconds
