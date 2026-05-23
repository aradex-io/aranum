<#
.SYNOPSIS
    Identify services the current user can modify (privesc to service account).
.DESCRIPTION
    Three classes:
      1. Service DACL allows SERVICE_CHANGE_CONFIG / SERVICE_ALL_ACCESS  -> sc.exe config <svc> binPath=...
      2. Service binary permissions allow Modify/Write                  -> overwrite binary
      3. Service registry key permissions allow FullControl/Write       -> set ImagePath
#>
[CmdletBinding()]
param()

function Get-CurrentSids {
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sids = @($ident.User.Value)
    $ident.Groups | ForEach-Object { $sids += $_.Value }
    return $sids
}
$mySids = Get-CurrentSids
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name

function Test-CanWrite($path) {
    if (-not (Test-Path $path)) { return $false }
    try { $acl = Get-Acl $path } catch { return $false }
    foreach ($a in $acl.Access) {
        if ($a.AccessControlType -ne 'Allow') { continue }
        if ($a.FileSystemRights -notmatch 'Modify|FullControl|Write') { continue }
        try { $sid = (New-Object Security.Principal.NTAccount($a.IdentityReference)).Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if ($mySids -contains $sid) { return @($true, $a.IdentityReference.Value) }
    }
    return @($false, $null)
}

Write-Host "=== Modifiable service binaries ===" -ForegroundColor Cyan
Get-CimInstance Win32_Service | ForEach-Object {
    $exe = ($_.PathName -replace '^"([^"]+)".*','$1') -replace '^([^\s]+).*','$1'
    if ($exe -and (Test-Path $exe)) {
        $r = Test-CanWrite $exe
        if ($r[0]) {
            Write-Host "[+] $($_.Name) | binary=$exe | granted-to=$($r[1]) | runas=$($_.StartName)" -ForegroundColor Green
        }
    }
}

Write-Host "`n=== Modifiable service registry keys ===" -ForegroundColor Cyan
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
    $key = $_.PSPath
    try { $acl = Get-Acl -Path $key -ErrorAction Stop } catch { return }
    foreach ($a in $acl.Access) {
        if ($a.AccessControlType -ne 'Allow') { continue }
        if ($a.RegistryRights -notmatch 'FullControl|SetValue|WriteKey') { continue }
        try { $sid = (New-Object Security.Principal.NTAccount($a.IdentityReference)).Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if ($mySids -contains $sid) {
            Write-Host "[+] $($_.PSChildName) granted $($a.RegistryRights) to $($a.IdentityReference)" -ForegroundColor Green
        }
    }
}

Write-Host "`n=== Service DACL (sc.exe sdshow) — non-builtin services ===" -ForegroundColor Cyan
Get-Service | Where-Object { $_.Status -ne $null } | ForEach-Object {
    $name = $_.Name
    $sd = & sc.exe sdshow $name 2>$null
    if ($sd -match 'WD' -or $sd -match 'BU' -or $sd -match 'AU') {
        # Crude flag — WD=World, BU=Built-in Users, AU=Authenticated Users in SDDL
        Write-Host "[?] $name SDDL contains broad principal: $sd" -ForegroundColor Yellow
    }
}
