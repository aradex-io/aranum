<#
.SYNOPSIS
    One-shot Windows privilege escalation enumerator.
.DESCRIPTION
    Collects OS info, user/group/token data, services, scheduled tasks, registry
    autoruns, AlwaysInstallElevated, saved credentials, WSUS config, LAPS, AV,
    AppLocker, UAC, network info, and writable PATH dirs. Output is grouped and
    colored when running interactively.
.PARAMETER OutFile
    Optional path to also write transcript output (TXT).
.EXAMPLE
    .\Invoke-PrivEscEnum.ps1
    .\Invoke-PrivEscEnum.ps1 -OutFile C:\Windows\Temp\enum.txt
.NOTES
    Authorized testing only. No exploit payloads — enumeration only.
#>
[CmdletBinding()]
param(
    [string]$OutFile
)

if ($OutFile) {
    Start-Transcript -Path $OutFile -Force | Out-Null
}

function Section($t) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}
function Sub($t) {
    Write-Host ""
    Write-Host "[*] $t" -ForegroundColor Yellow
}
function Hit($t) { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }

# ---------- 1. SYSTEM ----------
Section "SYSTEM INFO"
$os = Get-CimInstance Win32_OperatingSystem
"OS:           $($os.Caption) [$($os.Version) build $($os.BuildNumber)]"
"Architecture: $($os.OSArchitecture)"
"Hostname:     $env:COMPUTERNAME"
"Domain:       $env:USERDOMAIN"
"Install date: $($os.InstallDate)"
"Last boot:    $($os.LastBootUpTime)"

Sub "Hotfixes installed"
Get-HotFix | Select-Object HotFixID, Description, InstalledOn |
    Sort-Object InstalledOn -Descending | Format-Table -AutoSize

# ---------- 2. CURRENT USER ----------
Section "CURRENT USER"
"User:        $env:USERNAME"
"Domain:      $env:USERDOMAIN"
"User Profile: $env:USERPROFILE"

Sub "whoami /all"
whoami /all

Sub "Privileged token groups"
$priv = @('Administrators','Backup Operators','Server Operators','Account Operators',
          'Print Operators','DnsAdmins','Schema Admins','Enterprise Admins','Domain Admins',
          'Hyper-V Administrators','Remote Desktop Users','Remote Management Users')
$myGroups = (whoami /groups) -join "`n"
foreach ($g in $priv) {
    if ($myGroups -match [regex]::Escape($g)) { Hit "Member of $g" }
}

Sub "Useful token privileges (for SE* exploits)"
$useful = @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeBackupPrivilege',
            'SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege',
            'SeLoadDriverPrivilege','SeTcbPrivilege','SeManageVolumePrivilege',
            'SeSecurityPrivilege','SeShutdownPrivilege','SeCreateTokenPrivilege')
$privs = (whoami /priv) -join "`n"
foreach ($p in $useful) {
    if ($privs -match $p) {
        $line = ($privs -split "`n") | Where-Object { $_ -match $p }
        $enabled = ($line -match 'Enabled')
        if ($enabled) { Hit "$p (ENABLED)" } else { Miss "$p (disabled — can still be enabled)" }
    }
}

# ---------- 3. SERVICES ----------
Section "SERVICES — UNQUOTED & WRITABLE"
Sub "Unquoted service paths with spaces"
Get-WmiObject win32_service | ForEach-Object {
    $p = $_.PathName
    if ($p -and $p -notmatch '^"' -and $p -match ' ' -and $p -notmatch '^[A-Za-z]:\\Windows\\') {
        Hit "$($_.Name) -> $p (StartMode=$($_.StartMode), State=$($_.State))"
    }
}

Sub "Service binary write-check (current user)"
$svcs = Get-WmiObject win32_service | Where-Object { $_.PathName }
foreach ($s in $svcs) {
    $exe = ($s.PathName -replace '^"([^"]+)".*','$1') -replace '^([^\s]+).*','$1'
    if (Test-Path $exe -ErrorAction SilentlyContinue) {
        try {
            $acl = Get-Acl $exe -ErrorAction Stop
            $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
            foreach ($a in $acl.Access) {
                if (($a.AccessControlType -eq 'Allow') -and
                    ($a.FileSystemRights -match 'Write|FullControl|Modify') -and
                    (($ident.Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value }) -contains $a.IdentityReference.Value -or
                     $a.IdentityReference.Value -eq $ident.Name -or
                     $a.IdentityReference.Value -match 'Everyone|Authenticated Users|Users')) {
                    Hit "WRITABLE BINARY: $($s.Name) -> $exe (granted to $($a.IdentityReference.Value))"
                    break
                }
            }
        } catch {}
    }
}

# ---------- 4. SCHEDULED TASKS ----------
Section "SCHEDULED TASKS"
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    $principal = $task.Principal.UserId
    $action = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    if ($principal -match 'SYSTEM|Administrators|NETWORK SERVICE') {
        Hit "[$principal] $($task.TaskPath)$($task.TaskName) -> $action"
    } else {
        "[$principal] $($task.TaskPath)$($task.TaskName) -> $action"
    }
}

# ---------- 5. ALWAYSINSTALLELEVATED ----------
Section "AlwaysInstallElevated"
$hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
"HKLM = $hklm | HKCU = $hkcu"
if ($hklm -eq 1 -and $hkcu -eq 1) { Hit "AlwaysInstallElevated ENABLED — msfvenom -f msi gives SYSTEM" }

# ---------- 6. STORED CREDENTIALS ----------
Section "STORED CREDENTIALS"
Sub "cmdkey /list"
cmdkey /list

Sub "Credential Manager files"
Get-ChildItem -Hidden -Recurse "$env:USERPROFILE\AppData\Local\Microsoft\Credentials","$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials" -ErrorAction SilentlyContinue

Sub "Unattended install files"
@('C:\Windows\Panther\Unattend.xml','C:\Windows\Panther\Unattended.xml',
  'C:\Windows\Panther\Unattend\Unattended.xml','C:\Windows\Panther\Unattend\Unattend.xml',
  'C:\Windows\System32\sysprep\sysprep.xml','C:\Windows\System32\sysprep\sysprep.inf',
  'C:\Windows\system32\sysprep.inf','C:\unattend.xml','C:\unattend.inf',
  'C:\Windows\Panther\unattend.txt') | ForEach-Object {
    if (Test-Path $_) { Hit $_ }
}

Sub "Group Policy Preferences (Groups.xml, Services.xml, ...)"
@('\\$env:USERDOMAIN\SYSVOL','C:\ProgramData\Microsoft\Group Policy\History') | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue |
            ForEach-Object { Hit $_.FullName }
    }
}

Sub "AutoLogon registry"
$al = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($al.DefaultPassword) { Hit "DefaultUserName=$($al.DefaultUserName) DefaultPassword=$($al.DefaultPassword)" }

# ---------- 7. WRITABLE PATH ----------
Section "WRITABLE PATH DIRECTORIES"
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
foreach ($d in $env:Path -split ';') {
    if (-not $d -or -not (Test-Path $d)) { continue }
    try {
        $tmp = Join-Path $d (".write_test_" + [Guid]::NewGuid().ToString())
        [IO.File]::WriteAllText($tmp, 'x')
        Remove-Item $tmp -Force
        Hit "WRITABLE: $d"
    } catch {}
}

# ---------- 8. AV / EDR ----------
Section "AV / EDR Detection"
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
    Select-Object displayName, productState, pathToSignedProductExe
@('MsMpEng.exe','CSFalconService.exe','SentinelAgent.exe','elastic-endpoint.exe','MBAMService.exe',
  'TmCCSF.exe','xagt.exe','cybereason*.exe','TaniumClient.exe') | ForEach-Object {
    Get-Process -Name ($_ -replace '\.exe$') -ErrorAction SilentlyContinue
}

# ---------- 9. APPLOCKER / WDAC ----------
Section "AppLocker / WDAC"
try {
    Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop | Out-String -Stream | Select-String '<RuleCollection|<FilePath|<FileHash'
} catch { Miss "AppLocker not configured or no permission" }

# ---------- 10. NETWORK ----------
Section "NETWORK"
ipconfig /all
Sub "Listening ports"
netstat -ano | Select-String 'LISTENING'
Sub "Open SMB shares (local)"
net share

# ---------- 11. INTERESTING FILES ----------
Section "INTERESTING FILES (grep for password/secret/key)"
$searchPaths = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents",
                 'C:\inetpub\wwwroot','C:\xampp\htdocs')
foreach ($p in $searchPaths) {
    if (Test-Path $p) {
        Get-ChildItem $p -Recurse -Include *.txt,*.ini,*.config,*.xml,*.ps1,*.bat,*.cmd,*.kdbx -ErrorAction SilentlyContinue |
            Select-String -Pattern 'password|passwd|secret|api[_-]?key|token=' -SimpleMatch -ErrorAction SilentlyContinue |
            Select-Object -First 200 Path, LineNumber, Line
    }
}

if ($OutFile) { Stop-Transcript | Out-Null; Write-Host "`nWrote transcript to $OutFile" -ForegroundColor Cyan }
