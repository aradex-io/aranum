<#
.SYNOPSIS
    Check PrintNightmare (CVE-2021-34527 / CVE-2021-1675) mitigation state on
    this host. Detection only — does NOT attempt to add a driver.

.DESCRIPTION
    PrintNightmare exploits the Print Spooler's RpcAddPrinterDriverEx /
    RpcAsyncAddPrinterDriver to load a malicious DLL as SYSTEM. MS-supplied
    mitigations:
      - Spooler service stopped
      - HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
            RestrictDriverInstallationToAdministrators = 1
            NoWarningNoElevationOnInstall              = 0
      - HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers
            DisableWebPnPDownload                      = 1

    A host that passes all three is patched-by-policy. Anything else is a
    candidate for exploitation.

.NOTES
    Authorized testing only. Detection only — no driver add attempted.
#>
[CmdletBinding()]
param()

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Warn($t) { Write-Host "[!] $t" -ForegroundColor Yellow }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "PRINTNIGHTMARE MITIGATION STATE"

$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if (-not $spooler) {
    Miss "Spooler service not present — host is not vulnerable"
    exit 0
}
"Spooler service: $($spooler.Status) (StartType=$($spooler.StartType))"

$pap = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -ErrorAction SilentlyContinue
$prn = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -ErrorAction SilentlyContinue

$restrict = $pap.RestrictDriverInstallationToAdministrators
$noWarn   = $pap.NoWarningNoElevationOnInstall
$updPrompt= $pap.UpdatePromptSettings
$webPnp   = $prn.DisableWebPnPDownload

"RestrictDriverInstallationToAdministrators: $restrict"
"NoWarningNoElevationOnInstall:              $noWarn"
"UpdatePromptSettings:                       $updPrompt"
"DisableWebPnPDownload:                      $webPnp"
""

$vulnerable = $false
if ($spooler.Status -eq 'Running') {
    if ($restrict -ne 1) {
        Warn "RestrictDriverInstallationToAdministrators != 1 — non-admin driver install possible"
        $vulnerable = $true
    }
    if ($noWarn -eq 1) {
        Warn "NoWarningNoElevationOnInstall = 1 — silent install"
        $vulnerable = $true
    }
    if (-not $vulnerable -and $restrict -eq 1) {
        Hit "MITIGATED: Spooler running, RestrictDriverInstall=1 — patched-by-policy"
    }
} else {
    Hit "MITIGATED: Spooler not running"
}

if ($vulnerable) {
    Warn "CRITICAL: PrintNightmare configuration is exploitable — see CVE-2021-34527 PoC chain"
}
