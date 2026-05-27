<#
.SYNOPSIS
    Local-only sanity check: does THIS host have the SeImpersonate token
    privilege (and SeAssignPrimaryToken, SeTcb, SeDebug) as the current
    user, and is the impersonation-chain to SYSTEM realistic?

.DESCRIPTION
    Used as a precondition check before the operator decides to run
    PrintSpoofer / RoguePotato / GodPotato style chains. Confirms:
      - Current user holds SeImpersonate (often granted to service accounts
        like IUSR_*, NT SERVICE\*, MSSQL service account, etc.)
      - The Print Spooler service is exploitable (PrintSpoofer)
      - DCOM is reachable locally (RoguePotato)

.NOTES
    Per the description in REVIEW-001 §2.7: local-only. NEVER fires the
    actual coercion against arbitrary targets.
#>
[CmdletBinding()]
param()

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Warn($t) { Write-Host "[!] $t" -ForegroundColor Yellow }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "LOCAL COERCED-AUTH ESCALATION PRECONDITIONS"

# Token privileges via whoami /priv
$priv = (whoami /priv) -join "`n"
$want = @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege','SeDebugPrivilege')
$haveImp = $false
foreach ($p in $want) {
    if ($priv -match "$p.*Enabled") {
        Hit "$p (ENABLED) — escalation primitive available"
        if ($p -eq 'SeImpersonatePrivilege') { $haveImp = $true }
    } elseif ($priv -match $p) {
        Miss "$p (disabled — can still be enabled via NtAdjustToken)"
    }
}

# Spooler — PrintSpoofer chain
$spooler = (Get-Service Spooler -ErrorAction SilentlyContinue).Status
"Spooler: $spooler"
if ($haveImp -and $spooler -eq 'Running') {
    Hit "CRITICAL: SeImpersonate + Spooler running — PrintSpoofer chain to SYSTEM viable."
    "  -> Run: PrintSpoofer.exe -c 'cmd /c whoami > C:\Windows\Temp\who.txt'"
}

# DCOM — RoguePotato/RemotePotato0 chain
$dcom = (Get-CimInstance Win32_DCOMApplicationSetting -ErrorAction SilentlyContinue).Count
"DCOM applications enumerable: $dcom"
if ($haveImp -and $dcom -gt 0) {
    Hit "HIGH: SeImpersonate + DCOM reachable — RoguePotato / GodPotato chain candidates."
}

# WebDAV redirector — JuicyPotatoNG dependency
$webdav = (Get-Service WebClient -ErrorAction SilentlyContinue).Status
"WebClient (WebDAV): $webdav"

Hdr "NOTES"
"This script ONLY enumerates local preconditions. Per CLAUDE.md §9 invariant 1"
"and the REVIEW-001 §2.7 design note, it does NOT fire any coercion chain."
"The operator runs the actual chain via PrintSpoofer.exe / GodPotato.exe / etc."
