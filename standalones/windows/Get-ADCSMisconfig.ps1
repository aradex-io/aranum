<#
.SYNOPSIS
    Local ADCS ESC1/ESC2/ESC4 detection via ADSI (no external dependencies).
    Walks the PKI configuration container and flags certificate templates
    whose ACL or attributes match the documented escalation primitives.

.DESCRIPTION
    ESC1: template allows ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU +
          Authenticated Users (or other broad principal) enroll right
    ESC2: template has Any Purpose EKU OR No EKU — same broad enrollment
    ESC4: vulnerable ACL on a template (WriteOwner / WriteDacl / Full Control to
          a non-admin principal — means an unprivileged user can modify the
          template into an ESC1-vulnerable state)

    This script is the no-deps Linux-attacker fallback for when Certipy can't
    run from the operator's box. Output mirrors the salient fields Certipy
    flags so report.py's existing ESC* rules pick it up.

.NOTES
    Authorized testing only. Per ADR-004 D4: read-only — no template
    modification, no certificate issuance attempted.
#>
[CmdletBinding()]
param([switch]$LibraryOnly)

function Hit($t) { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Hdr($t) { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                   Write-Host "  $t" -ForegroundColor Cyan
                   Write-Host ("="*70) -ForegroundColor Cyan }

$script:EnrollExtendedRight = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'

function Test-LowPrivilegePrincipal($IdentityReference) {
    $text = $IdentityReference.ToString()
    try {
        $sid = $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        $sid = $text
    }
    return ($sid -eq 'S-1-1-0' -or $sid -eq 'S-1-5-11' -or
            $sid -eq 'S-1-5-32-545' -or $sid -match '-513$' -or
            $text -match '(^|\\)(Everyone|Authenticated Users|Domain Users|Users)$')
}

function Test-LowPrivilegeEnrollment($SecurityDescriptor) {
    $allowed = $false
    $denied = $false
    foreach ($ace in @($SecurityDescriptor.Access)) {
        if (-not (Test-LowPrivilegePrincipal $ace.IdentityReference)) { continue }
        $rights = $ace.ActiveDirectoryRights.ToString()
        $genericAll = $rights -match 'GenericAll'
        $extended = $rights -match 'ExtendedRight'
        if (-not $genericAll -and -not $extended) { continue }
        if ($extended -and -not $genericAll) {
            $objectType = [Guid]$ace.ObjectType
            if ($objectType -ne [Guid]::Empty -and $objectType -ne $script:EnrollExtendedRight) { continue }
        }
        if ($ace.AccessControlType.ToString() -eq 'Deny') { $denied = $true }
        elseif ($ace.AccessControlType.ToString() -eq 'Allow') { $allowed = $true }
    }
    # Conservative effective-right approximation: any applicable broad deny
    # suppresses the allow, preventing admin-only/restricted templates from
    # becoming low-privilege ESC1/2 positives.
    return ($allowed -and -not $denied)
}

if ($LibraryOnly) { return }

Hdr "AD CS TEMPLATE MISCONFIGURATION (ESC1 / ESC2 / ESC4)"

try {
    $root = [ADSI]"LDAP://RootDSE"
    $configNC = $root.configurationNamingContext
} catch {
    Write-Host "[!] Cannot read configurationNamingContext — not domain-joined or no LDAP reach" -ForegroundColor Red
    exit 1
}

$templatesPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
"Search: $templatesPath"
""

try {
    $templates = [ADSI]$templatesPath
} catch {
    Write-Host "[!] Cannot read Certificate Templates container: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# OID -> human-readable EKU map (subset that matters for escalation)
$EKU = @{
    "1.3.6.1.5.5.7.3.2"     = "Client Authentication"
    "1.3.6.1.5.2.3.4"       = "PKINIT Client Authentication"
    "1.3.6.1.4.1.311.20.2.2"= "Smart Card Logon"
    "2.5.29.37.0"           = "Any Purpose"
    "1.3.6.1.5.5.7.3.1"     = "Server Authentication"
}

# msPKI-Certificate-Name-Flag — bit 0x00000001 = ENROLLEE_SUPPLIES_SUBJECT
$ESC1_BIT = 0x1
$CT_FLAG_PEND_ALL_REQUESTS = 0x2   # manager-approval gate — approval-required != ESC1

$esc1_hits = 0
$esc2_hits = 0
$esc4_hits = 0

foreach ($tmpl in $templates.Children) {
  try {
    $name      = $tmpl.cn[0]
    $nameFlag  = [int]($tmpl."msPKI-Certificate-Name-Flag"[0] -bor 0)
    $ekuList   = @($tmpl.pkiExtendedKeyUsage)
    $enrollSig = [int]($tmpl."msPKI-RA-Signature"[0] -bor 0)
    $enrollFlag = [int]($tmpl."msPKI-Enrollment-Flag"[0] -bor 0)
    $needsApproval = ($enrollFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -ne 0

    # Resolve EKUs to friendly names
    $ekuFriendly = $ekuList | ForEach-Object { $EKU[$_] ; if (-not $EKU.ContainsKey($_)) { $_ } }
    $hasClientAuth = ($ekuFriendly -contains "Client Authentication") -or
                     ($ekuFriendly -contains "PKINIT Client Authentication") -or
                     ($ekuFriendly -contains "Smart Card Logon")
    $hasAnyPurpose = ($ekuFriendly -contains "Any Purpose") -or ($ekuList.Count -eq 0)

    # Read DACL — surfaces non-admin enroll + writable-template (ESC4)
    $sd = $tmpl.psbase.ObjectSecurity
    $acl = @()
    foreach ($a in $sd.Access) {
        $acl += "$($a.IdentityReference) $($a.ActiveDirectoryRights)"
    }
    $broadEnroll = Test-LowPrivilegeEnrollment $sd

    # ESC1 — ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + RA signature == 0 AND
    # not gated by manager approval (an approval-required template isn't ESC1).
    if (($nameFlag -band $ESC1_BIT) -and $hasClientAuth -and $enrollSig -eq 0 -and
        (-not $needsApproval) -and $broadEnroll) {
        Hit "ESC1 (Vulnerable): $name (ENROLLEE_SUPPLIES_SUBJECT + Client Auth, no enrollment-agent signature required, no manager approval)"
        $esc1_hits++
    }
    # ESC2 — Any Purpose / No EKU on a template that anyone-Authenticated can enroll
    if ($hasAnyPurpose) {
        if ($broadEnroll) {
            Hit "ESC2 (Vulnerable): $name (Any Purpose / No EKU + broad enroll right)"
            $esc2_hits++
        }
    }
    # ESC4 — WriteOwner / WriteDacl / GenericWrite granted to non-admin principal
    foreach ($a in $sd.Access) {
        $idStr = $a.IdentityReference.ToString()
        if ($idStr -match "Administrators|Enterprise Admins|Domain Admins|SYSTEM|CREATOR OWNER") { continue }
        if ($a.ActiveDirectoryRights -match "WriteOwner|WriteDacl|GenericWrite|GenericAll") {
            Hit "ESC4 (Vulnerable): $name granted $($a.ActiveDirectoryRights) to $idStr"
            $esc4_hits++
            break
        }
    }
  } catch {
    # One unreadable/odd template SD must not abort the whole enumeration.
    Miss "template '$($tmpl.cn)' skipped: $($_.Exception.Message)"
  }
}

""
"ESC1 vulnerable: $esc1_hits"
"ESC2 vulnerable: $esc2_hits"
"ESC4 vulnerable: $esc4_hits"
