<#
.SYNOPSIS
    Enumerate named pipes; flag ones whose ACL permits Everyone / Authenticated
    Users / current user WRITE — often an escalation surface (impersonation
    via the pipe server's identity).

.DESCRIPTION
    Many services expose named pipes for IPC. If the pipe's ACL is permissive
    AND the pipe server runs as SYSTEM, an unprivileged user can connect,
    impersonate the calling thread, and inherit SYSTEM token via
    ImpersonateNamedPipeClient (requires SeImpersonate — which most service
    accounts have).

.NOTES
    Authorized testing only. Read-only enumeration of the pipe ACL — no
    pipe creation, no impersonation attempted.
#>
[CmdletBinding()]
param()

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "NAMED PIPES — ACL audit"

$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$mySids  = $current.Groups | ForEach-Object {
    try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $null }
}
$mySids += $current.Name

# Enumerate pipes via Get-ChildItem on \\.\pipe\
$pipes = Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction SilentlyContinue
"Pipes enumerated: $($pipes.Count)"
""

$writable = 0
foreach ($p in $pipes) {
    try {
        $acl = Get-Acl -LiteralPath "\\.\pipe\$($p.Name)" -ErrorAction Stop
    } catch { continue }
    foreach ($ace in $acl.Access) {
        $id = $ace.IdentityReference.Value
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $writes = $ace.FileSystemRights -match 'Write|FullControl|Modify|ChangePermissions|TakeOwnership'
        if (-not $writes) { continue }
        # Match against current user / their groups / well-known unprivileged principals
        $unprivileged = $id -match 'Everyone|Authenticated Users|Users|INTERACTIVE|NETWORK' -or
                        ($mySids -contains $id)
        if ($unprivileged) {
            Hit "WRITABLE PIPE: $($p.Name) — $($ace.FileSystemRights) granted to $id"
            $writable++
            break
        }
    }
}

""
"Writable pipes (to current user / Everyone / Auth Users): $writable"
if ($writable -gt 0) {
    Hit "HIGH: at least one pipe writable — if the server runs as SYSTEM and has SeImpersonate, this is escalation."
    "Operator next step:"
    "  - Connect to the pipe and check the server's identity (Get-NamedPipeServerInstance / Sysinternals pipelist.exe -accepteula)."
    "  - If SYSTEM-owned + you have SeImpersonate, RoguePotato/PrintSpoofer-class chains apply."
}
