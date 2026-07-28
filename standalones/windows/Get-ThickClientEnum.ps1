<#
.SYNOPSIS
    Workstation / thick-client enumeration — installed apps, running GUI
    processes, and credentials/config AT REST. READ-ONLY.

.DESCRIPTION
    Targets the "roaming analyst workstation" surface that Invoke-PrivEscEnum's
    server-privesc checks skip: GUI thick clients and the connection profiles /
    saved sessions / credential blobs they leave on disk and in the registry.

    Enumerates, presence + path + why-it-matters only (NO decryption, NO
    exfiltration, NO writes — CLAUDE.md §9 invariant 1):
      * Installed apps (Uninstall registry keys + Program Files dirs)
      * Running GUI processes with window titles
      * PuTTY / pageant saved sessions, host keys, .ppk private keys
      * WinSCP saved sessions (registry + WinSCP.ini)
      * Saved .rdp files + cached RDP creds (cmdkey TERMSRV)
      * OpenVPN / Cisco AnyConnect / WireGuard profiles
      * Browser saved-login DBs (Chrome/Edge/Brave Login Data, Firefox
        logins.json) — PRESENCE ONLY, no decryption
      * Electron resources\app.asar + per-app config
      * Generic connection-string / credential patterns in %APPDATA% /
        %LOCALAPPDATA% app config trees (*.ini/*.xml/*.json/*.config)

    Findings are emitted to stdout (Write-Output) in the [+]/[-] style
    Invoke-PrivEscEnum.ps1 uses, so report.py's winenum rules ingest them.
    New finding-class markers are UPPERCASE THICKCLIENT-* prefixes.

.PARAMETER OutFile
    Optional path to also write output (TXT) via Tee-Object.

.EXAMPLE
    .\Get-ThickClientEnum.ps1
    .\Get-ThickClientEnum.ps1 -OutFile C:\Windows\Temp\thick.txt

.NOTES
    Authorized testing only. Read-only enumeration — no exploit payloads.
#>
[CmdletBinding()]
param(
    [string]$OutFile
)

# ---- emit helpers: Write-Output (data stream) so report.py ingests stdout ----
function Section($t) { Write-Output ""; Write-Output ("===[ {0} ]===" -f $t) }
function Hit($t)     { Write-Output ("[+] {0}" -f $t) }
function Miss($t)    { if ($VerbosePreference -eq 'Continue') { Write-Output ("[-] {0}" -f $t) } }

# Presence finding helper: emits "[+] MARKER: <path> — <why>" iff the path exists.
function Present($marker, $path, $why) {
    if ($path -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
        Hit ("{0}: {1} — {2}" -f $marker, $path, $why)
        return $true
    }
    return $false
}

$body = {

# ---------- 1. INSTALLED APPLICATIONS ----------
Section "INSTALLED APPLICATIONS (uninstall registry + Program Files)"
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$seen = @{}
foreach ($k in $uninstallKeys) {
    Get-ItemProperty $k -ErrorAction SilentlyContinue | ForEach-Object {
        $n = $_.DisplayName
        if ($n -and -not $seen.ContainsKey($n)) {
            $seen[$n] = $true
            $loc = if ($_.InstallLocation) { $_.InstallLocation } else { '' }
            Hit ("THICKCLIENT-APP: {0} {1} {2}" -f $n, $_.DisplayVersion, ($(if($loc){"($loc)"}else{''})))
        }
    }
}
foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if ($pf -and (Test-Path $pf)) {
        Get-ChildItem -LiteralPath $pf -Directory -ErrorAction SilentlyContinue |
            Select-Object -First 100 | ForEach-Object {
                if (-not $seen.ContainsKey($_.Name)) { $seen[$_.Name] = $true; Miss ("Program Files dir: {0}" -f $_.FullName) }
            }
    }
}

# ---------- 2. RUNNING GUI PROCESSES + WINDOW TITLES ----------
Section "RUNNING GUI PROCESSES (window titles)"
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowTitle } |
    ForEach-Object {
        Hit ("THICKCLIENT-APP: process {0} (pid {1}) window '{2}'" -f $_.ProcessName, $_.Id, $_.MainWindowTitle)
    }

# ---------- 3. PuTTY / pageant ----------
Section "PuTTY / pageant SAVED SESSIONS + KEYS"
Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $s = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        Hit ("THICKCLIENT-SAVED-SESSION: PuTTY '{0}' Host={1} User={2} ProxyUser={3} — saved SSH session (proxy creds may be present)" -f `
            [uri]::UnescapeDataString($_.PSChildName), $s.HostName, $s.UserName, $s.ProxyUsername)
    }
if (Test-Path 'HKCU:\Software\SimonTatham\PuTTY\SshHostKeys') {
    Hit "THICKCLIENT-SAVED-SESSION: HKCU\Software\SimonTatham\PuTTY\SshHostKeys — cached host keys reveal hosts this user has reached"
}
foreach ($base in @($env:USERPROFILE, "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")) {
    if ($base -and (Test-Path $base)) {
        Get-ChildItem -LiteralPath $base -Recurse -Filter '*.ppk' -ErrorAction SilentlyContinue -Depth 3 |
            Select-Object -First 20 | ForEach-Object {
                $enc = 'unknown'
                try { $enc = (Select-String -Path $_.FullName -Pattern 'Encryption:' -ErrorAction SilentlyContinue | Select-Object -First 1).Line } catch {}
                Hit ("THICKCLIENT-SSHKEY-AT-REST: {0} — PuTTY .ppk private key ({1}); convert with puttygen, feed to ssh-key-triage" -f $_.FullName, $enc)
            }
    }
}

# ---------- 4. WinSCP ----------
Section "WinSCP SAVED SESSIONS"
Get-ChildItem 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $s = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        Hit ("THICKCLIENT-SAVED-SESSION: WinSCP '{0}' Host={1} User={2} — Password field present={3} (weakly-encrypted, decryptable)" -f `
            [uri]::UnescapeDataString($_.PSChildName), $s.HostName, $s.UserName, [bool]$s.Password)
    }
foreach ($ini in @("$env:APPDATA\WinSCP.ini", "$env:USERPROFILE\WinSCP.ini")) {
    Present "THICKCLIENT-CRED-AT-REST" $ini "WinSCP.ini — saved sessions incl. weakly-encrypted passwords" | Out-Null
}

# ---------- 5. RDP saved files + cached creds ----------
Section "RDP FILES + CACHED CREDENTIALS"
Hit "THICKCLIENT-RDP-CREDS: enumerating cmdkey saved credentials (TERMSRV/* = cached RDP creds)"
try {
    (cmdkey /list 2>$null) | Select-String 'Target:|TERMSRV' | ForEach-Object { Write-Output ("    {0}" -f $_.Line.Trim()) }
} catch {}
foreach ($base in @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop", $env:USERPROFILE)) {
    if ($base -and (Test-Path $base)) {
        Get-ChildItem -LiteralPath $base -Recurse -Filter '*.rdp' -Force -ErrorAction SilentlyContinue -Depth 2 |
            Select-Object -First 20 | ForEach-Object {
                Hit ("THICKCLIENT-RDP-CREDS: {0} — saved .rdp (full address / username, prompt-for-credentials flag)" -f $_.FullName)
            }
    }
}
Present "THICKCLIENT-RDP-CREDS" "$env:LOCALAPPDATA\Microsoft\Remote Desktop\1.0\.rdp" "Remote Desktop store — cached connections" | Out-Null

# ---------- 6. VPN PROFILES ----------
Section "VPN PROFILES"
$vpnPaths = @(
    @{ M='THICKCLIENT-VPN-PROFILE'; P="$env:USERPROFILE\OpenVPN\config";                          W='OpenVPN user config — .ovpn incl. possible inline auth-user-pass' },
    @{ M='THICKCLIENT-VPN-PROFILE'; P="$env:ProgramFiles\OpenVPN\config";                          W='OpenVPN system config directory' },
    @{ M='THICKCLIENT-VPN-PROFILE'; P="$env:APPDATA\Cisco\Cisco AnyConnect Secure Mobility Client"; W='Cisco AnyConnect profile — server list, cached prefs' },
    @{ M='THICKCLIENT-VPN-PROFILE'; P="$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile"; W='AnyConnect XML profiles (ServerList)' },
    @{ M='THICKCLIENT-VPN-PROFILE'; P="$env:ProgramFiles\WireGuard\Data\Configurations";            W='WireGuard tunnel configs — PrivateKey/PresharedKey (DPAPI-wrapped)' },
    @{ M='THICKCLIENT-VPN-PROFILE'; P="$env:APPDATA\Fortinet\FortiClient";                          W='FortiClient config — saved VPN tunnels' }
)
foreach ($v in $vpnPaths) { Present $v.M $v.P $v.W | Out-Null }
foreach ($base in @("$env:USERPROFILE", "$env:USERPROFILE\Documents")) {
    if ($base -and (Test-Path $base)) {
        Get-ChildItem -LiteralPath $base -Recurse -Filter '*.ovpn' -ErrorAction SilentlyContinue -Depth 3 |
            Select-Object -First 20 | ForEach-Object { Hit ("THICKCLIENT-VPN-PROFILE: {0} — OpenVPN profile" -f $_.FullName) }
    }
}

# ---------- 7. BROWSER SAVED-LOGIN DBs (presence only) ----------
Section "BROWSER SAVED-LOGIN STORES (presence only, NO decryption)"
$browsers = @(
    @{ P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data";           W='Chrome Login Data (AES-GCM, key in Local State/DPAPI)' },
    @{ P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data";           W='Edge Login Data (AES-GCM, key in Local State/DPAPI)' },
    @{ P="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"; W='Brave Login Data (AES-GCM, DPAPI-wrapped key)' }
)
foreach ($b in $browsers) { Present "THICKCLIENT-BROWSER-LOGINDB" $b.P $b.W | Out-Null }
$ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ffProfiles) {
    Get-ChildItem -LiteralPath $ffProfiles -Recurse -Filter 'logins.json' -ErrorAction SilentlyContinue -Depth 2 |
        Select-Object -First 10 | ForEach-Object {
            Hit ("THICKCLIENT-BROWSER-LOGINDB: {0} — Firefox saved logins (needs key4.db + NSS)" -f $_.FullName)
        }
}

# ---------- 8. ELECTRON APPS ----------
Section "ELECTRON APPS (app.asar + config)"
$electronRoots = @("$env:LOCALAPPDATA\Programs", "$env:APPDATA", "$env:LOCALAPPDATA")
foreach ($r in $electronRoots) {
    if ($r -and (Test-Path $r)) {
        Get-ChildItem -LiteralPath $r -Recurse -Filter 'app.asar' -ErrorAction SilentlyContinue -Depth 3 |
            Select-Object -First 15 | ForEach-Object {
                Hit ("THICKCLIENT-ELECTRON: {0} — Electron app.asar; 'npx asar extract' for embedded API keys/endpoints" -f $_.FullName)
            }
    }
}

# ---------- 9. HARDCODED SECRETS IN APP CONFIG TREES ----------
Section "HARDCODED SECRETS IN %APPDATA% / %LOCALAPPDATA% CONFIG"
$configRoots = @($env:APPDATA, $env:LOCALAPPDATA)
$secretRe = 'password|passwd|secret|api[_-]?key|token\s*[=:]|connectionString|Data Source=.*Password='
# $script: scope so the cap persists across nested ForEach-Object child scopes.
$script:tcEmitted = 0
foreach ($r in $configRoots) {
    if (-not $r -or -not (Test-Path $r)) { continue }
    Get-ChildItem -LiteralPath $r -Recurse -Include '*.ini','*.xml','*.json','*.config' -ErrorAction SilentlyContinue -Depth 4 |
        Select-Object -First 400 | ForEach-Object {
            if ($script:tcEmitted -ge 60) { return }
            try {
                Select-String -Path $_.FullName -Pattern $secretRe -ErrorAction SilentlyContinue |
                    Select-Object -First 2 | ForEach-Object {
                        if ($script:tcEmitted -lt 60) {
                            $script:tcEmitted++
                            Hit ("THICKCLIENT-CONFIG-SECRET: {0}:{1}: {2}" -f $_.Path, $_.LineNumber, ($_.Line.Trim() -replace '\s+',' '))
                        }
                    }
            } catch {}
        }
}

Section "DONE"
Write-Output "Read-only thick-client sweep complete. Decrypt browser/VPN/WinSCP/DPAPI stores operator-side only (see Get-DPAPIBlobs.ps1, Get-StoredCreds.ps1). Feed .ppk keys to ssh-key-triage.py."

}  # end $body

if ($OutFile) {
    & $body | Tee-Object -FilePath $OutFile
} else {
    & $body
}
