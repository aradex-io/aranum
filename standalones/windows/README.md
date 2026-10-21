# Windows standalones

**Authorized testing only. Read-only enumeration** (CLAUDE.md section 1 / section 9).
Self-contained PowerShell privilege-escalation / credential-exposure enumeration scripts —
no dependencies, no installation, nothing written to the target.

## How to run them (read this first)

> **Do not double-click a `.ps1`.** On Windows, double-clicking a `.ps1` never *runs* it —
> the shell only *opens* it in an editor or a document viewer (the "can't open this file"
> message). Run it one of these ways instead:

- **From a PowerShell console** (recommended):

  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-PrivEscEnum.ps1
  ```

  `-ExecutionPolicy Bypass` here applies only to that single process — nothing system-wide
  is changed. Equivalently, run `Set-ExecutionPolicy -Scope Process Bypass` once for the
  current session, then call the scripts normally.

- **Right-click the `.ps1` → "Run with PowerShell"** for a quick default run.

- `enum.bat` needs no PowerShell at all — double-click or run it when PowerShell is blocked
  or restricted (`enum.bat > out.txt`).

Do **not** paste raw multi-line script text into an interactive prompt — line-by-line paste
can misfire on `if { }` blocks. Always run via `-File` (above).

### Compatibility

Compatible with the **Windows PowerShell 5.1** that ships in-box on Windows 10/11 and with
**PowerShell 7+** (`pwsh`). The scripts are plain ASCII, so Windows PowerShell 5.1 parses
them correctly regardless of the host's active code page (a BOM-less script with non-ASCII
characters is misread as ANSI by 5.1 and fails with spurious `if` / `}` parse errors — these
scripts avoid that by staying ASCII-only).

## What's here

| Script | Purpose |
|---|---|
| `Invoke-PrivEscEnum.ps1` | All-in-one privesc sweep: token privileges, service misconfig, AlwaysInstallElevated, WSUS-over-HTTP, UAC/token-filter, WDigest, SCCM NAA, plus AD-depth checks and thick-client creds when domain-joined. Start here. |
| `Get-TokenPrivileges.ps1` | Token privilege audit (`SeImpersonate`, `SeBackup`, etc.). |
| `Test-CoercedAuth.ps1` | Local coercion / potato preconditions (SeImpersonate + Spooler/DCOM/WebDAV). Enumerates only — fires no chain. |
| `Get-ServiceMisconfig.ps1` | Service DACL / misconfiguration (`sc.exe sdshow`). |
| `Get-UnquotedServices.ps1` | Unquoted service-path detection. |
| `Get-AlwaysInstallElevated.ps1` | `AlwaysInstallElevated` MSI policy check. |
| `Get-ScheduledTasks.ps1` | Scheduled-task enumeration (writable task binaries). |
| `Get-WritablePathDirs.ps1` | Writable directories on `%PATH%` (DLL/binary planting surface). |
| `Get-NamedPipes.ps1` | Named-pipe ACL audit (writable pipes -> impersonation surface). |
| `Get-ADCSMisconfig.ps1` | AD CS template misconfig (ESC1 / ESC2 / ESC4). |
| `Get-LAPSPassword.ps1` | LAPS password readability as the current user. |
| `Get-GPPCPassword.ps1` | Group Policy Preferences `cpassword` sweep. |
| `Get-PetitPotamSignals.ps1` | Coercion / relay preconditions (SMB & LDAP signing, coerce-vector services, AD CS HTTP enrollment). |
| `Get-PrintNightmare.ps1` | PrintNightmare (CVE-2021-34527) configuration detection. |
| `Get-DPAPIBlobs.ps1` | Locate DPAPI-protected blobs (presence only — no decryption). |
| `Get-StoredCreds.ps1` | Stored / cached credential enumeration. |
| `Get-ThickClientEnum.ps1` | Thick-client credential-at-rest: PuTTY / WinSCP / RDP / VPN / browser / Electron. |
| `enum.bat` | No-PowerShell batch enumeration for when PS is blocked. |

All `Get-*` / `Invoke-*` scripts carry comment-based help — run `Get-Help .\Script.ps1 -Full`.
