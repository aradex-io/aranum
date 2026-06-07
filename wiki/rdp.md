---
service: rdp
title: RDP (Remote Desktop Protocol)
ports: 3389
aliases: ms-wbt-server, terminal-services
---

# RDP — quick wins

**When you see it:** 3389/tcp open and `rdp-enum-encryption` shows `Security layer: RDP`
(no NLA) → pre-authentication attack surface exists; or NLA is present but valid creds
are in scope → `xfreerdp` gives a GUI shell.

> Authorized testing only. Spray attacks risk account lockout — always read the password
> policy first. Steps marked ✏️ authenticate to or write state on the target.

## Triage (read-only)
```sh
nmap -Pn -p3389 --script rdp-enum-encryption,rdp-ntlm-info H
nxc rdp H -u '' -p ''                          # NLA check + banner
rdp-sec-check.pl H 2>/dev/null                 # detailed protocol/cipher audit
```

## Quick wins

### NLA / encryption level recon
```sh
nmap -Pn -p3389 --script rdp-enum-encryption H
```
*Why:* Identifies whether Network Level Authentication is enforced. Without NLA, the
logon screen is reached pre-auth, widening the attack surface (BlueKeep, credential
spray without lockout on some old builds). `rdp-ntlm-info` also leaks NetBIOS/AD
domain names without credentials.

### BlueKeep check — CVE-2019-0708
```sh
rdpscan H                          # github.com/robertdavidgraham/rdpscan
# Or: msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS H; run; exit"
```
*Why:* BlueKeep is a pre-auth RCE in Windows 7 / Server 2008 R2 via the RDP channel
`MS_T120`. `rdpscan` reports `VULNERABLE`, `SAFE`, or `UNKNOWN`. No reliable nmap NSE
exists for this — use rdpscan or the Metasploit auxiliary (detection only; exploitation
is a separate scope decision). Note: `smb-vuln-ms12-020` (in enum-rdp.sh) checks a
different CVE.

### Credential validation ✏️
```sh
nxc rdp H -u U -p P                           # single cred check
nxc rdp H -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```
*Why:* nxc validates credentials against RDP's NTLMv2 challenge without opening a full
session — faster and less noisy than a full xfreerdp login. `--no-bruteforce` pairs
each user with one password (spray, not brute), keeping lockout risk low.

### GUI session ✏️
```sh
xfreerdp /v:H /u:U /p:P /d:DOMAIN +clipboard /dynamic-resolution
# Pass-the-hash (requires DisableRestrictedAdmin=0 on target):
xfreerdp /v:H /u:U /pth:NTLMHASH /d:DOMAIN
```
*Why:* Full interactive desktop. PTH works when Restricted Admin Mode is disabled on the
target (common on older Server releases; blocked by default on Server 2012R2+).

### Screenshot without interaction ✏️
```sh
nxc rdp H -u U -p P --screenshot --screentime 5
```
*Why:* Captures the desktop of authenticated sessions (or the logon screen if no NLA).
Useful for quickly identifying who is logged in and what is running.

## aranum helpers
- `aranumtoolkit/network/enum-rdp.sh` — runs nmap rdp-enum-encryption / rdp-ntlm-info /
  rdp-vuln-ms12-020, nxc rdp cred check + screenshot, and rdp-sec-check.pl.

## Gotchas
- RDP lockout policy is typically the same as the domain policy — check `--pass-pol` via
  SMB before any spray. Default Server 2019 lockout is often 5 attempts / 30 min.
- BlueKeep affects only non-NLA RDP (NLA requires auth before the vulnerable channel).
  Patch status: all vendors patched by mid-2019; expect it only on legacy/air-gapped
  targets.
- PTH via xfreerdp requires the `Restricted Admin Mode` registry key to be enabled
  (`DisableRestrictedAdmin = 0`); it was disabled by default after MS16-072 / Server 2016+.
- `rdp-vuln-ms12-020` (DoS — CVE-2012-0002) run by enum-rdp.sh is a different bug from
  BlueKeep; do NOT send it against production without explicit approval — it can crash
  the target.
- RDP over 5987 or non-standard ports (common in hardened deployments) won't be caught
  by default nmap; re-scan with `-p-` if you suspect a redirect.

## Sources
- HackTricks `pentesting-rdp`; Hackviser RDP pentesting;
  rdpscan README (robertdavidgraham/rdpscan); NetExec wiki RDP;
  CVE-2019-0708 BlueKeep advisory (Microsoft).
