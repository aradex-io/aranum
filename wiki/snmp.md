---
service: snmp
title: SNMP
ports: 161/udp, 162/udp
aliases: snmp-trap
---

# SNMP — quick wins

**When you see it:** 161/udp open and a community string works (default `public` read,
`private` read-write). SNMP is a goldmine — it leaks users, processes, installed software,
network interfaces, routes, ARP, and sometimes plaintext credentials, all unauthenticated
beyond a guessable string.

> Authorized testing only. Reads are passive; a write-community change (✏️) alters device
> config — get explicit sign-off and revert.

## Triage (read-only)
```sh
snmp-check -c public H                 # one-shot human-readable dump (best first look)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt H   # brute the community string
snmpwalk -v2c -c public H 1.3.6.1.2.1.1 # sysDescr/sysName — confirm + OS fingerprint
```

## Quick wins

### Full MIB walk → users, software, processes
```sh
snmpwalk -v2c -c public H .1                       # everything (noisy but complete)
snmpwalk -v2c -c public H 1.3.6.1.4.1.77.1.2.25    # Windows local usernames
snmpwalk -v2c -c public H 1.3.6.1.2.1.25.4.2.1.2   # running processes
snmpwalk -v2c -c public H 1.3.6.1.2.1.25.6.3.1.2   # installed software
snmpwalk -v2c -c public H 1.3.6.1.2.1.25.4.2.1.5   # process command-line args (creds!)
```
*Why:* the host-resources + Windows MIBs expose usernames, software versions (CVE pivot),
and full process command lines — service accounts often pass passwords on the cmdline.

### Grab network layout
```sh
snmpwalk -v2c -c public H 1.3.6.1.2.1.4.22.1.2     # ARP table (neighbours)
snmpwalk -v2c -c public H 1.3.6.1.2.1.4.21         # routing table
snmpwalk -v2c -c public H 1.3.6.1.2.1.2.2.1.6      # interface MACs
```
*Why:* maps the internal network for pivoting from a single reachable host.

### Cisco / network-gear config exfil
```sh
snmpwalk -v2c -c public H 1.3.6.1.4.1.9.9.91        # Cisco; look for community/enable
# RW community + TFTP: copy running-config off the device
```
*Why:* with a RW community, network gear will TFTP its running-config (with hashed/plaintext
secrets) to your server — classic credential capture.

### Write-community config change ✏️
```sh
snmpset -v2c -c private H <OID> <type> <value>      # only with sign-off; revert after
```
*Why:* `private`/RW community lets you change device config (routes, SNMP users, gear
running-config push). High blast radius — confirm scope first.

### SNMPv3 user enumeration
```sh
nmap -sU -p161 --script snmp-info,snmp-brute H
snmpwalk -v3 -l noAuthNoPriv -u OPERATOR H 1.3.6.1.2.1.1  # valid user = different error
```
*Why:* even v3 leaks valid usernames via differing error responses → targeted password attack.

## aranum helpers
- `enum-snmp.sh` — produced this finding (community check + key MIB pulls).

## Gotchas
- UDP — no handshake; "open|filtered" is common. Confirm with an actual `snmpwalk`, not just the port state.
- Wrong community / v3-only → timeouts; try `public`, `private`, `community`, vendor defaults, then `onesixtyone` a wordlist.
- Read-only community blocks `snmpset`; the read MIBs are still the high-value loot.
- Rate-limit walks on flaky/IoT gear — a full `.1` walk can be slow or wedge cheap devices.

## Sources
- HackTricks `161-162-pentesting-snmp` + "SNMP RCE"; Hackviser SNMP; common MIB OID cheat sheets.
