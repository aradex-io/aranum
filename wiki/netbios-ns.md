---
service: netbios-ns
title: NetBIOS Name Service
ports: 137
aliases: netbios-ns, nbns, nbt
---

# NetBIOS-NS — quick wins

**When you see it:** UDP 137 answering a name query → NetBIOS Name Service. It's a recon
surface: the name table leaks the host's NetBIOS name, logged-in user, workgroup/domain, and
MAC address without any auth. A workgroup that doesn't match its neighbours is a rogue-host
signal.

> Authorized testing only. Triage is read-only. Active NBNS spoofing/poisoning (Responder) is
> an on-network MITM technique — out of scope for this read-only page; noted only for context.

## Triage (read-only)
```sh
nmblookup -A H                          # full name table (names, group flags)
nbtscan H                                # name, user, MAC, workgroup in one line
nbtscan -r 10.10.10.0/24                 # sweep a subnet (source port 137)
nmap -sU -p 137 --script nbstat H        # NSE nbstat: names + MAC
```

## Quick wins

### Name-table dump
```sh
nmblookup -A H
```
*Why:* returns the `<00>` (workstation), `<20>` (file server), `<03>` (messenger/logged-in
user), and `<1C>/<1B>` (domain/PDC) records — you learn the hostname, whether it's a DC/file
server, and often the logged-in username, all unauthenticated.

### MAC + workgroup fingerprint
```sh
nbtscan -v H
```
*Why:* the MAC address identifies the NIC vendor (VMware/Hyper-V/physical) and the workgroup
field tells you the domain — feeds host classification and the rogue-host check below.

### Rogue-host / workgroup-mismatch sweep
```sh
nbtscan -r 10.10.10.0/24 | awk '{print $NF, $1}' | sort
```
*Why:* a host whose workgroup differs from the rest of the subnet (e.g. `WORKGROUP` amid a
`CORP` domain) is often an unmanaged/rogue device or an attacker box — a lead worth chasing.

## aranum helpers
- `aranumtoolkit/network/enum-netbios-ns.sh` — dispatcher (name table via nbtscan/nmblookup; workgroup-mismatch / rogue-host signal).

## Gotchas
- UDP 137 is often filtered across VLANs even when SMB (445) is reachable — absence here doesn't mean the host is down.
- The `<03>` logged-in-user record only appears if the Messenger service registered it — modern Windows frequently omits it.
- NetBIOS is legacy; pure-SMB (445-only) hosts with NetBIOS-over-TCP disabled won't answer 137 at all.
- For the interactive/spoofing side (NBNS/LLMNR poisoning), that's Responder territory on the local segment — a different technique class.

## Sources
- `nbtscan` / `nmblookup` man pages; nmap `nbstat` NSE; HackTricks `137-138-139-pentesting-netbios`.
