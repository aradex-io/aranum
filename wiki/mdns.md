---
service: mdns
title: mDNS / DNS-SD
ports: 5353/udp
aliases: dns-sd, bonjour, zeroconf, avahi
---

# mDNS / DNS-SD — quick wins

**When you see it:** 5353/udp answers a DNS-SD PTR query for `_services._dns-sd._udp.local` → the host
hands you its whole advertised-service catalog plus, usually, its **real internal hostname**. High-value
internal recon with no auth.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
nmap -sU -p5353 --script dns-service-discovery H     # service catalog + records
avahi-browse -art                                     # on-subnet: browse everything, resolve
dns-sd -B _services._dns-sd._udp local.               # macOS: list advertised service types
```

## Quick wins

### Service-catalog enumeration
```sh
nmap -sU -p5353 --script dns-service-discovery H
```
*Why:* the `_services._dns-sd._udp.local` PTR returns every service type the host advertises —
`_ssh`, `_sftp-ssh`, `_smb`, `_afpovertcp`, `_airplay`, `_ipp`/`_printer`, `_http`, `_workstation` —
a free map of what else to hit on the box.

### Resolve to host + port (PTR → SRV → A)
```sh
avahi-resolve -n HOSTNAME.local                       # advertised name → IP
dns-sd -L "INSTANCE" _ssh._tcp local.                 # instance → host:port + TXT
```
*Why:* chasing each advertised service down to SRV/A gives the real hostname, port, and TXT metadata
(model, versions) — often the internal name that DNS won't tell you.

## aranum helpers
- `aranumtoolkit/network/enum-mdns.sh` — dispatcher (one unicast DNS-SD PTR query for `_services._dns-sd._udp.local` → advertised service types; stdlib socket, nmap `dns-service-discovery` fallback). Not amplification-gated (single unicast query).

## Gotchas
- mDNS is link-local by design — reachable off-subnet usually means a misconfigured reflector/relay (itself worth noting).
- `avahi-browse`/`dns-sd` need to be on the same L2 segment; the unicast PTR probe works cross-subnet if the host answers.
- UDP silence ≠ closed. Some stacks only answer multicast, not unicast 5353.

## Sources
- HackTricks `5353-udp-multicast-dns-mdns`; nmap `dns-service-discovery` docs; avahi-browse / dns-sd man pages; aranum `enum-mdns.sh` header.
