---
service: ssdp
title: SSDP / UPnP
ports: 1900/udp
aliases: upnp, ssdp-discover
---

# SSDP / UPnP — quick wins

**When you see it:** 1900/udp answers an `M-SEARCH` with `HTTP/1.1 200` + a `LOCATION:` header → the
device advertises its descriptor XML (model/firmware/serial + control URLs). SUBSCRIBE with a spoofed
callback is the **CVE-2020-12695 (CallStranger)** data-exfil / reflected-amplification surface.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
nmap -sU -p1900 --script upnp-info H         # device/service inventory + LOCATION
# raw unicast M-SEARCH:
printf 'M-SEARCH * HTTP/1.1\r\nHOST: H:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' | nc -u -w3 H 1900
```

## Quick wins

### M-SEARCH → LOCATION descriptor
```sh
# from the M-SEARCH reply, fetch each LOCATION URL:
curl -s http://H:PORT/rootDesc.xml            # path comes from the LOCATION header
```
*Why:* the descriptor XML gives model, firmware, serial, and the presentation/control URLs — device
fingerprint plus the SOAP endpoints you'd drive next. All unauthenticated.

### Map the control/SUBSCRIBE surface (CallStranger — CVE-2020-12695)
```sh
nmap -sU -p1900 --script upnp-info H          # lists services + eventSubURL / controlURL
```
*Why:* an eventing endpoint that honors a caller-supplied `Callback` header lets an attacker exfil data
or reflect/amplify traffic (CallStranger). Enumerate the control URLs; do **not** launch amplification
at third parties.

## aranum helpers
- `aranumtoolkit/network/enum-ssdp.sh` — dispatcher (one unicast `M-SEARCH ST: ssdp:all` → device/service inventory + `LOCATION` XML URLs into `_hints.txt`; nmap `upnp-info` fallback).
  **AGGRESSIVE / opt-in:** gated behind `ENUM_RUN_SSDP=1` (or `auto-enum.sh --ssdp`) because SSDP is a reflection vector.

## Gotchas
- 1900 is a broadcast/multicast protocol — off-subnet reachability usually means a misconfigured reflector/relay.
- UDP silence ≠ closed; some devices only answer multicast M-SEARCH, not unicast.
- The interesting data is behind the `LOCATION` URL (often a high TCP port), not on 1900 itself.

## Sources
- HackTricks `1900-udp-pentesting-upnp`; CVE-2020-12695 (CallStranger) advisory; nmap `upnp-info` docs; aranum `enum-ssdp.sh` header.
