---
service: slp
title: Service Location Protocol (SLP)
ports: 427
aliases: slp, svrloc
---

# SLP — quick wins

**When you see it:** UDP/TCP 427 answering an SLP query → Service Location Protocol, common on
VMware ESXi, printers, and SAN/NAS appliances. Two angles: it **enumerates registered
services** (a map of the appliance's exposed protocols), and CVE-2023-29552 makes an
internet-reachable SLP responder a **massive reflection/amplification DDoS source (up to
2200x)**. This is an **opt-in / aggressive** surface in aranum (`--slp`).

> Authorized testing only. Do **not** probe internet-facing or arbitrary SLP hosts — a crafted
> query can make the target reflect amplified traffic at a victim, turning you into a DDoS
> source. Only use against explicitly authorized, internal targets.

## Triage (read-only)
```sh
nmap -sU -p 427 --script slp-discovery H            # enumerate registered services
nmap -sU -p 427 --script slp-info H                  # attributes per service
# aranum's gated dispatcher wraps these:
bash aranumtoolkit/network/enum-slp.sh --slp --targets t.txt --output /tmp/slp
```

## Quick wins

### Service directory enumeration
```sh
nmap -sU -p 427 --script slp-discovery H
```
*Why:* SLP's whole job is advertising services — `slp-discovery` returns every service URL the
host registers (e.g. `service:VMwareInfrastructure`, printer/SAN endpoints), mapping the
appliance's attack surface without touching those services directly.

### Service attribute detail
```sh
nmap -sU -p 427 --script slp-info H
```
*Why:* `slp-info` pulls the attributes for each advertised service — versions, management URLs,
and identifiers that pivot to appliance-specific CVEs (ESXi, printer firmware, storage controllers).

### CVE-2023-29552 amplification-surface flag
```sh
# aranum enum-slp reports whether the host is an amplification candidate.
```
*Why:* CVE-2023-29552 lets an attacker register services then send a spoofed-source query,
making the SLP host blast a huge response at the victim (2200x amplification). aranum only
**flags** the surface — it never sends spoofed/amplifying traffic.

## aranum helpers
- `aranumtoolkit/network/enum-slp.sh` — **opt-in** dispatcher (`--slp`/`--aggressive`); nmap `slp-discovery`/`slp-info` + CVE-2023-29552 amplification-surface flag.

## Gotchas
- **Amplification risk is the whole reason this is gated** — never point it at addresses you don't own; a spoofed query reflects at a third party.
- `nmap -sU` needs root for reliable UDP; without it the dispatcher warns and falls back to a limited scan.
- SLP is frequently found on VMware ESXi — a hit there pairs with the ESXi/vSphere management surface (443/902) as the real target.
- UDP unreliability means no answer ≠ closed; retry, and note that many hosts filter 427 at the perimeter (the correct hardening for CVE-2023-29552).

## Sources
- CVE-2023-29552 (BitSight/Curesec SLP amplification) advisory; nmap `slp-discovery`/`slp-info` NSE; aranum §9 amplification safety stance.
