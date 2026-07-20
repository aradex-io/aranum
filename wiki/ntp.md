---
service: ntp
title: NTP
ports: 123/udp
aliases: ntpd, network-time-protocol
---

# NTP — quick wins

**When you see it:** 123/udp open and a mode-6 `readvar` returns a variable string → version/OS/peer
config leak. If a mode-7 `monlist` request draws a large response, the host is a **CVE-2013-5211**
reflection/amplification source — an integrity/DoS finding on its own.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
ntpq -c rv H                         # mode-6 readvar: version, system, processor, OS
ntpq -c 'rv 0 version' H             # just the version string
nmap -sU -p123 --script ntp-info H   # NSE corroboration of readvar
```

## Quick wins

### Mode-6 readvar — version/config leak
```sh
ntpq -c rv H
ntpq -c peers -c assoc H             # association / peer topology
```
*Why:* the control (mode 6) `readvar` reply discloses ntpd version, kernel/OS, processor, and peer
config unauthenticated — clean host fingerprinting and a patch-level tell for known ntpd CVEs.

### Mode-7 monlist — amplification precondition (CVE-2013-5211)
```sh
nmap -sU -p123 --script ntp-monlist H
```
*Why:* a `MON_GETLIST` response returns the last clients the server talked to — a big-amplitude
reflection vector and a list of hosts that recently synced. A non-empty reply = the box is an
amplification source. Do **not** drive amplification against arbitrary/internet-facing addresses.

## aranum helpers
- `aranumtoolkit/network/enum-ntp.sh` — dispatcher (mode-6 readvar + single mode-7 monlist probe; stdlib socket, nmap `ntp-info`/`ntp-monlist` fallback).
  **AGGRESSIVE / opt-in:** gated behind `ENUM_RUN_NTP=1` (or `auto-enum.sh --ntp`) because monlist is an amplification vector.

## Gotchas
- monlist was removed/disabled after ntpd 4.2.7p26 (`disable monitor`) — modern boxes won't answer it, but readvar usually still does.
- UDP: no response ≠ closed. Rate-limiting (`limited`/KoD) can swallow probes; retry slowly.
- Never fire the monlist probe at hosts you don't own — you become the reflection source.

## Sources
- HackTricks `123-udp-pentesting-ntp`; CVE-2013-5211 advisories; ntpq / nmap `ntp-info`/`ntp-monlist` docs; aranum `enum-ntp.sh` header.
