---
service: tftp
title: TFTP
ports: 69/udp
aliases: tftpd, trivial-ftp
---

# TFTP — quick wins

**When you see it:** 69/udp answers an RRQ with a DATA packet (opcode `0x0003`) → the file exists and
TFTP has **no auth**. A blind read of `running-config`/`startup-config` typically yields SNMP
communities, type-7 enable secrets, and VPN PSKs.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
nmap -sU -p69 --script tftp-enum H            # brute a canonical filename wordlist
tftp H -c get running-config -                # DATA reply = file exists (no auth)
```

## Quick wins

### Blind config grab
```sh
for f in running-config startup-config config.text network-confg pxelinux.cfg/default; do
  tftp H -c get "$f" "loot_${f//\//_}" && echo "GOT $f"
done
```
*Why:* TFTP has no directory listing, so you guess canonical names. Network-gear configs are the
jackpot — they hold SNMP RW communities, enable secrets (often reversible type-7), and tunnel PSKs.

### PXE / boot artifacts
```sh
tftp H -c get pxelinux.cfg/default
tftp H -c get bootstrap.cfg
```
*Why:* PXE configs point at kernel/initrd/preseed images and sometimes embed install-time creds or
kickstart URLs — a foothold into the provisioning chain.

## aranum helpers
- `aranumtoolkit/network/enum-tftp.sh` — dispatcher (blind RRQ for a canonical config/PXE filename list — `running-config`, `startup-config`, `network-confg`, `pxelinux.cfg/default`, etc.; DATA vs ERROR distinguishes readable files; nmap `tftp-enum` fallback).

## Gotchas
- Read-only guessing game: no listing, so coverage depends on the filename list. Add device-specific names (`<hostname>-confg`, `<hostname>.cfg`).
- UDP + no auth means an ERROR reply (`0x0005`) still proves the server is alive — just that *that* file isn't present.
- Firewalls often let the RRQ out but block the server's ephemeral-port DATA reply back — a get can hang; confirm return path.

## Sources
- HackTricks `69-udp-pentesting-tftp`; nmap `tftp-enum` docs; Cisco type-7 secret notes; aranum `enum-tftp.sh` header.
