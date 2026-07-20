---
service: afp
title: AFP (Apple Filing Protocol)
ports: 548
aliases: afpovertcp, appleshare
---

# AFP — quick wins

**When you see it:** 548/tcp open and nmap `afp-serverinfo` returns the machine type / UAM list → the
server leaks its Mac model, OS, and supported auth methods with no login. If the **Guest UAM** is
listed, you can mount shares anonymously.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
nmap -Pn -p548 --script afp-serverinfo H       # model, OS, UAMs (auth methods)
nmap -Pn -p548 --script afp-showmount H        # exported volumes (no auth)
```

## Quick wins

### Server info + UAM disclosure
```sh
nmap -Pn -p548 --script afp-serverinfo H
```
*Why:* unauthenticated `afp-serverinfo` returns the Mac model, macOS version, machine name, and the UAM
list. `No User Authent` / `Guest` in the UAMs = anonymous access is on.

### Enumerate + guest-mount shares — sensitive
```sh
nmap -Pn -p548 --script afp-showmount H        # list exported volumes
# guest mount (macOS): mount_afp afp://;AUTH=No%20User%20Authent@H/VOLUME /mnt/afp
```
*Why:* `afp-showmount` lists volumes without auth; if guest UAM is enabled you can mount and read share
contents. Treat mounted data as sensitive — scope which volumes you touch.

## aranum helpers
- `aranumtoolkit/network/enum-afp.sh` — dispatcher (nmap `afp-serverinfo` + `afp-showmount`; flags on machine type / AFP banner and enumerated shares).

## Gotchas
- Macs almost always run SMB (445) alongside AFP — pair the two; creds/shares often overlap.
- Guest access can be enabled for AFP but disabled per-volume — `afp-showmount` may list volumes you still can't mount as guest.
- AFP is deprecated by Apple (SMB is default since macOS 10.9); seeing it usually means an older server or a NAS.

## Sources
- HackTricks `548-pentesting-apple-filing-protocol-afp`; nmap `afp-serverinfo` / `afp-showmount` docs; aranum `enum-afp.sh` header.
