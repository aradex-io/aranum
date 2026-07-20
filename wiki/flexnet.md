---
service: flexnet
title: FlexNet Publisher / FLEXlm License Server
ports: 27000-27009
aliases: flexlm, lmgrd, license-daemon
---

# FlexNet / FLEXlm — quick wins

**When you see it:** an open port in 27000-27009 (the `lmgrd` range) → a FlexNet Publisher /
FLEXlm license server. Characteristic of MATLAB, Cadence, Synopsys, Ansys, COMSOL, and Mentor
hosts. The value is intel: `lmstat` discloses every licensed product, version, and the
usernames/hostnames currently checked out.

> Authorized testing only. Triage is read-only. This is an information-disclosure surface —
> `lmstat` queries are read-only but noisy; no write path is documented here.

## Triage (read-only)
```sh
nc -nv -w 4 H 27000                            # banner / connectivity check
nmap -sV -p 27000-27009 H                      # identify lmgrd + vendor daemon range
lmutil lmstat -a -c 27000@H                    # full status (needs local lmutil)
```

## Quick wins

### Full license inventory via lmstat
```sh
lmutil lmstat -a -c 27000@H
```
*Why:* `lmstat -a` discloses every licensed feature, its version, total/available seats, and
the `user@host` of each active checkout — a map of who runs what expensive EDA/simulation
software and on which internal hosts.

### Per-feature diagnostics
```sh
lmutil lmdiag -c 27000@H
```
*Why:* `lmdiag` reveals feature-level detail (expiry, vendor string, host binding) — useful
for spotting node-locked licenses and stale/borrowed seats.

### Server hostid / vendor daemon enumeration
```sh
lmutil lmhostid -c 27000@H
nmap -sV -p 27000-27100 H | grep -i flex
```
*Why:* the hostid is the value a stolen license file is bound to; the vendor daemon listens
on an ephemeral port (often just above 27009) — enumerate the range to fingerprint the exact
product (e.g. `MLM` = MATLAB, `snpslmd` = Synopsys).

## aranum helpers
- `aranumtoolkit/network/enum-flexnet.sh` — dispatcher (banner detection + `lmutil lmstat -a` when `lmutil` is present locally).

## Gotchas
- `lmutil` must be installed on your box (ships with the vendor product, e.g. MATLAB's `bin/glnxa64`) — the dispatcher falls back to banner-only evidence without it.
- The `lmgrd` master port (27000-27009) is fixed, but the **vendor daemon** picks a random high port each restart unless pinned — firewall rules often miss it.
- No default credentials — FLEXlm has no auth; the finding is disclosure + version-mapping to known `lmadmin`/`lmgrd` CVEs, not direct RCE.
- Usernames/hostnames leaked by `lmstat` feed straight into AD/user-enum and lateral targeting.

## Sources
- Revenera FlexNet Publisher `lmutil`/`lmstat` reference; HackTricks license-server notes; aranum iteration I-C.
