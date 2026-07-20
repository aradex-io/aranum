---
service: finger
title: Finger
ports: 79
aliases: fingerd
---

# Finger — quick wins

**When you see it:** 79/tcp open and `finger @H` returns login/name/tty lines → the finger daemon
leaks logged-in and arbitrary local accounts. Pure username/host enumeration — feeds every downstream
spray list.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
finger @H                              # list currently logged-in users
finger root@H                          # confirm a specific account exists
# no finger client — raw:
printf 'root\r\n' | nc -w4 H 79
```

## Quick wins

### Enumerate logged-in users
```sh
finger @H
```
*Why:* the empty query returns everyone currently logged in (login, name, tty, idle, host) —
real usernames plus the hosts they're connecting *from*.

### Confirm / harvest specific accounts
```sh
for u in root admin test user guest oracle; do echo "== $u"; finger "$u@H"; done
```
*Why:* a valid account returns home dir, shell, last-login, and any `.plan`/`.project`; an invalid one
says "no such user" — a clean oracle. Feed confirmed names into SSH/SMTP/RDP spray lists.

## aranum helpers
- `aranumtoolkit/network/enum-finger.sh` — dispatcher (empty query for logged-in users, then probes `root/admin/test/user/guest`; flags on `Login`/`Name`/`Directory`/`tty` in the response).

## Gotchas
- Many `fingerd` builds disable arbitrary-user lookups or `@` chaining — you may get logged-in users only, or nothing.
- Classic `user@host@target` relay chaining is blocked on modern daemons.
- No output ≠ closed; some daemons answer only a bare newline and stay silent on names.

## Sources
- HackTricks `79-pentesting-finger`; finger(1) / fingerd docs; aranum `enum-finger.sh` header.
