---
service: jabber
title: XMPP / Jabber
ports: 5222, 5223, 5269, 5280, 5281, 7070, 7443, 9090, 9091
aliases: xmpp, xmpp-client, xmpp-server
---

# XMPP / Jabber — quick wins

**When you see it:** 5222/tcp (client) or 5269/tcp (server-to-server) open → an XMPP server
(ejabberd, Prosody, Openfire). Check whether in-band registration (XEP-0077) is advertised
(free account) and whether the admin console is exposed — Openfire's console has a pre-auth
path-traversal→RCE (CVE-2023-32315).

> Authorized testing only. Triage is read-only; SASL user-enum is response-differential
> (creates nothing). Steps marked ✏️ modify target state (account creation, plugin upload) —
> the Openfire helper requires typed-FQDN confirm + cleanup.

## Triage (read-only)
```sh
nmap -sV --script xmpp-info -p 5222,5269 H            # version, stream features, TLS
standalones/jabber/jabber-admin-api-probe.sh --target H   # ejabberd /api/ + Openfire console exposure
curl -sI http://H:9090/ http://H:9091/                # Openfire admin console (HTTP/HTTPS)
```

## Quick wins

### Detect in-band registration (XEP-0077)
```sh
nmap -p 5222 --script xmpp-info H | grep -i register
```
*Why:* if `<register/>` is in the stream features, anyone can self-register an account
(`jabber-admin-api-probe.sh` reports it) — an instant authenticated foothold for MUC/roster
enumeration and internal messaging.

### SASL username enumeration (read-only)
```sh
python3 standalones/jabber/jabber-user-enum.py --target H --domain DOMAIN --users users.txt
```
*Why:* the SASL response differs for valid vs invalid usernames — enumerate real accounts
without creating anything (no XEP-0077 conflict probe, which would create accounts).

### Single-credential validation
```sh
python3 standalones/jabber/jabber-validate.py --target H --jid user@DOMAIN --password PASS
```
*Why:* validates one credential via SCRAM-SHA-256→SHA-1→PLAIN with a single attempt — safe
confirmation of harvested/guessed creds without a lockout-triggering spray.

### Openfire console auth bypass → RCE — CVE-2023-32315 ✏️
```sh
python3 standalones/jabber/openfire-cve-2023-32315.py detect --target H     # read-only check
# exploit path (typed-FQDN confirm + operator-supplied JSP plugin + cleanup):
python3 standalones/jabber/openfire-cve-2023-32315.py exploit --target H
```
*Why:* Openfire 3.10.0–4.7.4 admin console path traversal reaches setup pages without auth →
create an admin, upload a JSP plugin, get RCE. `detect` is read-only; `exploit`/`cleanup` are
gated per ADR-001.

## aranum helpers
- `aranumtoolkit/network/enum-jabber.sh` — dispatcher (banner, cert+SANs, SASL mechs, XEP-0077, disco, MUC, BOSH/WS, admin-API exposure).
- `standalones/jabber/jabber-user-enum.py`, `jabber-validate.py` — read-only enum / single-cred validation.
- `standalones/jabber/jabber-admin-api-probe.sh` — ejabberd/Prosody/Openfire admin-surface detection.
- `standalones/jabber/openfire-cve-2023-32315.py` — Openfire RCE (`detect`/`exploit`/`cleanup`, gated). Read `standalones/jabber/README.md` + ADR-001 first.

## Gotchas
- STARTTLS is usually mandatory on 5222 before SASL — the enum tools handle it; raw `nc` won't get past the stream negotiation.
- 5223 (legacy SSL) and 5269 (s2s) speak the same XML but different roles; user-enum targets the client port.
- Openfire admin console is 9090 (HTTP) / 9091 (HTTPS); ejabberd/Prosody expose 5280/5281 (BOSH/HTTP) + their own admin APIs.
- XEP-0077 registration is often rate-limited or captcha-gated — advertised ≠ always usable.

## Sources
- CVE-2023-32315 (Openfire) advisories; XEP-0077 / XEP-0030 specs; `standalones/jabber/README.md`; ADR-001-19MAY2026-jabber-scope.
