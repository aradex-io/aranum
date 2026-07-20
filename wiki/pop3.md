---
service: pop3
title: POP3
ports: 110, 995
aliases: pop3, pop3s
---

# POP3 — quick wins

**When you see it:** 110/tcp (POP3) or 995/tcp (POP3S) open — a mail-retrieval server. Value
is credential-driven: valid creds let you `RETR` every message (mail holds reset links, keys,
internal docs), and a banner that allows plaintext `USER`/`PASS` means creds are sniffable and
cheap to spray.

> Authorized testing only. Triage is read-only. A `USER`/`PASS` login (marked ✏️) authenticates
> against a real mailbox — confirm scope and watch lockout policy.

## Triage (read-only)
```sh
nc -nv H 110                                          # greeting banner (server + product)
printf 'CAPA\r\n' | nc -w3 H 110                       # capabilities (USER, SASL, STLS)
openssl s_client -connect H:995 -quiet 2>/dev/null     # POP3S banner + cert
nmap -sV --script pop3-capabilities,pop3-ntlm-info -p 110,995 H
```

## Quick wins

### Capability / plaintext-auth check
```sh
printf 'CAPA\r\n' | nc -w3 H 110
```
*Why:* `CAPA` lists supported auth (`USER`, `SASL PLAIN/LOGIN`) and whether `STLS` is offered.
A server accepting `USER`/`PASS` with no `STLS` requirement transmits creds in cleartext —
sniffable on-path and safe to spray. `pop3-ntlm-info` leaks the AD domain/host.

### Authenticated mailbox read ✏️
```sh
{ printf 'USER %s\r\nPASS %s\r\nLIST\r\nRETR 1\r\nQUIT\r\n' "$U" "$P"; sleep 2; } | nc -w5 H 110
```
*Why:* `LIST` shows the message count and `RETR n` pulls a full message — mailboxes carry
password-reset emails, API keys, and internal correspondence, a fast lateral pivot from one
valid credential.

### Credential spray ✏️
```sh
nxc pop3 H -u users.txt -p passwords.txt        # or the dispatcher's ENUM_USER/PASS probe
```
*Why:* mail passwords are commonly reused for SSO/OWA; a small, lockout-aware spray against
harvested usernames frequently lands.

## aranum helpers
- `aranumtoolkit/network/enum-pop3.sh` — dispatcher (CAPA banner, plaintext-auth flag, optional `ENUM_USER`/`ENUM_PASS` probe).
- `standalones/creds/spray-scheduler.py` — lockout-aware spray wrapper.

## Gotchas
- POP3 downloads and (by default) deletes-on-read only if the client issues `DELE` — read-only `RETR` leaves mail in place, but some servers auto-expunge; avoid `DELE`.
- `STLS` on 110 upgrades to TLS; a server offering only `STLS` (not enforcing it) is downgrade-MITM-able.
- 995 is implicit TLS from byte one — use `openssl s_client`, not raw `nc`.
- POP3 only sees the INBOX (no folders) — for full mailbox access prefer IMAP (`wiki/imap.md`) when both are open.

## Sources
- HackTricks `110-995-pentesting-pop`; nmap `pop3-*` NSE; netexec POP3 module.
