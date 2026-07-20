---
service: imap
title: IMAP
ports: 143, 993
aliases: imap2, imaps
---

# IMAP — quick wins

**When you see it:** 143/tcp (IMAP) or 993/tcp (IMAPS) open — a mailbox server. The interest
is credential-driven: valid creds give full mailbox read (mail is a goldmine of secrets and
password-reset links), and a plaintext-auth-allowed banner means creds can be sniffed or
sprayed cheaply.

> Authorized testing only. Triage is read-only. A `LOGIN` attempt (marked ✏️) authenticates
> against real accounts — confirm the account list is in scope and mind lockout policy.

## Triage (read-only)
```sh
nc -nv H 143                                          # banner (server + product)
printf 'a CAPABILITY\r\n' | nc -w3 H 143              # capabilities (AUTH mechs, STARTTLS)
openssl s_client -connect H:993 -quiet 2>/dev/null    # IMAPS banner + cert (SANs = usernames)
nmap -sV --script imap-capabilities,imap-ntlm-info -p 143,993 H
```

## Quick wins

### Capability / plaintext-auth check
```sh
printf 'a CAPABILITY\r\n' | nc -w3 H 143 | tr ' ' '\n' | grep -i "AUTH\|LOGINDISABLED\|STARTTLS"
```
*Why:* absence of `LOGINDISABLED` on the plaintext port means `LOGIN user pass` is accepted
in the clear — sniffable and sprayable. `AUTH=NTLM` leaks the Windows domain/host via
`imap-ntlm-info`.

### Authenticated mailbox read ✏️
```sh
openssl s_client -connect H:993 -quiet 2>/dev/null <<'EOF'
a LOGIN USER PASS
b SELECT INBOX
c SEARCH ALL
d FETCH 1:5 (BODY[HEADER])
EOF
```
*Why:* one valid login exposes every folder; mailboxes routinely hold password-reset emails,
API keys, VPN configs, and internal contact lists — often the fastest lateral pivot.

### Credential spray ✏️
```sh
nxc imap H -u users.txt -p passwords.txt        # or the repo dispatcher's ENUM_USER/PASS probe
```
*Why:* mail creds are frequently reused for OWA/SSO; a small spray against harvested usernames
often lands. Respect lockout thresholds — use the spray scheduler.

## aranum helpers
- `aranumtoolkit/network/enum-imap.sh` — dispatcher (CAPABILITY banner, STARTTLS flag, optional `ENUM_USER`/`ENUM_PASS` login probe).
- `standalones/creds/spray-scheduler.py` — lockout-aware wrapper for any credential spray.

## Gotchas
- STARTTLS on 143 upgrades the plaintext session — a server offering only STARTTLS (not `LOGINDISABLED`) can still be MITM-downgraded.
- Dovecot vs Cyrus vs Exchange changes folder names and quirks — read the banner before scripting `SELECT`.
- 993 requires TLS from the first byte (`openssl s_client`), unlike 143 — a raw `nc` to 993 gets you nothing.
- Lockout policy on mail servers is often aggressive (AD-backed) — spray slowly or you'll lock accounts.

## Sources
- HackTricks `143-993-pentesting-imap`; nmap `imap-*` NSE docs; netexec IMAP module.
