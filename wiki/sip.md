---
service: sip
title: SIP / VoIP
ports: 5060, 5061
aliases: sip, sip-tls
---

# SIP / VoIP — quick wins

**When you see it:** 5060/tcp or /udp (SIP) or 5061 (SIP-TLS) → a VoIP server (Asterisk,
FreePBX, Cisco CUCM, Avaya). The quick wins are extension (user) enumeration and password
guessing — a valid extension + weak secret lets you register a rogue endpoint and place calls
(toll fraud) or intercept.

> Authorized testing only. Triage is read-only. Extension enumeration and REGISTER attempts
> (marked ✏️) generate real signalling against the PBX — confirm scope; brute-forcing can lock
> extensions or flood CDRs.

## Triage (read-only)
```sh
nmap -sU -sT -p 5060,5061 --script sip-methods,sip-enum-users H   # methods + vendor
svmap H                                            # SIPVicious: identify SIP devices
sudo sipvicious_svmap H                             # (newer package name)
```

## Quick wins

### Vendor fingerprint + allowed methods
```sh
nmap -sU -p 5060 --script sip-methods H
```
*Why:* the `Server:`/`User-Agent:` header and OPTIONS response fingerprint the PBX (Asterisk,
FreePBX, CUCM, Avaya) → maps to product default extensions and known CVEs; the allowed methods
tell you whether REGISTER/INVITE are open.

### Extension (user) enumeration ✏️
```sh
svwar -m INVITE -e 100-999 H            # SIPVicious extension war-dial
# nmap equivalent:
nmap -sU -p 5060 --script sip-enum-users --script-args 'sip-enum-users.padding=3' H
```
*Why:* the server responds differently (401/407 vs 404) for existing vs non-existent
extensions — enumerate the valid extension numbers before password-guessing.

### Extension password guess ✏️
```sh
svcrack -u EXTENSION -d /usr/share/wordlists/rockyou.txt H
```
*Why:* a cracked extension secret lets you REGISTER as that endpoint → place outbound calls
(toll fraud), receive its calls, or pivot into the internal dial plan. Asterisk/FreePBX
extensions with the number as the secret are common.

## aranum helpers
- `aranumtoolkit/network/enum-sip.sh` — dispatcher (nmap `sip-methods`/`sip-enum-users`; vendor fingerprint Asterisk/FreePBX/CUCM/Avaya/Polycom).

## Gotchas
- SIP runs on BOTH UDP and TCP 5060 — the dispatcher scans `-sU -sT`; a UDP-only probe can miss a TCP-only PBX and vice versa.
- Extension enumeration is noisy and hits the PBX's auth log / CDR — coordinate, and prefer OPTIONS/`sip-enum-users` over an INVITE war-dial where possible.
- FreePBX/Asterisk `allowguest=yes` lets unauthenticated INVITEs place calls — test for anonymous calling before bothering with cracking.
- 5061 is TLS — use `sip-methods` over TCP/TLS or an `openssl s_client` wrap; SIPVicious targets UDP by default.

## Sources
- SIPVicious (`svmap`/`svwar`/`svcrack`) docs; nmap `sip-*` NSE; HackTricks `5060-pentesting-sip`; Asterisk/FreePBX security guides.
