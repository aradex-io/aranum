---
service: radius
title: RADIUS
ports: 1812, 1813, 1645, 1646
aliases: radius, radacct
---

# RADIUS — quick wins

**When you see it:** UDP 1812 (auth) / 1813 (accounting) — a RADIUS server (NPS, FreeRADIUS,
ISE) backing VPN / 802.1X / admin logins. The 2024 **BlastRADIUS** flaw (CVE-2024-3596) lets
an on-path attacker forge an Access-Accept when the server doesn't enforce Message-Authenticator.
This is an **opt-in / aggressive** surface in aranum (`--radius`) because probes can trip NAS
lockout policies.

> Authorized testing only. Access-Request probes can interact with account-lockout policy —
> confirm the probe username matches no real account. BlastRADIUS exploitation (marked ✏️)
> needs an on-path position + nonce grinding and is well beyond the read-side check.

## Triage (read-only)
```sh
nmap -sU -p 1812,1813 H                              # confirm RADIUS ports respond
# stdlib Access-Request probe (aranum dispatcher does this):
ENUM_RUN_RADIUS=1 bash aranumtoolkit/network/enum-radius.sh --targets t.txt --output /tmp/r
```

## Quick wins

### BlastRADIUS precondition check — CVE-2024-3596
```sh
# does the server require Message-Authenticator on responses?
# aranum enum-radius reports the enforcement state from its Access-Request/Reject.
```
*Why:* BlastRADIUS abuses RADIUS's MD5-based Response Authenticator: if the server accepts
requests/replies **without** a Message-Authenticator attribute, an on-path attacker can craft
an MD5 chosen-prefix collision to turn an Access-Reject into an Access-Accept. The read-side
check only confirms the precondition (enforcement off) — not a live forge.

### Shared-secret confirmation / offline crack
```sh
# capture a request/response pair on-path, then crack the shared secret offline:
# (the Response Authenticator = MD5(Code|ID|Length|ReqAuth|Attrs|Secret))
```
*Why:* many RADIUS deployments reuse a weak shared secret across NAS clients; a captured
auth exchange lets you brute the secret offline, after which you can inject/spoof RADIUS
freely. Requires a captured pair (sniff or MITM).

### Access-Request probe (reachability + policy)
```sh
# use the gated dispatcher — a benign non-existent username avoids lockout:
ENUM_RUN_RADIUS=1 bash aranumtoolkit/network/enum-radius.sh --targets t.txt --output /tmp/r
```
*Why:* confirms the server is live and speaking RADIUS, and its reject behaviour reveals
whether Message-Authenticator is enforced — all without guessing real credentials.

## aranum helpers
- `aranumtoolkit/network/enum-radius.sh` — **opt-in** dispatcher (`--radius`/`--aggressive`, env-gated `ENUM_RUN_RADIUS=1`); stdlib Access-Request probe + BlastRADIUS (CVE-2024-3596) enforcement precondition check.

## Gotchas
- Probes may count against NAS-side lockout — always use a username you've confirmed does **not** exist (`aratool-probe` in the dispatcher is designed for this).
- UDP: no response can mean filtered, dropped, or "silently discarded because the shared secret is wrong" — absence isn't a clean signal.
- BlastRADIUS does **not** affect EAP-based flows (802.1X with EAP) the same way — it targets non-EAP RADIUS (PAP/CHAP over the NAS).
- Full exploitation needs an on-path position between NAS and RADIUS server plus a fast chosen-prefix MD5 collision — the aranum check is precondition-only by design.

## Sources
- CVE-2024-3596 (BlastRADIUS) advisory + blastradius.fail; RFC 2865/2866; FreeRADIUS Message-Authenticator hardening notes; aranum §9 safety stance.
