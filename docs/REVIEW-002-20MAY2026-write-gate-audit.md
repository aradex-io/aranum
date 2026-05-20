# REVIEW-002 — Write-gate audit of exploitation helpers

**Date:** 2026-05-20
**Tag this lands under:** `v0.14.0` (iteration G.8)
**Owning invariant:** `CLAUDE.md` §9 invariant 1 —
*"No script in this repo writes to a target without an explicit `--write` / `--exploit` / `--rce` flag (default is enumeration-only)."*

This document audits every helper in `activemq/`, `redis/`, `smtp/`, `jabber/`,
and `creds/` to verify the invariant. Where the audit found a violation, the
fix was committed BEFORE this doc landed (per the iteration-G ordering rule:
gaps become fix commits, not findings).

---

## 1. Method

For each helper:

1. Read the top docstring / banner to identify intent.
2. Read the arg parser to identify the gate flag (if any) and what it gates.
3. Run the helper with `--target` set to an unreachable IP and verify the
   default invocation neither connects nor writes — output should describe
   what *would* happen and exit 0.
4. Confirm the gate is documented in `--help` and the operator-facing README.

Helpers were classified into three tiers:

- **Read-only:** No filesystem / no network mutation against target. No gate needed.
- **Envelope-only:** Touches target protocol state (e.g. SMTP `MAIL FROM` / `RCPT TO`)
  but does NOT deliver payload / write data. Documented as enumeration; no gate
  required (matches `nmap --script smtp-open-relay` precedent).
- **Write/exploit:** Mutates target state (file write, RCE, message delivery,
  module load). **MUST** carry an explicit gate flag.

---

## 2. Helper-by-helper findings

### activemq/

| Helper | Tier | Gate | Default behaviour | Status |
|---|---|---|---|---|
| `activemq-quickwin.sh` | read-only | — | per-target detection + CVE-2023-46604 classification | ✅ OK as-shipped |
| `activemq-queues.sh` | read-only | — | JMS QueueBrowser pull from each queue. Browsing is non-destructive — messages stay in the queue. | ✅ OK as-shipped |
| `activemq-jolokia-rce.sh` | write/exploit | `--exploit` | **was: default-fire.** Now: dry-run summary → exit 0 unless `--exploit`. | 🛠 fixed this iteration |
| `activemq-cve-2023-46604.py` | write/exploit | `--exploit` | **was: default-fire (RCE).** Now: dry-run summary → exit 0 unless `--exploit`. | 🛠 fixed this iteration |

### redis/

| Helper | Tier | Gate | Default behaviour | Status |
|---|---|---|---|---|
| `redis-quickwin.sh` | read-only | — | detection + exploitability tier | ✅ OK as-shipped |
| `redis-lateral.sh` | read-only | — | explicitly documented as "Doesn't change ANY state on the target. Read-only operations only." Verified: only `CLIENT LIST`, `INFO`, `CONFIG GET`, `SLOWLOG`, `SCAN`, `GET`/`HGETALL`/`LRANGE`, `CLUSTER NODES`, `SENTINEL MASTERS`, `PUBSUB CHANNELS`, `MEMORY STATS`, `ACL LIST`. No `SET`, no `CONFIG SET`, no `SAVE`. | ✅ OK as-shipped |
| `redis-rogue-master.py` | passive listener | — | binds a port, serves one payload to the FIRST connecting victim, exits. Doesn't initiate any connection. The active write step lives in `redis-rce-module.sh` (which now gates on `--exploit`). | ✅ OK as-shipped |
| `redis-rce-module.sh` | write/exploit | `--exploit` | **was: default-fire (RCE).** Now: dry-run → exit 0 unless `--exploit`. | 🛠 fixed this iteration |
| `redis-rce-ssh.sh` | write/exploit | `--write` | **was: default-fire (writes `authorized_keys` to disk).** Now: dry-run → exit 0 unless `--write`. Gate name is `--write` rather than `--exploit` because the action is a file write, not an RCE primitive. | 🛠 fixed this iteration |

### smtp/

| Helper | Tier | Gate | Default behaviour | Status |
|---|---|---|---|---|
| `smtp-quickwin.sh` | read-only | — | EHLO/STARTTLS/VRFY probes + tier | ✅ OK as-shipped |
| `smtp-user-enum.sh` | envelope-only | — | VRFY/EXPN/RCPT TO probes. Aborts at RCPT result; no DATA. | ✅ OK as-shipped |
| `smtp-relay-test.sh` | envelope-only | — | Sends the 19 classical MAIL FROM / RCPT TO routing variants and reads each RCPT reply code. **Never sends DATA**, so no message is delivered. Matches `nmap --script smtp-open-relay` precedent. The `RELAY OPEN` finding then points the operator at `smtp-phish-send.sh` which is fully gated. | ✅ OK as-shipped |
| `spf-dmarc-check.sh` | read-only | — | DNS lookups only (`dig +short`). No connection to the target's SMTP listener. | ✅ OK as-shipped |
| `smtp-phish-send.sh` | write/send | `--send` | **was: default-send.** Now: dry-run → exit 0 unless `--send`. Operator must opt in to actually deliver the spoofed message. | 🛠 fixed this iteration |
| `smtp-smuggling-test.py` | write/send | `--send` | **was: default-send (transmits DATA payloads, including the smuggled second-message).** Now: dry-run → exit 0 unless `--send`. | 🛠 fixed this iteration |

### jabber/

| Helper | Tier | Gate | Default behaviour | Status |
|---|---|---|---|---|
| `jabber-admin-api-probe.sh` | read-only | — | unauthenticated GET probes to Ejabberd `/api/`, Prosody `mod_admin_telnet` (5582), Prosody `mod_admin_web` (5280/admin). No POSTs, no auth attempts. | ✅ OK as-shipped |
| `jabber-user-enum.py` | read-only | — | per ADR-001 D2 + D4: SASL-failure-XML differential only. The script-level docstring explicitly rejects the IBR creation path because "it creates accounts when the conflict-error path doesn't fire — that's a target-state change we won't take." Confirmed: no `<query xmlns='jabber:iq:register'>` followed by submit. | ✅ OK as-shipped |
| `jabber-validate.py` | read-only | — | single-credential validation only; no spray, no account creation. | ✅ OK as-shipped |
| `openfire-cve-2023-32315.py` | write/exploit | `--exploit` (with typed-FQDN confirm) and `--cleanup` (reverses prior `--exploit`) | iteration H's reference implementation of the pattern. Default = detection only. | ✅ OK as-shipped |

### creds/

| Helper | Tier | Gate | Default behaviour | Status |
|---|---|---|---|---|
| `default-creds-sweep.py` | envelope-only | — | attempts login with default-credential pairs from `default-creds.json`. No actions post-login (no command execution, no config change). Failed logins are the standard side effect of any auth check. Documented as enumeration. | ✅ OK as-shipped |

---

## 3. Summary

- **Helpers audited:** 19
- **Helpers requiring a gate:** 7
- **Helpers found in violation at audit start:** 6 (`activemq-jolokia-rce.sh`, `activemq-cve-2023-46604.py`, `redis-rce-module.sh`, `redis-rce-ssh.sh`, `smtp-phish-send.sh`, `smtp-smuggling-test.py`)
- **Already compliant:** 1 (`openfire-cve-2023-32315.py` — iteration H reference implementation)
- **Violations resolved before this doc was committed:** 6 / 6

### Gate-flag vocabulary (post-fix)

| Action shape | Gate flag |
|---|---|
| Memory-corruption / unauthenticated RCE chain | `--exploit` |
| Authenticated admin-RCE chain | `--exploit` |
| Filesystem write via primitive (e.g. `authorized_keys`) | `--write` |
| Network-delivered message (SMTP DATA payload) | `--send` |

All gates print a dry-run summary and exit 0 when omitted. None of them have an
environment-variable bypass — operator presence is required.

---

## 4. Standing rule for future helpers

Any new helper added to `activemq/`, `redis/`, `smtp/`, `jabber/`, `creds/`, or
a future `<protocol>/` directory MUST be classified at the same three tiers
before merge:

1. Read-only → no gate.
2. Envelope-only → no gate; document the precedent inline in the script header.
3. Write / exploit / send → add the appropriate gate flag from the vocabulary
   above; verify the dry-run exits 0 before any network operation; add an
   entry to this document in the same commit.

The smoke test in `tests/smoke.sh` will be extended in G.7-followup to assert
that every helper whose name matches `*-cve-*`, `*-rce-*`, `*-phish-*`, or
`*-rogue-*` exits 0 without `--exploit` / `--write` / `--send` / `--fire`
present in argv.
