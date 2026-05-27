# ADR-001 — Scope of Iteration H (Jabber/XMPP tooling)

**Date:** 2026-05-19
**Status:** Accepted
**Roadmap reference:** ROADMAP-001 iteration H
**Decision drivers:** user direction (2026-05-19 milestone) + CLAUDE.md §9 safety invariants

---

## Context

Iteration H was added to ROADMAP-001 as a user-requested milestone ("standalones/jabber/comp pentesting tooling"). Before sequencing the work, four scope questions needed answers because the framing — *"comp pentesting"* — has more than one defensible interpretation (XMPP only, vs. Cisco UC, vs. SIP/voice, vs. modern team chat). The other three questions were aggressiveness of credential validation, OpenFire CVE-2023-32315 gating, and library policy.

This ADR records the answers and the reasoning that supports them so a future agent (Claude or human) does not have to relitigate.

## Decisions

### D1 — Target surface: XMPP/Jabber only

**Decision:** Iteration H covers self-hosted XMPP server enumeration (Ejabberd, Prosody, Openfire) and federated Jabber. Cisco UC stack, SIP/voice telephony, and modern team chat (Matrix, Mattermost, Rocket.Chat) are **out of scope for this iteration** and will be considered as separate future iterations if and when the operator's engagement profile justifies them.

**Reasoning:** Smallest defensible scope; ships fastest; the XMPP surface is independently coherent and historically the worst-covered gap in network enum kits. Cisco UC and SIP would each more-than-double the iteration and introduce protocol families (SCCP/SIP/AMI/ESL) that warrant their own ADR + scope review.

**Consequence:** If a future engagement needs Cisco UC or SIP, open a fresh ADR (`ADR-002-...`) and add iteration H.5 / H.6 / H.7 to ROADMAP-001 — do not silently expand H beyond what this ADR records.

### D2 — Credential validation: enumeration + single-credential validation only; no spray

**Decision:** Iteration H ships:
- User enumeration via XEP-0077 in-band-registration probing and SASL response-based timing differential
- Single-credential validation (`jabber-validate.py` accepts one `--user` + `--password` and confirms it authenticates)
- MUC nickname harvest

Iteration H does **not** ship a password-spraying tool. Spray belongs in a separate, scoped tool with mandatory per-target rate caps and lockout-policy awareness. That tool — if built at all — would land in a later iteration with its own ADR.

**Reasoning:** Lockouts during engagements are operationally expensive. The rest of the toolkit defaults to enumeration over offensive action. Single-cred validation is sufficient for "we found a credential elsewhere — is it valid here?" which is the most common engagement need. Bulk spray is rarely needed and risks more than it delivers.

**Consequence:** `jabber-spray.py` is **not** built in iteration H. If a future iteration wants it, the spray must:
- Require an explicit `--rate <N/min>` (no default)
- Honor the future Iteration G `--throttle` flag
- Detect account-locked responses and stop the entire campaign on the first one
- Require typed confirmation before starting (operator types the target domain literally)

### D3 — OpenFire CVE-2023-32315: full chain behind `--exploit`

**Decision:** Ship a single tool `standalones/jabber/openfire-cve-2023-32315.sh` (or `.py`) that:

1. **Default behavior (no flags):** detection only — probes the vulnerable `setup/setup-/..` traversal pattern, parses the response signature, reports `VULNERABLE` / `NOT VULNERABLE` / `UNKNOWN` with the version banner. **No target state change.**

2. **With `--exploit`:** performs the full chain — admin user creation via the path-traversal endpoint, then upload of a JSP webshell plugin, then prints the resulting webshell URL. **Strongly modifies target state.**

**Mandatory safeguards on `--exploit`:**
- Typed confirmation prompt: operator must type the target FQDN/IP literally before action begins (no `--yes-i-mean-it` short-circuit)
- Created admin username is logged at INFO and to `<out>/exploit_log.txt` with timestamp
- Plugin filename is non-default and recorded in the same log
- **`--cleanup` companion flag** that takes the admin credential from the previous run and reverses the changes (deletes the admin user via the legitimate API, removes the plugin). Cleanup is the **first thing** the README documents.
- No persistence (per CLAUDE.md §9 invariant 4): the plugin executes once and is intended to be removed by `--cleanup` immediately after the operator has captured what they need

**Reasoning:** The operator explicitly chose option 3 (full chain) in 2026-05-19 scoping. CLAUDE.md §9 invariant 1 requires write actions be `--write` / `--exploit` / `--rce`-gated — this design respects that. §9 invariant 4 forbids persistence — `--cleanup` enforces it. §9 invariant 5 (no detection-evasion) is not engaged. The full chain is widely published (the original CVE-2023-32315 advisory ships a reference PoC of identical shape), so withholding it does not raise the bar for attackers, but the `--cleanup` discipline does protect engagement targets from operator drift.

**Consequence:** This tool is the only iteration H component that intentionally modifies target state. Every code reviewer should treat it as such.

### D4 — Library policy: stdlib-only for enum/probe; slixmpp optional for state-machine-heavy tools

**Decision:** All enumeration and probe scripts in `standalones/jabber/` use Python stdlib only (matching the `standalones/graphql/gql.py` precedent — single-file portable, no pip install required on the jump box). The OpenFire CVE-2023-32315 helper is HTTP-only and stays stdlib (or `bash + curl`).

If a future tool genuinely needs XMPP state-machine depth (e.g. a TLS-strip MITM probe that has to negotiate STARTTLS), it may pull in `slixmpp` as an **optional** dependency: detected by `deps-check.sh`, with a clear stderr hint when missing. No stdlib-only tool ever depends on slixmpp.

**Reasoning:** XMPP enumeration is at heart XML-over-TCP with a thin handshake. Stdlib is sufficient and lets operators drop tools on any jump box without pre-staging dependencies.

**Consequence:** `jabber-enum.py`, `jabber-user-enum.py`, `jabber-validate.py`, and `openfire-cve-2023-32315.sh` are stdlib-only / bash-only. No `requirements.txt` in `standalones/jabber/`.

## Out of scope for Iteration H (explicitly declined)

- **Cisco UC** (CUCM, UDS, CTI) — separate future ADR if needed.
- **SIP / voice telephony** — separate future ADR if needed.
- **Modern team chat** (Matrix, Mattermost, Rocket.Chat) — separate future ADR if needed.
- **Password spray** — see D2 consequences.
- **OpenFire CVE plugin persistence** — the uploaded plugin is intended to be cleaned up via `--cleanup`. We do not ship a "leave-behind" variant.
- **Server-side request forgery via XMPP server-to-server** — interesting, but cross-realm reconnaissance and out-of-scope for a single-iteration ship.

## Revision policy

Changes to this ADR require either:
- A subsequent ADR superseding it (linked from `Status:` and from this ADR), or
- A note appended to "Decisions" with a date and the change reason.

Silent edits to past decisions are not allowed.

End of ADR-001.
