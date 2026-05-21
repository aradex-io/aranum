# ADR-004 — AD-depth tool dependency strategy (iteration D1)

| | |
|---|---|
| **Status** | Accepted (2026-05-20) |
| **Iteration** | D1 (introduced 2026-05-20) |
| **Tag** | `v0.17.0` |
| **Supersedes** | none |
| **Related** | REVIEW-001 §2.2 / §2.3 / §2.4 / §2.7, [ADR-001](ADR-001-19MAY2026-jabber-scope.md), CLAUDE.md §9 |

## Context

REVIEW-001 §2.2–§2.7 calls for AD-depth coverage that depends on external tools
which themselves require careful operator handling: BloodHound (graph
collection), Certipy (AD CS ESC1–8 enumeration), petitpotam.py (coerce probe),
plus the existing impacket suite. None of these are stdlib; all have install
gotchas; some have admin-vs-non-admin reach differences.

This ADR records the decisions that govern how the D1 dispatchers integrate
those tools.

## Decisions

### D1 — `bloodhound-python` is the BloodHound ingestor

**Decision:** `enum-ldap.sh` invokes `bloodhound-python` (or `bloodhound.py`)
when present and a credential is available. Output is the canonical
`<domain>_<timestamp>_*.json` set, zipped into `$OUT/ldap/<dc>/bloodhound.zip`.

**Reason:** the actively-maintained Linux-attacker-side ingestor; produces
BloodHound CE-compatible JSON; collection method `Default` covers the safe
subset (no Session collection on first run — that requires admin and is loud).
Alternatives considered:
- **AzureHound** — wrong scope (Entra ID, not on-prem AD).
- **`SharpHound.exe` via WinRM/SMB** — only works from a Windows host or
  requires running `SharpHound.exe` on the target, which itself violates
  CLAUDE.md §9 invariant 4 (persistence) if left in place.
- **`ldapdomaindump`** — outputs a smaller subset; lacks ACL/edge data;
  useful as a fallback but not the primary.

### D2 — `Certipy` is the AD CS enumerator

**Decision:** `enum-ldap.sh` runs `certipy find` when present. Output is the
text/JSON report under `$OUT/ldap/<dc>/certipy.txt` and `certipy.json`.
report.py rules parse the JSON for ESC1–8 findings → CRITICAL per finding.

**Reason:** Certipy is the cross-platform Python tool that runs from a
Linux attacker box (most other ESC enumerators are Windows-only / BOF).
Active maintenance; covers ESC1–11 categories; JSON output enables clean
downstream parsing.

### D3 — Graceful skip when an optional tool is missing

**Decision:** Every D1 dispatcher path that depends on an external tool MUST:

1. Check `command -v <tool>` first.
2. If missing: print a one-line `[skip] <feature> — <tool> not installed; <install hint>`
   AND continue with the dispatcher's other phases.
3. NEVER hard-fail the dispatcher because of a missing optional tool.

**Reason:** an operator with a deps-check-clean attacker box should get the
full output; an operator running with partial dependencies should still get
the non-blocked phases. Mirrors the existing `_lib.sh::have()` pattern.

`deps-check.sh` (D1.7) flags the new optional deps under a dedicated
"AD DEPTH" section so the operator knows what they're missing.

### D4 — Never auto-escalate to admin

**Decision:** None of the D1 enhancements REQUIRE admin credentials.
Operator-supplied creds are used as-is; the dispatchers do NOT attempt
`runas`, `psexec`, `gettgt -hashes`, or any other privilege boost. If the
operator HAS admin creds and wants admin-scoped reach (e.g. AS-REP roast
of every account regardless of `DONT_REQ_PREAUTH`), they pass those creds
directly — no implicit escalation by us.

**Reason:** mirrors G.8 invariant 1 (no implicit write/escalation). The
operator is the source of truth for what reach is appropriate. Admin-scoped
output is more dangerous in a transcript / report file; the operator opts
in by passing admin creds, not by our tool deciding for them.

### D5 — Coerce probes (PetitPotam) are detection-only

**Decision:** The PetitPotam check in `enum-smb.sh` confirms whether the
target's IPC$ pipe is reachable and whether `petitpotam.py` *would* succeed —
it does NOT actually trigger the coerce against an attacker-controlled relay.
The hint output documents the exact `ntlmrelayx` + `petitpotam.py` invocation
the operator would run AFTER confirming the test is in scope.

**Reason:** a real coerce + relay chain establishes attacker-side credential
capture and is a clear "write to target state" path (creates an NTLMv2 logon
on the relayed target). Per CLAUDE.md §9 invariant 1, that path requires
operator opt-in. Detection without opt-in is the right default.

### D6 — Output convention: raw tool output preserved + report.py rules parse signals

**Decision:** D1 dispatchers preserve EACH external tool's raw output
verbatim under `$OUT/<service>/<ip>_<port>/<tool>.{txt,json,zip}`. report.py
adds severity rules that classify lines in those files (e.g. Certipy's
`ESC1 (Vulnerable)` line → CRITICAL).

**Reason:** consistent with the existing dispatcher pattern (every tool's
raw output is preserved for the operator to grep/diff). Severity classification
is a post-walk concern; the scanner remains cheap and re-runnable.

### D7 — Windows PowerShell scripts (D1.4) ship as standalone files

**Decision:** The 8 new PS1 scripts (Get-LAPSPassword, Get-ADCSMisconfig,
Get-GPPCPassword, Get-DPAPIBlobs, Get-NamedPipes, Get-PrintNightmare,
Get-PetitPotamSignals, Test-CoercedAuth) ship as standalone files under
`windows/`. They are NOT folded into `Invoke-PrivEscEnum.ps1`.

**Reason:**
- They have distinct scope (AD-specific) vs. the local-privesc aggregator.
- Each carries a meaningful "what to check next" hint that aggregator output
  would dilute.
- The bulk-enum-windows.py orchestrator (K) ships `Invoke-PrivEscEnum.ps1`
  by default but accepts `--script PATH` — operators can ship any of the
  new scripts via the same transport when they want focused output.

The aggregator MAY later fold the most-useful checks (e.g. AlwaysInstallElevated
already in PrivEscEnum), but that's a separate decision recorded when made.

## What this ADR DOES NOT validate

The Linux + Windows side of D1 is testable in three dimensions:

1. **Syntax + lint** — every bash/PS1 script must pass `bash -n` / `pwsh -NoProfile -Command`.
2. **Graceful-skip behaviour** — every dispatcher must complete with rc=0 even
   when bloodhound-python / certipy / petitpotam.py are absent.
3. **Synthetic-output classification** — report.py's new rules anchored on
   fixture files mimicking each tool's output.

**Not testable on this codebase's CI** (Fedora Linux, no domain controller):
- BloodHound collection against a real DC (the JSON shape is stable enough that
  fixture-based testing is meaningful, but a real run end-to-end is engagement work).
- Certipy ESC findings against a real CA (same: fixture-based for report rules,
  real run is engagement work).
- PetitPotam coerce against a real DC (detection part is testable via the
  IPC$ probe; the coerce path is operator-gated).

Operators running D1 against their first AD environment should re-verify the
fixture assumptions match what their target actually emits, and file a
follow-up commit if the formats drift.
