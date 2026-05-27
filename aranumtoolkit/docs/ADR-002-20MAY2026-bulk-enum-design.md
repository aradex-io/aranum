# ADR-002 — Bulk local-enum at scale (Linux first)

| | |
|---|---|
| **Status** | Accepted (2026-05-20) |
| **Iteration** | J (introduced 2026-05-20) |
| **Tag** | `v0.15.0` |
| **Supersedes** | none |
| **Related** | [ROADMAP-001](ROADMAP-001-19MAY2026-thoroughness-execution.md), [REVIEW-002](REVIEW-002-20MAY2026-write-gate-audit.md), CLAUDE.md §9 |

## Context

Through `v0.14.0` the toolkit covered two disjoint phases:

- **Pre-auth surface enumeration** — `aranumtoolkit/network/auto-enum.sh` against unauthenticated nmap output.
- **Post-foothold local enumeration** — `standalones/linux/linenum-fast.sh` and `standalones/windows/Invoke-PrivEscEnum.ps1` running on a single target.

The handoff between them was manual: the operator would obtain credentials, then copy the local-enum scripts to each target host (scp, zip, copy-paste). On an engagement spanning 50–500 hosts this becomes the dominant time sink and the dominant source of operator error (wrong script, forgotten step, lost output).

This ADR records the design of the **bulk-enum** layer that fills that gap.

## Decisions

### D1 — stdin-pipe over scp-then-execute

**Decision:** The orchestrator transports the enumeration script to the target via SSH's stdin (`ssh user@host bash -s -- -v < linenum-fast.sh`), not by copying the file with `scp` and then executing it.

**Reason:**
1. **No on-disk artifact on the victim.** The script lives only in the SSH session's memory and is gone when the session ends. No AV/EDR signature target on disk; no forensic trail beyond the SSH connection record.
2. **One round-trip.** scp + ssh is two connections + two auth handshakes per host. stdin-pipe is one. At 500 hosts the latency difference matters.
3. **Atomic — there is no half-installed state.** If the SSH connection drops mid-transfer, nothing was left on the target. With scp, partial uploads create cleanup work.
4. **The output channel is the input channel.** stdout from the remote `bash` flows back over the same authenticated, encrypted SSH session that delivered the command — no separate exfil mechanism is needed and the audit trail is one connection per host. Per CLAUDE.md §9 invariant 2 (no auto-exfil / no phone-home), the channel being the same one the operator initiated is the cleanest possible answer.

**Cost:** the local-enum scripts must be self-contained — no `source <other-file>`. They already are; this is documented and enforced by Iteration J's smoke test which runs each one in isolation.

### D2 — No "bundle" build step

**Decision:** `linenum-fast.sh` is shipped as-is to bulk-enum. There is no `make bundle` target that concatenates `standalones/linux/*.sh` into a single file.

**Reason:** investigation confirmed that `linenum-fast.sh` is already a superset of the 8 sibling scripts in `standalones/linux/`. The smaller scripts exist as standalone convenience tools for interactive use (operator wants JUST the SUID check, or JUST the cred-hunt with a custom `--paths` list). A bundle would either:
- Duplicate checks (running the same enum twice per host), or
- Replace `linenum-fast.sh` entirely (a refactor we don't need to do for the J iteration to land).

If a check in one of the smaller scripts later proves engagement-critical and is NOT in `linenum-fast.sh`, the fix is to fold it into `linenum-fast.sh` — separate task, separate commit, not infrastructure work.

### D3 — Per-engagement `known_hosts` silo

**Decision:** Every `bulk-enum-linux.sh` run writes to `$OUTDIR/known_hosts` rather than `~/.ssh/known_hosts`, using `-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$OUTDIR/known_hosts`.

**Reason:** at the user's target scale (50–500 hosts per engagement):
1. The operator's `~/.ssh/known_hosts` would balloon with entries from every engagement, mixing trust contexts that should be isolated.
2. A future engagement against an overlapping IP range would silently inherit a previous engagement's host keys — a wrong-but-cached key would be accepted as valid. **Engagement-scoped trust prevents this.**
3. `accept-new` means the first connection to each host is accepted (logged in the per-engagement file) and subsequent connections in the same engagement verify against that record. Within an engagement, MITM detection still works; across engagements, no cross-contamination.

The operator can override (`--ssh-opt 'UserKnownHostsFile=~/.ssh/known_hosts'`) for the unusual case where shared trust is desired — but it is opt-in, not the default.

### D4 — `--throttle` parity with `auto-enum.sh`

**Decision:** `bulk-enum-linux.sh --throttle` collapses to `-P 1` + per-host `ENUM_THROTTLE_DELAY` sleep (default 1s), reusing the helpers introduced in G.7.

**Reason:** OT / lab / engineering hosts often run services that don't tolerate concurrent SSH sessions; some legacy SSH daemons crash on rapid sequential auth. Operators who reach for `--throttle` on `auto-enum.sh` will reach for it here for the same reasons. Sharing the flag name and semantics is one less thing to remember.

### D5 — Verdict logic lives in `report.py`, not the scanner

**Decision:** `bulk-enum-linux.sh` only captures raw output. The per-host CRITICAL/HIGH/MEDIUM/LOW verdict is assigned by `aranumtoolkit/network/report.py` post-walk.

**Reason:**
- The scanner stays cheap and re-runnable; the analyser is independent.
- Verdict rules will evolve as engagement experience accumulates. Keeping them in one analyser file means an operator can update verdicts without re-running the scan.
- `report.py` already produces `findings.json` + `report.md` + `report.html` for `auto-enum.sh` outputs — extending it to recognise bulk-enum outputs reuses the existing reporting infrastructure rather than building parallel report machinery.

### D6 — Windows orchestration deferred to v0.16.0 (next iteration, "K")

**Decision:** Iteration J ships **Linux only**. Windows orchestration lands as iteration K (`v0.16.0`).

**Reason:** WinRM as a low-privileged domain user requires explicit "Remote Management Users" group membership, which most environments do not grant. SMB + wmiexec needs admin. SSH-on-Windows is rare in real environments. Building a Windows orchestrator before validating the design against a real engagement would be speculative architecture. Once Linux is proven in the field, the Windows transport (`pywinrm` via `Invoke-Command -ScriptBlock`) lands with the realistic-reach caveats documented up front.

### D7 — Operator scale tuning for 50–500 hosts

**Decision:** Default parallelism is 4 (`auto-enum.sh` parity), capped at 16 unless the operator explicitly raises it. SSH per-connection options:
- `BatchMode=yes` — no interactive password prompts; auth must work on first try
- `ConnectTimeout=10` — fast failure on dead hosts
- `ServerAliveInterval=15` `ServerAliveCountMax=4` — detect dropped sessions in <1 min
- `StrictHostKeyChecking=accept-new` + per-engagement `UserKnownHostsFile`
- `LogLevel=ERROR` — suppress the per-connection banner spam at scale

**Reason:** at 50–500 hosts:
- `MaxStartups` exhaustion (the SSH daemon's pending-auth queue) only becomes a problem above ~10 simultaneous connections to ONE target. With per-target connections distributed across N targets, default 4 is fine.
- `known_hosts` lookup time is linear in the file's host count; per-engagement files keep this small.
- Interactive password prompts cannot be allowed — at 500 hosts, the operator cannot babysit auth.

If scale ever crosses 5000 the design has to change (batch + persistent queue + async-io). This ADR explicitly scopes 50–500 and flags the 5000+ revisit.

## Out of scope for J (explicitly)

- **No agent / no persistence.** Per CLAUDE.md §9 invariant 4. Bulk-enum is a one-shot per host; nothing lives on the victim afterwards.
- **No detection-evasion.** Per CLAUDE.md §9 invariant 5. AMSI/ETW/EDR bypass logic does not belong in this iteration and is forbidden in this repo at all.
- **No automated exploitation.** This iteration runs enumerators only. CRITICAL verdicts from `report.py` point the operator at the relevant follow-up script (e.g. `redis-rce-ssh.sh --write`) which carries its own G.8 write gate.
- **No credential capture.** Auth is one-shot per host using already-obtained creds. There is no spray, no harvest, no shadow-file copy-out beyond what `linenum-fast.sh` already prints to stdout.

## Open question recorded for v0.16.0 (Iteration K — Windows)

Should the Windows orchestrator default to WinRM-only (covering the "Remote Management Users" subset only) and document SMB-admin as a separate `--use-smb-admin` flag? Or should it auto-fall-back? Recommendation: WinRM-only by default, no auto-fallback; if the operator has admin creds they can ask for `--use-smb-admin` explicitly. This mirrors the `--exploit` opt-in pattern from G.8 — the operator must explicitly request the higher-privilege path.

To be decided in ADR-003 when iteration K lands.
