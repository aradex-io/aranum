# REVIEW-011 — S4 `--local` access layer, independent diff review (Daybreak Blue)

- **Date:** 26 OCT 2026
- **Sprint:** S4 (`dev/local-access`), base `41860c8`, head `e5b0a6b` (6 commits).
- **Reviewer:** Daybreak Blue (`gpt-daybreak-blue-latest`, reasoning `xhigh`),
  cyber-tier peer — **not** the author model. Non-interactive file handoff;
  prompt + diff + plan section + declared exclusions supplied. Raw output:
  `build/scratch/s4-review/review.md` (exit 0).
- **Gate:** Phase-6 independent diff review. Verdict returned
  **CHANGES-REQUESTED**, 10 findings. This record classifies each against the
  code, with evidence, and states the disposition. ≤3 patch rounds.

## Declared out-of-scope (restated to the reviewer)

Tool-hardening / compliance-control findings on our own scripts; deliberate
constants (EXEC_CEILING tiers, compact-probe core budget) are features not bugs;
pwsh-7-vs-PS-5.1 runtime parity (structurally enforced, see CARD-S4 §b/c);
desktop rdp/vnc transport (S5). No finding was rejected on these grounds — all
10 landed in in-scope code.

## Round 1 — disposition by finding

Severity is the reviewer's; **Verdict** is this review's adjudication with
evidence (the reviewer proposes, it does not judge).

| # | Sev | Verdict | One-line basis |
|---|-----|---------|----------------|
| 1 | high | **CONFIRMED** | `IMPACKET_NOISE` strips `[+]`/`[-]`; `PROBE_PRIVS` emits privilege evidence on exactly those prefixes → evidence discarded. |
| 2 | high | **CONFIRMED (narrowed)** | Routing by `pathways[0]` is by design (prefer full engine); the real defect is a **dry-run PLAN row that advertises a compact-probe that never executes** when a full-engine pathway precedes it. Runtime cross-lane fallback is new behavior → backlog item, not this sprint. |
| 3 | high | **CONFIRMED (fix differs)** | `run_windows_engine` runs `run_bounded(timeout=0)` — unbounded. The windows engine has **no `--host-timeout` flag** (only the linux engine does), so the fix is a subprocess wall-clock cap, not flag-forwarding. |
| 4 | medium | **CONFIRMED** | Linux self-scan discards `rc`; `--self --linux-script /missing` (rc 127) records `status=OK`. |
| 5 | medium | **CONFIRMED (minor)** | No-pathway hosts are filtered out of execution; the planning-phase skip row exists, but a real run writes no per-host `_meta`, so an unreachable machine vanishes from the dashboard. |
| 6 | medium | **CONFIRMED (minor)** | `exec_argv` takes bare `host`; a non-default `HostSpec.port` is silently ignored (impacket exec has no SMB-port on the target string) with no warning. |
| 7 | medium | **CONFIRMED** | Dashboard: `if marked and host in bulk_host_index` attaches the bulk-host dir files to **every** `(host, svc)` pair, so a mixed host's genuine service card (e.g. `smb`) shows bulk-posture files instead of its own. |
| 8 | medium | **CONFIRMED** | Windows self-scan hardcodes `WIN_PRIVESC`, ignoring the existing `--windows-script` flag; the linux branch honors `--linux-script`. |
| 9 | medium | **CONFIRMED** | `_partition_local` matches exact option tokens only; `--targets=hosts.txt` (`--opt=value`) is misrouted. |
| 10 | low | **CONFIRMED** | `run_bounded`: a first-signal `ProcessLookupError` `break`s with `out`/`errb` unbound (the `for…else` is skipped) → `UnboundLocalError` on the exit race. |

All ten are real. No rejections. #2, #3 are confirmed but the stated remedy was
corrected against the code (narrowed scope / different mechanism, below).

## Fixes applied (round 1) — by class

**Class A — output/evidence fidelity (#1).** `clean_exec_output` must not treat
the compact probe's own `[+]`/`[-]` privilege lines as impacket noise. Fix:
once the probe's `PROBE_HEADER` sentinel is seen, keep every line verbatim
through `PROBE_END`; `IMPACKET_NOISE` is applied only *outside* that span (that
is where impacket's real banner/status chatter lives). Sweep identity:
`grep -n 'IMPACKET_NOISE\|PROBE_HEADER\|PROBE_END' local-enum.py` — one cleaner,
one call site (`run_exec_probe`); both covered.

**Class B — timeout enforcement (#3, #10).**
- #3: `run_windows_engine` now passes a subprocess wall-clock cap to
  `run_bounded` derived from `--host-timeout`. Because the engine runs a
  credential *group* (not one host) and has no per-host timer of its own, the
  cap is a generous whole-invocation bound `host_timeout × len(group)` (0 ⇒
  unbounded, unchanged). Recorded as a known approximation (the engine has no
  per-host timeout; this only guarantees a hung collector cannot run forever).
- #10: on `ProcessLookupError`, reap buffered output with `communicate()` before
  `break`, so `out`/`errb` are always bound.
- Sweep: every `run_bounded(` call audited for `timeout=0` on an external engine —
  linux (forwards `--host-timeout` to the script) and windows (now capped) are
  the only two; the compact probe already passed `timeout=args.host_timeout`.

**Class C — self-scan correctness (#4, #8).**
- #4: linux self-scan folds collector `rc` into status — non-zero rc with no
  timeout ⇒ `COLLECTOR_ERR` (rc recorded in `_meta`), not `OK`.
- #8: windows self-scan honors `--windows-script` for the privesc collector,
  symmetric with linux `--linux-script`.
- Sweep: both self-scan branches audited for every `args.*script` override flag
  defined in `build_parser` (`--linux-script`, `--linux-posture-script`,
  `--windows-script`); all now consumed. There is no `--windows-posture-script`
  flag, so none is owed.

**Class D — plan/execution completeness (#2, #5, #6).**
- #2: `plan_host` no longer appends an exec pathway that the executor will never
  run (a full-engine pathway already present). It still emits a plan row for
  operator visibility, now noted `superseded by winrm/ssh (compact probe runs
  only when it is the sole pathway)` instead of a misleading `fits=yes`. True
  runtime cross-lane fallback (run the full engine, fall back to exec on auth
  failure) is filed as **S4-BL-01** for a later sprint — it is new runtime
  behavior outside the S4 plan.
- #5: `execute_plans` writes a `status=SKIPPED` `_meta.json` for every planned
  host with no usable pathway, so an unreachable machine appears in the
  inventory as skipped rather than disappearing.
- #6: the exec path warns once when a host routed to an exec method carries a
  non-default `HostSpec.port` (impacket exec connects to the method's fixed
  SMB/DCOM port; the custom port cannot be honored — fail loud, don't silently
  ignore).

**Class E — dashboard evidence attribution (#7).** The marked-bulk-host evidence
branch is gated on the service being a bulk/posture pseudo-service
(`{linenum, winenum, posture}`); genuine service cards fall through to the
service-dir resolution. Sweep: the only place bulk-host files are attached is the
one `if marked and host in bulk_host_index` branch.

**Class F — argv partitioning (#9).** `_partition_local` splits `--opt=value` on
the first `=` and routes by the option name, matching the separate-token path.

## Backlog created

- **S4-BL-01** (gap, relevance 3): runtime cross-lane fallback — when a windows
  host's preferred full-engine pathway (winrm/ssh) fails at connect/auth time and
  a consent-gated exec method is also configured, run the compact exec probe as a
  true fallback. Deferred from S4: new runtime behavior, own test surface, not in
  the S4 plan. Tracked in PLAN-001 backlog.

## New tests (Phase 7b coverage for the fixes)

Added to `aranumtoolkit/tests/test_local_access.py`: probe `[+]`/`[-]`
preservation through the cleaner (#1); windows-engine subprocess cap derived from
`--host-timeout` (#3); `run_bounded` process-exit race returns bound output (#10);
self-scan `COLLECTOR_ERR` on non-zero rc (#4); windows self-scan `--windows-script`
honored (#8); dual-capability host exec row `superseded` + `pathways` honest (#2);
skipped-host `_meta` written (#5); exec custom-port warning (#6); mixed-host SMB
card resolves service-dir evidence not bulk files (#7); `_partition_local`
`--opt=value` routing (#9).

## Gate result

Round 1 resolved all 10 findings (8 fixed as stated, 2 fixed with a
code-corrected remedy, 1 sub-item backlogged with an ID). No class recurred.
**Phase-6 gate: GREEN.** Proceed to Phase 7 re-run.
