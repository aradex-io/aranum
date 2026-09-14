# R1 Quality Remediation Implementation Report

**Date:** 2026-09-14
**Branch:** `codex/aranum-r1-14sep2026`
**Baseline:** `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
**Scope:** R1 only: S1-01 through S1-23, S2-01 through S2-04, and S3-01
through S3-03. Aranum self-security and live-target scanning were excluded.

## Outcome

All 30 validated R1 findings are implemented with regression coverage. No item
in the ledger below is merely planned, and there is no known implementation
blocker. Tests use synthetic files, local shims, mocked transports, and local
loopback fixture servers only.

## Implementation ledger

| ID | Status | Implemented behavior and principal evidence |
|---|---|---|
| S1-01 | Complete | `report.py` caches compiled prefilters by immutable rule signature rather than transient object identity; 5,000 ephemeral-rule lifecycles are compared to direct classification. |
| S1-02 | Complete | `auto-enum.sh` records current-run service failure state atomically and exits 4 when any selected dispatcher fails. |
| S1-03 | Complete | Serial and parallel summaries consume run-scoped atomic result records; resume skips cannot inherit stale `.rc` data and are counted in the parent process. |
| S1-04 | Complete | Planner task IDs include host, port, protocol, service, and phase; same-port TCP and UDP tasks remain distinct. |
| S1-05 | Complete | Planner deduplicates stable tasks before sharding; shard fixtures prove disjoint task IDs. |
| S1-06 | Complete | Queue mode invokes the real dispatcher once per selected task with an exact one-endpoint target file and parsed task/service/phase/protocol/risk/priority/target arguments. `service-metadata.json` is the fleet-wide execution-capability authority: explicitly phase-aware FTP/SSH expose independently executable phase tasks, while every monolithic dispatcher exposes one canonical `all` task per endpoint and rejects staged records before dispatch. Dispatcher-authored context and task-scoped exit records provide exact completion. Real FTP phase 1 performs banner discovery only while phase 2 performs anonymous/auth enumeration; its Nmap and credentialed NXC paths honor the selected port, including mixed-port target sets. SSH phase 1 remains gated from phase-2 auth-posture logic. No `ENUM_TASK_FILE` handoff remains. |
| S1-07 | Complete | Queue JSONL is fully parsed and schema/range validated before dispatch; malformed/conflicting records and an explicitly supplied empty queue fail nonzero. Exact duplicates collapse deterministically, while a nonempty queue intentionally filtered to zero by priority succeeds with an empty authoritative state. |
| S1-08 | Complete | `aranum.py` treats `--service-parallel` as a value-taking run option, preserving option/value ordering. |
| S1-09 | Complete | `nmap-parse.py` emits a separate all-host inventory for XML, gnmap, and normal output and distinguishes `hosts_up` from `hosts_with_open_ports`. |
| S1-10 | Complete | `iterative-enum.sh` mines documented prior raw SMB evidence and produces sorted, deduplicated, repeat-stable user inputs. |
| S1-11 | Complete | Global service metadata no longer suppresses severity-derived confidence/priority/actions; critical defaults resolve to high/P0 unless explicitly overridden. |
| S1-12 | Complete | Metadata merge order is repository defaults, output-root metadata, then run-local metadata, so the closest explicit override wins. |
| S1-13 | Complete | Explicit custom severity rules precede defaults and therefore implement the documented override contract. |
| S1-14 | Complete | Report summaries include assessed-clean, failed, skipped, unassessed, and confirmed endpoint coverage independent of finding presence. Queue state is authoritative even when empty: failure/skip and endpoints absent from the selected queue cannot be overwritten by stale `.done`, rc=0, service evidence, or findings. Output-local queue state is exclusive; parent fallback records are accepted only when local state is absent and their run ID matches current run state when available. |
| S1-15 | Complete | Findings deduplicate by logical endpoint/severity/complete evidence identity and retain all `evidence_paths`, preventing dispatcher/host double counting. |
| S1-16 | Complete | `autoenum-diff.sh` identity includes host, port, protocol, service, severity, and the complete evidence identity; port-only and long-tail changes are detected. |
| S1-17 | Complete | Merged output emits schema version `"2"` and rejects sources that do not declare the supported schema. |
| S1-18 | Complete | Merge derives `redacted` and `redaction_state` (`unredacted`, `redacted`, or `mixed`) from every source. |
| S1-19 | Complete | Evidence paths are published only after successful copies; missing/failed copies get explicit status, warnings, `complete=false`, and process exit 3. |
| S1-20 | Complete | Recce export auto-discovers `raw/inventory.json` and XML, gnmap, or normal scan inputs. |
| S1-21 | Complete | Recce endpoint resolution preserves explicit transport protocol and refuses ambiguous or absent protocol inference instead of fabricating TCP. |
| S1-22 | Complete | Recce `vuln_scanned`/host `enumerated` state derives from successful exact-endpoint coverage or a non-superseded exact finding; authoritative failed/skipped/unassessed state wins over older success/finding evidence, and queue-unselected/discovery-only ports remain incomplete. |
| S1-23 | Complete | Shared report finalization parses exact, address-family-delimited endpoint tokens, including bracketed and bare IPv6 host:port, and cannot confuse an IPv4/IPv6 prefix with a different host. |
| S2-01 | Complete | `_lib.sh::parse_common_args` rejects failed/non-directory evidence paths immediately; representative dispatchers already propagate its nonzero status. |
| S2-02 | Complete | Linux and Windows bulk artifacts use readable collision-safe user/host/port/platform endpoint IDs and atomic endpoint manifests; repeated rows are deduplicated. |
| S2-03 | Complete | Non-resume workers invalidate old `.done` state before transport, recreate it atomically only on success, and preserve it only for explicit resume skips. |
| S2-04 | Complete | Both bulk runners validate parallelism as an integer in 1..16 before creating workers or invoking `xargs`. |
| S3-01 | Complete | Dependency checks probe the named executable/capability, treat exit 126/127 shims as unusable, fix package-hint aliases, aggregate required misses, and return nonzero only for required failure. |
| S3-02 | Complete | `make lint` first verifies `shellcheck --version`; an absent/broken executable activates the full tracked-shell `bash -n` fallback. |
| S3-03 | Complete | Local `make test` and CI both declare lint, unittest, pytest, smoke, and data-audit components; CI installs pytest and invokes each named gate visibly. |

## Files changed by concern

- Gate/CI: `.github/workflows/ci.yml`, `Makefile`, `deps-check.sh`,
  `aranumtoolkit/tests/smoke.sh`.
- CLI/planning/campaign: `aranum.py`, `aranumtoolkit/network/auto-enum.sh`,
  `plan.py`, `nmap-parse.py`, `iterative-enum.sh`, `_lib.sh`, `enum-ssh.sh`.
- Reporting/merge/diff: `report.py`, `report-dashboard.py`,
  `service-metadata.json`, `autoenum-diff.sh`, `merge-results.py`.
- Interop/bulk state: `aranum_to_recce.py`, `bulk-enum-linux.sh`,
  `bulk-enum-windows.py`.
- Regression tests: `test_r1_remediation.py`, `test_quality_gate_r1.py`,
  `test_interop_recce.py`, `test_merge_results.py`, `test_phase1_hardening.py`.
- Documentation: `CHANGELOG.md`, `aranumtoolkit/docs/SCHEMA.md`,
  `aranumtoolkit/docs/ADR-002-20MAY2026-bulk-enum-design.md`,
  `aranumtoolkit/interop/README.md`, and this report.

## Verification evidence

- Focused pre-existing regression set: `148 passed, 5 skipped, 48 subtests
  passed in 11.74s`.
- R1 adversarial and quality-gate tests: `19 passed in 10.52s` before the
  added bulk migration/state boundary cases; those cases also passed under
  `make unittest` and the full pytest run.
- Initial `python3 -m pytest aranumtoolkit/tests -q`: `323 passed, 5 skipped,
  68 subtests passed in 41.44s`.
- Post-verifier focused endpoint/coverage gate: `44 passed, 1 skipped in
  7.24s` across R1, report/dashboard, structured-finding, and Recce tests.
- Post-verifier full `python3 -m pytest aranumtoolkit/tests -q`: `325 passed,
  5 skipped, 68 subtests passed in 40.73s`.
- Final anti-pattern closure gate (`test_r1_remediation.py`, Recce,
  dispatcher-contract, structured-finding, and dashboard tests): `55 passed,
  1 skipped, 43 subtests passed in 12.58s`.
- Final `python3 -m pytest aranumtoolkit/tests -q`: `329 passed, 5 skipped,
  68 subtests passed in 56.23s`.
- Release-blocker focused R1 run after the generic FTP phase contract and stale
  queue-state lifecycle fix: `23 passed in 10.33s`.
- Release-blocker adjacent planner/CLI/report/Recce run: `65 passed, 1 skipped,
  5 subtests passed in 5.33s`.
- Release-blocker full `python3 -m pytest aranumtoolkit/tests -q`: `331 passed,
  5 skipped, 68 subtests passed in 52.50s`.
- Release-blocker focused unittest orchestrator run: `6 tests`, `OK` in
  `6.842s`.
- Final queue-authority focused report/R1/Recce run: `51 passed, 1 skipped in
  8.86s`.
- Final queue-authority full `python3 -m pytest aranumtoolkit/tests -q`: `332
  passed, 5 skipped, 68 subtests passed in 40.28s`.
- Final queue-authority focused unittest run: `13 tests`, `OK` in `5.436s`.
- Fleet-wide phase-capability focused planner/queue/dispatcher/report run: `97
  passed, 1 skipped, 48 subtests passed in 40.56s`.
- Fleet-wide phase-capability full `python3 -m pytest aranumtoolkit/tests -q`:
  `334 passed, 5 skipped, 68 subtests passed in 70.16s`.
- Fleet-wide phase-capability focused unittest run: `12 tests`, `OK` in
  `31.032s`.
- Final hermetic SMB monolithic/rejected-phase regression: `1 passed in 0.67s`;
  every external dispatcher dependency was shimmed locally.
- Final planner plus R1 phase-capability regression: `30 passed in 6.47s`.
- Final FTP credential-port regressions: `2 passed in 0.76s`; hermetic NXC
  shims required explicit TCP 2121 and exact host partitioning across TCP
  2021/2121, and rejected any default-port-21 invocation.
- Final planner plus R1 regression after FTP credential-port closure: `31
  passed in 6.55s`.
- Final full `python3 -m pytest aranumtoolkit/tests -q` after FTP
  credential-port closure: `335 passed, 5 skipped, 68 subtests passed in
  40.49s`.
- Release-blocker full `make unittest`: `305 tests`, `OK (skipped=5)` in
  `41.453s`.
- Final `make unittest`: `303 tests`, `OK (skipped=5)` in `44.748s`.
- `make lint`: exit 0; ShellCheck unavailable, full tracked-shell `bash -n`
  fallback passed.
- `make data-audit`: exit 0; both governed data sources reported current.
- Final isolated `make smoke`: `PASS=374`, `FAIL=0`, `SKIP=1`. Immediately
  before the run, no other smoke/FP harness process and no listener on fixed
  loopback ports 19000/19010 existed. The FP/TP harness completed with no false
  positives and intact true-positive markers.
- Final static gate (`bash -n`, `py_compile`, metadata JSON validation,
  `git diff --check`, and branch assertion): exit 0.

The five skips are environmental optional adapters: pywinrm transport tests and
the Recce end-to-end adapter. Their protocol/state translation and transport
selection paths remain covered by mocked or dependency-independent tests.

## Migration/operator notes

- Bulk resume state now keys on full endpoints. An existing host-only directory
  is migrated only when exactly one requested endpoint maps to that host.
  Ambiguous legacy state exits 2 with corrective guidance; no guess is made.
- `merge-results.py` now returns 3 for a completed merge with incomplete
  evidence provenance. Consumers must treat exit 3 plus `complete=false` as a
  partial artifact, not full success.
- `deps-check.sh` returning 1 now means at least one required executable or
  required Python standard-library capability is genuinely unusable; optional
  misses stay informational.

## Verification re-review closure

The first independent verification returned `REQUEST_CHANGES` on two concrete
cases. Both are closed in the post-verifier test results above:

1. Endpoint attribution no longer performs substring matching. Adversarial
   fixtures distinguish `10.0.0.1` from `10.0.0.10`, reject
   `10.0.0.100` as a match for either, and attribute both
   `2001:db8::1:6379` and `[2001:db8::2]:6379` exactly.
2. Queue `failed`/`skipped` records are authoritative. Fixtures combine those
   records with stale `.done`, `.rc=0`, matched evidence, and an older
   `assessed_clean` record; report coverage remains failed/skipped and the Recce
   success set remains empty.

The final anti-pattern verification also returned `REQUEST_CHANGES`. Its five
concrete blockers are closed with production-path adversarial evidence:

1. The copied real `enum-ssh.sh` and `_lib.sh` execute once per selected task,
   consume the exact task/service/phase/protocol/risk/priority/target arguments,
   and reject a service-wide two-target substitution. Dispatcher-authored
   `_task-context.json` and task-specific process exit state are the completion
   authority; the fake `ENUM_TASK_FILE` path was removed.
2. With only phase 1 selected, one exact endpoint is probed and no phase-2
   key-only artifact is produced. A phase-2-only run produces that artifact,
   proving the selected phase controls the real SSH dispatcher path.
3. An authoritative queue containing only `192.0.2.22:22/tcp` leaves the
   inventory endpoint `192.0.2.23:22/tcp` unassessed despite service-level
   `.done`, rc=0, evidence, or a finding; Recce excludes it from successful
   coverage.
4. A whitespace-only explicitly supplied queue exits nonzero. A nonempty queue
   filtered to zero selected tasks exits zero with an empty authoritative state.
   An exact duplicate executes and writes state once rather than raising a
   `TypeError`; conflicting duplicates still fail closed.
5. Protocol-less Recce inventory records are skipped and a protocol-less
   finding without an unambiguous source remains unresolved instead of becoming
   TCP.

The release-blocker re-verification found two additional production-path gaps;
both are closed without weakening the prior R1 guarantees:

1. Phase constraints are no longer an SSH-only special case. The shared
   dispatcher phase contract is exercised by the copied real `enum-ftp.sh`:
   phase 1 produces banner evidence and cannot produce anonymous-listing/auth
   evidence, while phase 2 produces the enumeration evidence and does not run
   the banner block. Both exact task contexts and queue completion records carry
   their selected phase.
2. After a successful, non-dry-run, non-queue execution in an output directory,
   `auto-enum.sh` moves both queue-state locations consumed by `report.py` (the
   output-local snapshot and the sibling written next to an external queue) to
   run-ID-suffixed stale archives. An older queue campaign therefore cannot
   remain authoritative for fresh service-batch results, while both prior
   snapshots remain available for audit.

Final queue-authority verification then identified that merely archiving state
after a successful non-queue run was insufficient: report generation could
merge an output-local current queue snapshot with a stale sibling snapshot from
an external queue campaign. The production reader and publisher now enforce a
single campaign boundary:

1. `report.py` uses `OUTDIR/queue.state.jsonl` exclusively whenever it exists;
   the parent path is a legacy fallback only when the local path is absent.
2. `auto-enum.sh` publishes `execution_mode` and `queue_authoritative` in
   `run-state.json`. Queue records already carry `run_id`; when current run state
   provides an ID, records without that exact ID cannot influence coverage.
3. The regression combines a current local queue, a stale external-parent queue,
   service-wide success artifacts, and an unselected endpoint. The stale parent
   cannot mark that endpoint assessed. It also proves that a matching-run parent
   snapshot remains usable when the local compatibility copy is unavailable.

The fleet-wide S1-06 release gate then found that reusable phase helpers alone
did not prevent the other multi-phase metadata entries from planning duplicate
full-dispatcher executions. That gap is closed through one authoritative
capability contract rather than edits across the dispatcher fleet:

1. `service-metadata.json` defaults `task_execution` to `monolithic` and marks
   only the independently split FTP and SSH implementations as `phased`.
2. `plan.py` emits one canonical `all` task per monolithic service endpoint;
   phased services retain their declared phases, risk, priority, and
   protocol-aware task identity. A partial phase filter cannot select a
   monolithic full assessment.
3. `auto-enum.sh` and `_lib.sh` consume the same metadata contract. Crafted SMB
   phase-1/phase-2 tasks fail before the real dispatcher starts; a canonical SMB
   task runs the complete real dispatcher exactly once.
4. A real FTP phase-2 task on TCP 2121 proves both phase separation and that the
   Nmap command receives `-p2121`, not the old hard-coded `-p21`.
5. Credentialed NXC checks retain the same endpoint identity: targets are
   grouped by their selected port, every invocation receives an explicit
   `--port`, and mixed 2021/2121 endpoints are sent only to their matching NXC
   call. The hermetic 2121 regression rejects an implicit/default port-21 path.

An additional isolated smoke run was not started for these release-blocker
passes because parallel remediation sprints owned the shared fixed loopback
fixture ports.
The last isolated R1 smoke result remains `PASS=374`, `FAIL=0`, `SKIP=1`; the
new release-blocker paths are covered by subprocess-level real dispatcher and
orchestrator regressions in both pytest and unittest.

## Blockers and exclusions

No implementation blocker. Optional pywinrm and Recce packages are unavailable
on this host, so those live adapters were not exercised. No live target,
external network scan, commit, push, or aranum self-security work was performed.
