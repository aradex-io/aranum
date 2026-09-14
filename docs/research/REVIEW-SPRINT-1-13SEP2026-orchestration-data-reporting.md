# Aranum Comprehensive Quality Review — Sprint 1

Date: 13 September 2026
Baseline: `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
Sprint: Orchestration, Data Flow, and Reporting
Review mode: read-only product review; only this report was added
Explicit exclusion: security of aranum itself

## Outcome

Sprint 1 found 23 reproducible or source-demonstrable functional and quality issues: 11 high and 12 medium severity. The highest-impact themes are silent loss of valid findings, dispatcher failures reported as successful runs, planner identity collisions across TCP/UDP, queue phase claims that do not constrain execution, triage metadata that demotes every finding to `P3`, and recce exports that both fabricate TCP records for UDP findings and mark unexecuted ports as scanned.

| Severity | Count |
|---|---:|
| High | 11 |
| Medium | 12 |
| Low | 0 |
| Total | 23 |

## Findings

### S1-01 — Prefilter cache can silently drop valid findings after Python reuses a list ID

- **Category:** False negative / report data integrity
- **Severity:** High
- **File and line:** `aranumtoolkit/network/report.py:458-480`, with short-lived rule lists created at `aranumtoolkit/network/report.py:900-901`
- **Background/details:** `_PREFILTER_CACHE` is keyed only by `id(rules)`. The cache retains the integer ID but not the list, so after a rules list is freed Python may assign the same ID to a different list. `_classify()` then uses a combined regex compiled for the former rules and may return `None` before checking the current rules. `walk_findings_bulk()` constructs new Linux and Windows lists on each call, making this reachable in normal tests and reports.
- **Observable impact:** Findings disappear intermittently. The baseline test run observed missing `win-svc-imperson` and `win-backup-op` host verdicts; an immediate rerun passed. This is a silent false-negative condition in the main report.
- **Evidence/reproduction:** An isolated loop classified an `ALPHA_ONLY` list, deleted it, then created a `BETA_ONLY` list. Python reused the list ID at iteration 1; `_classify("BETA_ONLY", rules)` returned `None` while a direct rule loop returned `critical`: `{'iteration': 1, 'cached': None, 'bruteforce': 'critical'}`.
- **Proposed remediation:** Key the cache by an immutable rule signature such as `(pattern, flags, severity)` tuples, or cache an object that retains and identity-checks the original rule list. Add a regression that forces alternating ephemeral rules and compares the prefilter result with a brute-force classifier.

### S1-02 — A run with failed dispatchers exits successfully

- **Category:** Failure semantics / automation correctness
- **Severity:** High
- **File and line:** `aranumtoolkit/network/auto-enum.sh:502-511`, `aranumtoolkit/network/auto-enum.sh:548-561`, and caller behavior at `aranum.py:634-648`
- **Background/details:** The orchestrator increments `RUN_FAIL`, records the failing service, and prints a failure summary, but its final command is an informational `echo`. There is no final nonzero exit based on `RUN_FAIL`. The unified CLI trusts the subprocess return code and may generate reports/dashboard artifacts after the failed run.
- **Observable impact:** Schedulers, CI, and operators receive overall success for incomplete enumeration. Downstream reporting can be treated as complete even though one or more service families were not assessed.
- **Evidence/reproduction:** A copied orchestrator fixture used a synthetic `enum-ssh.sh` that exited 7. The dispatcher `.rc` contained `7`, but `auto-enum.sh` returned `0`.
- **Proposed remediation:** Define a documented partial-failure exit code and `exit` with it when `RUN_FAIL > 0`; preserve an explicit override only if partial success is intentionally accepted. Ensure `aranum.py` does not chain reports as a successful run when enumeration returned that status.

### S1-03 — Parallel summaries reuse stale `.rc` files and lose skip counts

- **Category:** Run-state accounting / resume correctness
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/auto-enum.sh:413-418`, `aranumtoolkit/network/auto-enum.sh:510-535`
- **Background/details:** Background dispatchers run in subshells, so the parallel path rebuilds only OK/FAIL counts from persistent `<service>/.rc` files. Early-return paths such as `--resume`, no dispatcher, zero targets, dry-run, and manual/OT skips do not replace or clear `.rc`. Their `RUN_SKIP` increments are also lost with the subshell.
- **Observable impact:** A resumed successful service can be reported as failed because of an old `.rc`; parallel output always under-reports skips. This makes run journals unreliable for enterprise retry decisions.
- **Evidence/reproduction:** With `ssh/.done` present and a stale `ssh/.rc` containing `9`, `--resume --service-parallel 2` returned 0 and printed `Dispatcher results: OK=0 FAIL=1 SKIP=0`; the service was actually resume-skipped.
- **Proposed remediation:** Use a run-scoped result directory or PID/result records created for every service outcome, including skip reasons. Clear legacy `.rc` before dispatch and aggregate only current-run records.

### S1-04 — Planner task identity omits protocol and collapses TCP/UDP work

- **Category:** Protocol identity / queue data loss
- **Severity:** High
- **File and line:** `aranumtoolkit/network/plan.py:293-301`, `aranumtoolkit/network/plan.py:383-400`, `aranumtoolkit/network/plan.py:412-420`
- **Background/details:** Tasks retain `proto` in their records, but `task_id`, `target_label`, and `output_hint` use only service, IP, port, and phase. The deduplicator uses `task_id`, so TCP and UDP instances of the same service/IP/port/phase collide.
- **Observable impact:** One valid protocol is silently removed from the execution queue. State overlays also cannot distinguish protocol-specific outcomes.
- **Evidence/reproduction:** Two synthetic DNS entries for `192.0.2.10:53`, one TCP and one UDP, produced four pre-dedup tasks but only two queue tasks. Both surviving tasks were TCP and IDs were `dns::192.0.2.10:53:{1,2}`.
- **Proposed remediation:** Include protocol in `task_id`, labels, output hints, sort keys, execution target syntax, and state records. Add mixed-protocol same-port queue tests.

### S1-05 — Sharding occurs before deduplication, so shards can overlap

- **Category:** Distributed execution / queue partitioning
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/plan.py:402-420`
- **Background/details:** The task list is partitioned by list position at lines 407-410 and deduplicated only afterward. Duplicate source records can therefore land in different shards with the same task ID.
- **Observable impact:** Workers believed to own disjoint shards can execute the same host/service/phase. This wastes scan capacity, duplicates evidence, and complicates completion accounting.
- **Evidence/reproduction:** Two identical UDP DNS inventory entries were planned as shards `1/2` and `2/2`. Both shards contained both task IDs (`dns::192.0.2.10:53:1` and `:2`), yielding a complete overlap.
- **Proposed remediation:** Deduplicate on the full canonical task identity before computing `tasks_pre_shard` and applying shard selection. Add an invariant test that the pairwise intersection of all shard task-ID sets is empty.

### S1-06 — Queue phases and priorities are advisory; execution ignores them and marks all phases complete

- **Category:** Planning/execution contract / false completion
- **Severity:** High
- **File and line:** `aranumtoolkit/network/auto-enum.sh:286-305`, `aranumtoolkit/network/auto-enum.sh:423-500`, with phase tasks created at `aranumtoolkit/network/plan.py:342-400`
- **Background/details:** The queue selector reduces tasks to a unique service list and then a unique set of `host:port` targets. It never passes the phase, protocol, task ID, risk, or priority to the dispatcher. After one whole-service dispatcher call, state writeback marks every queue item for that service `done` or `failed`. A priority threshold can select a phase-1 target but the unscoped dispatcher can still execute deeper checks represented by filtered-out phase-2 tasks.
- **Observable impact:** `--phase`, profile phase filters, and `--skip-low-priority` do not reliably constrain actual activity, while queue state claims granular phase completion that did not occur as modeled.
- **Evidence/reproduction:** A queue with SSH phase 1 and phase 2 generated one fake-dispatcher invocation; `queue.state.jsonl` then marked both `ssh::10.0.0.6:22:1` and `:2` as `done`.
- **Proposed remediation:** Either make dispatcher entrypoints phase/task aware and invoke the selected tasks, or change the planner to model the actual whole-dispatcher batch as one task. State must be written only for work actually executed.

### S1-07 — A malformed execution queue becomes an empty successful campaign

- **Category:** Input validation / fail-open orchestration
- **Severity:** High
- **File and line:** `aranumtoolkit/network/auto-enum.sh:286-306`, followed by the unconditional success path at `aranumtoolkit/network/auto-enum.sh:542-561`
- **Background/details:** The queue-reading Python command in command substitution does not catch JSON errors, and the shell does not check that substitution's status. A decode traceback leaves `ALL_CATEGORIES` empty; the orchestrator proceeds with no services and ends successfully.
- **Observable impact:** Queue corruption or partial writes can turn a planned enterprise run into a silent no-op that automation records as complete.
- **Evidence/reproduction:** A queue containing `{broken json` emitted a `JSONDecodeError`, printed `Will run:` with no services and `OK=0 FAIL=0 SKIP=0`, then returned 0.
- **Proposed remediation:** Validate the entire JSONL queue before creating output/run state; reject malformed or schema-invalid records with a nonzero usage/data error. Check every helper/substitution status and reject an unexpectedly empty queue unless explicitly allowed.

### S1-08 — Unified run shorthand mistakes `--service-parallel`'s value for the scan input

- **Category:** CLI argument propagation
- **Severity:** Medium
- **File and line:** `aranum.py:65-81`, `aranum.py:587-629`; supported option parsed at `aranumtoolkit/network/auto-enum.sh:151`
- **Background/details:** `_first_bare_arg()` depends on a manual set of value-taking auto-enum flags. `--service-parallel` is absent, so its numeric value is selected as the shorthand input when it appears before the scan token.
- **Observable impact:** The documented unified CLI form becomes unusable with a normal scale-control option ordering and reports the parallel count as a missing input file.
- **Evidence/reproduction:** `_prepare_run_args(['--service-parallel','4','scan.xml','--dry-run'])` produced `['-i','4','--service-parallel','scan.xml','--dry-run']`. The equals form happened to work.
- **Proposed remediation:** Use one shared argument schema/parser rather than a duplicated option set, or at minimum add the flag and regression-test every value-taking auto-enum option before and after the shorthand scan token.

### S1-09 — “Hosts up” excludes live hosts that have no open ports

- **Category:** Inventory coverage / misleading summary
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/nmap-parse.py:244-270`, `aranumtoolkit/network/nmap-parse.py:470-477`; displayed as “Hosts up” at `aranumtoolkit/network/auto-enum.sh:273-283` and reused by `aranumtoolkit/network/plan.py:423-426`
- **Background/details:** The parser emits only open-port entries and derives host count from those entries. It does not preserve up-host status separately.
- **Observable impact:** Live but filtered/no-open-port systems disappear from coverage metrics, making network reachability and assessment completeness look better or smaller than reality.
- **Evidence/reproduction:** Synthetic XML with two `state="up"` hosts, one without open ports, emitted one entry and a summary host count of 1 rather than 2.
- **Proposed remediation:** Parse host status independently from services and expose separate `hosts_up`, `hosts_with_open_ports`, and possibly `hosts_down` counts/records. Keep dispatcher entries port-based.

### S1-10 — Iterative enumeration does not mine prior SMB usernames from `--enum-output`

- **Category:** Iterative evidence mining / feature disconnect
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/iterative-enum.sh:117-126`, `aranumtoolkit/network/iterative-enum.sh:359-365`
- **Background/details:** The command promises to mine SMB output from `--enum-output`, but username extraction searches only the new `$OUTDIR/smb` and `$OUTDIR/../smb`. In the unified layout those are `session/inputs/smb` and `session/smb`, while prior evidence is under `session/raw/smb` (`$ENUM_OUT/smb`).
- **Observable impact:** Valid usernames learned during the first pass are not fed into follow-up enumeration, reducing the value of the iterative workflow.
- **Evidence/reproduction:** A synthetic raw tree with `raw/inventory.json` and `raw/smb/prior.txt` containing `user: alice` completed successfully, but the generated `inputs/smb/users.txt` was empty.
- **Proposed remediation:** Search explicit, bounded paths under `$ENUM_OUT/smb` in addition to current-pass outputs. Add a fixture that proves a prior username appears in the consolidated list.

### S1-11 — Global metadata defaults demote every structured finding to `P3`

- **Category:** Triage prioritization / metadata semantics
- **Severity:** High
- **File and line:** `aranumtoolkit/network/service-metadata.json:15-17`, `aranumtoolkit/network/report.py:211-229`, and dashboard ranking at `aranumtoolkit/network/report-dashboard.py:265-282`
- **Background/details:** Report generation is written to derive confidence, priority, and next actions from severity when metadata is absent. However, the global metadata defaults always supply `confidence=medium`, `priority=P3`, and one generic next action, so the severity fallbacks never execute for any service unless explicitly overridden. No service overrides priority or confidence.
- **Observable impact:** A critical finding is sorted as low-priority work (`P3` maps to 350), damaging the operator inbox and remediation order.
- **Evidence/reproduction:** `_structured_finding(... service='redis', severity='critical' ...)` returned `confidence='medium'`, `priority='P3'`, and `['Review evidence and validate impact']` rather than the critical fallbacks.
- **Proposed remediation:** Remove severity-dependent fields from global defaults, or treat sentinel/absent values as “derive from severity.” Apply only explicit service overrides after derivation and test all severity tiers through the dashboard sort.

### S1-12 — Per-run service metadata cannot override repository metadata

- **Category:** Configuration override / contract drift
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/report.py:88-125`
- **Background/details:** The docstring says `<out_dir>/service-metadata.json` lets a local run override the repository copy. The implementation iterates repository metadata first and immediately returns on success, so out-dir candidates are never read in a normal checkout.
- **Observable impact:** Engagement-specific titles, tags, priorities, and next actions are ignored with no warning.
- **Evidence/reproduction:** A temporary out-dir metadata file defining a Redis title `LOCAL OVERRIDE` was passed to `_load_service_metadata(out_dir)`; the resulting Redis metadata contained no such title.
- **Proposed remediation:** Load repository metadata as the base and overlay out-dir defaults/services, or reverse precedence if full replacement is intended. Document and test merge rules.

### S1-13 — Custom severity rules cannot override an existing default match

- **Category:** Rule precedence / feature contract
- **Severity:** Medium
- **File and line:** Override claim at `aranumtoolkit/network/report.py:28-29`; first-match behavior and append order at `aranumtoolkit/network/report.py:483-512`
- **Background/details:** The module says operators can “override” severity rules, but `_load_rules()` appends custom rules after defaults and `_classify()` stops at the first match. A custom rule cannot change the severity of text already covered by a default rule. CLI help calls them additions, leaving the contract inconsistent.
- **Observable impact:** Engagement-specific triage policy appears accepted but is silently ignored for common built-in patterns.
- **Evidence/reproduction:** A custom JSONL rule mapping `OpenSSH` to `high` still classified `OpenSSH 9.8` as the built-in `low`.
- **Proposed remediation:** Define explicit precedence: prepend custom rules for override semantics, or provide separate `--severity-rules-prepend/--replace` modes. Align help/docs and add collision tests.

### S1-14 — Report summary conflates assessed coverage with hosts that produced findings

- **Category:** Reporting semantics / coverage gap
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/report.py:981-997`, rendered without qualification at `aranumtoolkit/network/report.py:1005-1009`
- **Background/details:** Summary hosts and services are derived exclusively from findings. A successfully assessed target/service with no matching issue is invisible rather than recorded as covered with zero findings.
- **Observable impact:** `findings.json`, Markdown, diffs, and external consumers cannot distinguish “cleanly assessed” from “never assessed,” and a report for a successful no-finding run says zero hosts/services.
- **Evidence/reproduction:** A synthetic `ssh/192.0.2.5/banner.txt` with nonmatching completed-scan evidence produced zero findings and summary `{hosts: [], services: []}` despite one host/service evidence tree.
- **Proposed remediation:** Add explicit coverage fields sourced from inventory, targets, dispatcher status, and evidence directories (for example `hosts_assessed` and `services_attempted`) while retaining separate `hosts_with_findings` fields.

### S1-15 — The same logical evidence is counted twice through host and dispatcher logs

- **Category:** Deduplication / false-positive inflation
- **Severity:** Medium
- **File and line:** Host-file scan at `aranumtoolkit/network/report.py:814-861`, top-level log scan at `aranumtoolkit/network/report.py:862-882`, re-attribution at `aranumtoolkit/network/report-dashboard.py:392-436`
- **Background/details:** Dispatcher stdout is commonly tee'd into `_dispatcher.log` while the same result is written into a per-host file. The reporter emits both. The dashboard then reattributes IPv4 dispatcher lines to the real host but does not canonicalize or deduplicate the pair.
- **Observable impact:** Finding and severity counts are inflated, prioritization becomes noisy, and repeated evidence looks like multiple distinct issues.
- **Evidence/reproduction:** The same `SMB signing disabled on 192.0.2.10:445` line in a host evidence file and `_dispatcher.log` yielded two medium findings for the same host/service/line (one with port `445`, one with empty port). The checked-in dashboard fixture also repeats its signing result in both locations.
- **Proposed remediation:** Normalize dispatcher attribution/port first, then deduplicate on a logical finding key while retaining all evidence paths as provenance. Do not discard unique stdout-only results.

### S1-16 — Diff identity omits port and truncates evidence text

- **Category:** Change detection / silent false negative
- **Severity:** High
- **File and line:** `aranumtoolkit/network/autoenum-diff.sh:46-56`, `aranumtoolkit/network/autoenum-diff.sh:77-110`
- **Background/details:** Finding identity is `(host, service, severity, line[:120])`; port, protocol, finding ID, and text after byte/character 120 are ignored.
- **Observable impact:** A newly exposed service instance on a different port, or a meaningful change after the shared prefix, produces no alert and exit code 0.
- **Evidence/reproduction:** Two isolated comparisons were run: port 80 changed to 443 with all other fields equal, and the text changed only after 120 `A` characters. Both reported no new findings and returned 0.
- **Proposed remediation:** Prefer schema-v2 `finding_id` only if its stability semantics match cross-run comparison; otherwise use a full normalized tuple including host, port, protocol, service, severity/rule, and complete line. Truncate only display text.

### S1-17 — Merged findings omit the required schema version

- **Category:** Schema contract / consumer compatibility
- **Severity:** High
- **File and line:** `aranumtoolkit/network/merge-results.py:183-192`; required contract at `aranumtoolkit/docs/SCHEMA.md:3-24`
- **Background/details:** The documented stable contract says both report and merge emit schema v2 and consumers should pin `schema_version`. The merged payload does not contain that key and does not validate source schema compatibility.
- **Observable impact:** Strict consumers must reject the merge result, while permissive consumers cannot safely interpret mixed or future input schemas.
- **Evidence/reproduction:** Merging a valid `schema_version: "2"` payload returned 0, but the output's `schema_version` was absent.
- **Proposed remediation:** Validate supported source schemas, migrate when supported, reject incompatible mixes, and always emit the current string schema version.

### S1-18 — Merge falsely labels redacted results as unredacted

- **Category:** Output metadata accuracy
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/merge-results.py:183-192`, especially hard-coded `redacted: False` at line 188
- **Background/details:** Merge ignores source-level redaction metadata and always emits `false`, even when hosts and text remain pseudonymized.
- **Observable impact:** Downstream workflows cannot determine whether the merged artifact contains original identifiers, and may incorrectly join or compare pseudonyms as real hosts.
- **Evidence/reproduction:** A source with `redacted: true` and host `<TARGET-1>` merged to a payload with the same pseudonym but `redacted: false`.
- **Proposed remediation:** Preserve redaction state. Reject unsafe mixes of independently redacted sources unless a shared mapping/namespace is available; otherwise emit an explicit mixed/unknown state supported by a schema update.

### S1-19 — Failed evidence copies leave valid-looking paths to nonexistent files

- **Category:** Evidence provenance / partial failure
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/merge-results.py:137-154`
- **Background/details:** On `shutil.copy2()` failure, merge adds a warning but still records the digest mapping and rewrites the finding to the destination evidence path.
- **Observable impact:** Dashboards and operators follow broken evidence links, and a later duplicate may also reuse the nonexistent path.
- **Evidence/reproduction:** With `copy2` forced to raise `OSError`, `_merge_findings()` returned `evidence/src00-src/e.txt`; that path did not exist, although a warning was present.
- **Proposed remediation:** Only publish/deduplicate the destination path after a successful copy. On failure retain a clearly unavailable source reference or blank path plus structured warning/error metadata.

### S1-20 — Recce auto-discovery misses the canonical raw inventory

- **Category:** Interop discovery / coverage loss
- **Severity:** High
- **File and line:** `aranumtoolkit/interop/aranum_to_recce.py:248-267`; inventory is written at `aranumtoolkit/network/auto-enum.sh:267-270`
- **Background/details:** Unified runs write `outputs/<session>/raw/inventory.json`. The exporter checks reports, session root, and `inputs/inventory.json`, but not `raw/inventory.json`. It also auto-discovers only `.xml` scan inputs even though aranum accepts `.gnmap` and `.nmap`.
- **Observable impact:** The advertised no-flags session export can omit open ports/services that had no dispatcher output or finding, violating the “every discovered host, port and service” promise.
- **Evidence/reproduction:** A standard synthetic session containing `reports/findings.json`, `raw/inventory.json`, and a valid raw service tree returned autodiscovery `{inventory: None, raw: '<session>/raw'}`.
- **Proposed remediation:** Treat `session/raw/inventory.json` as the canonical first candidate, support all accepted nmap suffixes, and add an end-to-end unified-session fixture.

### S1-21 — Recce export fabricates TCP records for UDP evidence

- **Category:** Protocol mapping / interop corruption
- **Severity:** High
- **File and line:** Raw-tree default at `aranumtoolkit/interop/aranum_to_recce.py:230-244`; finding import at `aranumtoolkit/interop/aranum_to_recce.py:376-399`; the report finding schema omits protocol at `aranumtoolkit/network/report.py:202-231`
- **Background/details:** Raw-tree entries and all findings are forced to protocol `tcp`. When inventory correctly contains a UDP service, importing a finding for that port creates a second fabricated TCP port and attaches the vulnerability to it.
- **Observable impact:** UDP services such as SNMP, DNS, NTP, mDNS, SSDP, IKE, and RADIUS are represented on the wrong transport; checklists and remediation records become inaccurate.
- **Evidence/reproduction:** A fake-recce ingest with inventory `161/udp` and one SNMP finding produced ports `161/udp` and `161/tcp`, and the vulnerability protocol was `tcp`.
- **Proposed remediation:** Add protocol to the structured findings contract and carry it from parser/task/evidence through report and merge. When importing legacy findings, resolve protocol against inventory and refuse ambiguity rather than defaulting to TCP.

### S1-22 — Recce export marks skipped and failed work as enumerated/vulnerability-scanned

- **Category:** Coverage-state correctness / false completion
- **Severity:** High
- **File and line:** `aranumtoolkit/interop/aranum_to_recce.py:319-340`, `aranumtoolkit/interop/aranum_to_recce.py:416-421`; examples of deliberately unexecuted services at `aranumtoolkit/network/auto-enum.sh:329-348`
- **Background/details:** Every created host starts `enumerated=True`, and after ingestion every open port is unconditionally set `vuln_scanned=True`. Inventory includes ports excluded by filters, manual/gated services, zero-target/no-dispatch cases, and failed dispatchers.
- **Observable impact:** Recce's checklist reports complete coverage for checks aranum never ran, hiding precisely the gaps an engagement tracker is supposed to surface.
- **Evidence/reproduction:** The fake-recce ingest marked both inventory and fabricated ports `vuln_scanned=True` and the host `enumerated=True`; the exporter never consumed run log, `.done`, `.rc`, or queue state.
- **Proposed remediation:** Import discovery state separately from enumeration/vulnerability-scan state. Set completion only from task/service execution records with successful, target-specific outcomes; represent skipped, gated, failed, and unknown states explicitly.

### S1-23 — Dashboard cannot reattribute IPv6 dispatcher findings

- **Category:** IPv6 reporting / host attribution
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/report-dashboard.py:392-436`
- **Background/details:** The dashboard extracts known IPv6 targets from bracketed target files but reattributes dispatcher findings with an IPv4-only regex. The source comment acknowledges the missing path.
- **Observable impact:** IPv6 findings remain under `(dispatcher)` rather than the host, so per-host views and counts omit them and interop may be unable to resolve them.
- **Evidence/reproduction:** A `_targets_redis.txt` entry `[2001:db8::1]:6379` plus `_dispatcher.log` line `CRITICAL: UNAUTH Redis [2001:db8::1]:6379` produced a finding whose host remained `(dispatcher)`.
- **Proposed remediation:** Use `ipaddress`-based extraction for bracketed and bare IPv6 plus IPv4, normalize against known targets, and share the resolver with report/interop. Add IPv6 per-host dashboard tests.

## Coverage

The following in-scope production sources were read in full and traced together:

- `aranum.py`
- `aranumtoolkit/network/auto-enum.sh`
- `aranumtoolkit/network/iterative-enum.sh`
- `aranumtoolkit/network/plan.py`
- `aranumtoolkit/network/nmap-parse.py`
- `aranumtoolkit/network/merge-results.py`
- `aranumtoolkit/network/report.py`
- `aranumtoolkit/network/report-dashboard.py`
- `aranumtoolkit/network/wiki.py`
- `aranumtoolkit/network/autoenum-diff.sh`
- `aranumtoolkit/network/_lib.sh`
- `aranumtoolkit/network/engagement-profiles.json`
- `aranumtoolkit/network/service-metadata.json`
- `aranumtoolkit/interop/aranum_to_recce.py` and its README

Direct tests and fixtures read in full included unified CLI, parser, planner, queue, merge, report/dashboard, structured findings, bulk report, AD signals, wiki, dispatcher contract, interop, Phase-1 hardening, smoke coverage, all service XML fixtures, malicious XML fixtures, bulk-enum report fixtures, AD-signal fixtures, and the dashboard example tree. Relevant operator/schema material read in full included top-level `README.md`, `USAGE.md`, `aranumtoolkit/docs/{README.md,SCHEMA.md,TESTPLAN-001-07JUN2026-comprehensive-functional-test.md}`, example READMEs, and the wiki template.

The traced production path was:

`aranum run` → shorthand/session handling → `auto-enum.sh` parse/plan/queue → `nmap-parse.py` inventory → service dispatch/status/evidence → `report.py` classification/structured findings → queue state/merge/diff → dashboard aggregation → recce export.

## Commands and results

### Existing focused tests

Command:

```text
python3 -m unittest -v \
  aranumtoolkit.tests.test_unified_cli \
  aranumtoolkit.tests.test_nmap_parse \
  aranumtoolkit.tests.test_planner \
  aranumtoolkit.tests.test_queue \
  aranumtoolkit.tests.test_merge_results \
  aranumtoolkit.tests.test_report_dashboard \
  aranumtoolkit.tests.test_interop_recce \
  aranumtoolkit.tests.test_wiki \
  aranumtoolkit.tests.test_structured_findings \
  aranumtoolkit.tests.test_bulk_enum_report \
  aranumtoolkit.tests.test_dispatcher_contract
```

Result: 93 tests passed; one recce end-to-end test was skipped because recce was not importable. The cache bug is intermittent in the existing suite and was validated deterministically as described in S1-01.

### Static/format checks

- `bash -n` passed for the four in-scope shell scripts.
- `python3 -m py_compile` passed for the in-scope Python files.
- `python3 -m json.tool` passed for both metadata/config JSON files.
- `shellcheck` was unavailable in the active environment (a pyenv shim referenced a different environment), so no ShellCheck claim is made.

### Isolated focused fixtures

All additional fixtures were created under Python `TemporaryDirectory` locations and deleted after execution. They performed no external network activity. Confirmed results:

- Rule-cache list-ID reuse: cached `None` versus brute-force `critical`.
- Induced dispatcher exit 7: overall auto-enum exit 0.
- Parallel resume with stale `.rc=9`: `OK=0 FAIL=1 SKIP=0` for a skipped service.
- Mixed TCP/UDP same-port plan: four pre-dedup tasks reduced to two TCP-only tasks.
- Duplicate-entry shards: full task-ID overlap between shard 1 and shard 2.
- Two queue phases: one dispatcher call marked both phases done.
- Malformed queue: traceback plus empty overall success.
- Unified shorthand: `--service-parallel 4` rewrote input to `-i 4`.
- Two up hosts/one open-port host: host summary 1.
- Prior SMB `user: alice`: iterative users list empty.
- Critical Redis finding: structured priority `P3` and confidence `medium`.
- Local metadata title: ignored.
- Custom OpenSSH high rule: classified low.
- Evidence-only clean host: report summary zero hosts/services.
- Duplicate host/log line: two findings.
- Port-only and post-character-120 diffs: exit 0/no new finding.
- Merge of schema-v2 redacted input: schema missing and redacted false.
- Induced merge copy error: rewritten evidence path did not exist.
- Standard session autodiscovery: raw tree found, raw inventory missed.
- UDP SNMP recce mapping: fabricated TCP port and TCP vulnerability.
- IPv6 dispatcher finding: remained `(dispatcher)`.

## Review limits

- No real enterprise network, live service lab, or external recce installation was used in Sprint 1. Protocol behavior inside individual dispatchers belongs to Sprint 2.
- The optional recce integration was exercised with a minimal in-memory fake of the public model/store boundary; the repository's actual optional end-to-end test was skipped for the missing dependency.
- Security weaknesses in aranum itself were not evaluated or reported.
