# Aranum quality remediation sprint plan

Date: 13 September 2026
Planning baseline: `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
Input gate: [independent findings validation](../research/REVIEW-VALIDATION-13SEP2026-independent-findings-gate.md)
Scope: functional correctness, assessment effectiveness, feature coverage, operator trust, tests, and release quality
Explicit exclusion: security hardening of aranum itself

## Outcome and sequencing

This plan schedules all 72 independently accepted findings exactly once: 30 in Phase R1, 19 in Phase R2, and 23 in Phase R3. Phases are ordered by dependency, not merely severity. R1 first makes run state, evidence identity, reports, and quality gates trustworthy. R2 then repairs endpoint and protocol behavior on that foundation. R3 closes specialist verdict, lifecycle, packaging, and product-contract gaps.

Implementation is not part of the review task. Each phase must begin from a cleanly identified baseline, preserve unrelated worktree changes, and finish with its acceptance gate green before the next phase starts. Every functional change should be delivered as a small conventional commit with its tests and user-facing documentation or changelog entry.

## Common implementation rules

- Treat the independent validation wording and severity as binding. In particular, pass bare IPv6 hostnames to OpenSSH; never add URI-style brackets to the `ssh` destination argument.
- Preserve endpoint identity as structured `user`, `host`, `port`, `protocol`, and service data until the final transport adapter. Do not reconstruct identity by parsing display strings.
- Use run-scoped state written atomically. A current failure must invalidate prior success markers, and malformed or incomplete input must fail closed with a nonzero status.
- Build semantic fixtures around exact protocol stages and contradictory cases. A successful greeting or unrelated reply cannot prove a later command succeeded.
- Distinguish confirmed, likely, informational, clean-assessed, skipped, failed, and unassessed states in data models and rendered output.
- Keep bounded correlation conservative. Vendor recognition requires multiple compatible signals and must never rely on a port number alone.
- Do not make a mutating specialist action until every local prerequisite is validated. Record enough prior state to verify and reverse each mutation.
- Keep every commit independently testable. If a regression test demonstrates a defect, land it with the fix rather than leaving the default branch red.
- Use local mocks and fixtures for the normal gate. Live validation is permitted only against explicitly authorized disposable lab systems and must be separately identified.

## Phase R1 — trustworthy orchestration, artifacts, and quality gates

### Purpose and dependencies

R1 establishes reliable success/failure semantics and canonical data identity from parsing through reporting and export. It has no dependency on later phases. The existing intermittent report classifier failure must be fixed before enabling pytest as a mandatory CI job; otherwise the strengthened gate would correctly but nondeterministically fail.

### Finding mapping and execution waves

| Wave | Findings | Primary production paths | Planned change and acceptance |
|---|---|---|---|
| R1-A — executable quality gate | S3-01, S3-02 | `deps-check.sh`, `Makefile`, dependency test fixtures | Probe the executable named by each requirement, run a minimal version/capability check, aggregate required misses, and return nonzero. Make lint distinguish a runnable ShellCheck from a broken shim and reliably fall back to shell syntax checks when the executable is unavailable. Fixtures must cover absent commands, package-hint aliases, broken shims, optional misses, and required misses. |
| R1-B — report identity and semantics | S1-01, S1-11, S1-12, S1-13, S1-14, S1-15, S1-23 | `aranumtoolkit/network/report.py`, `report-dashboard.py`, `service-metadata.json`, report tests | Replace object-ID caching with content/lifetime-safe rule compilation; define repository/default/run-local precedence; allow explicit custom rules to override defaults; derive priority from severity unless explicitly overridden; model assessed-clean coverage; deduplicate the same logical evidence; and parse bracketed or bare IPv6 endpoints structurally. Acceptance includes thousands of classifier lifecycles, override matrices, duplicated evidence, clean runs, and IPv4/IPv6 dispatcher attribution. |
| R1-C — planner and campaign state machine | S1-02, S1-03, S1-04, S1-05, S1-06, S1-07, S1-08 | `aranum.py`, `aranumtoolkit/network/auto-enum.sh`, `plan.py`, orchestration tests | Give tasks protocol-aware stable IDs; deduplicate before sharding; pass phase, task, risk, priority, endpoint, and protocol through execution; write current-run result state atomically; aggregate skip/failure counts in the parent process; reject malformed queues; parse option values correctly; and make any selected dispatcher failure propagate to the campaign exit status. Tests must cover TCP/UDP on one port, duplicate inventories across shards, phase/priority filtering, stale state, malformed JSON, option permutations, and mixed dispatcher outcomes. |
| R1-D — inventory and iteration completeness | S1-09, S1-10 | `nmap-parse.py`, `iterative-enum.sh`, raw inventory schema and tests | Preserve all up hosts independently of open-service records and report both host and service counts. Mine prior evidence from the documented enum-output/raw paths into deterministic, deduplicated iteration inputs. Fixtures include up hosts with zero ports, mixed states, prior SMB users, empty prior evidence, and repeat runs. |
| R1-E — diff and merge contract | S1-16, S1-17, S1-18, S1-19 | `autoenum-diff.sh`, `merge-results.py`, `aranumtoolkit/docs/SCHEMA.md`, merge/diff tests | Define a complete canonical finding identity that includes endpoint port/protocol and untruncated evidence identity. Emit the required schema version, derive redaction from inputs, and never publish an evidence path unless the copy succeeded; surface partial-copy failure explicitly. Round-trip tests cover port-only changes, long-tail evidence changes, redacted mixtures, missing/copy-failed evidence, and schema validation. |
| R1-F — Recce interoperability truth | S1-20, S1-21, S1-22 | `aranumtoolkit/interop/aranum_to_recce.py`, export fixtures, optional Recce adapter tests | Discover canonical inventory and supported raw scan formats, keep transport protocol from source through vulnerability attachment, and derive enumerated/scanned state only from execution records. Adapter tests cover JSON inventory, XML and gnmap discovery, UDP-only services, skipped/failed/unexecuted ports, and mixed host completion. |
| R1-G — bulk/common execution state | S2-01, S2-02, S2-03, S2-04 | `aranumtoolkit/network/_lib.sh`, `bulk-enum-linux.sh`, `bulk-enum-windows.py`, dispatcher/bulk tests | Fail immediately when the evidence directory cannot be created; use collision-safe endpoint/user/port artifact keys plus a readable manifest; clear or supersede old success state before a non-resume attempt; and reject parallelism below one or above a documented safe maximum. Add an explicit legacy-state policy: migrate only unambiguous host-keyed artifacts into the manifest and refuse ambiguous legacy resume with a corrective message. Cover same-host users/ports, legacy unique/ambiguous state, success-then-failure, resume/non-resume, regular-file output paths, and boundary worker counts. |
| R1-H — CI closure | S3-03 | `.github/workflows/ci.yml`, `Makefile`, test documentation | Make the declared local and CI gates run the same unittest, pytest, smoke, data-audit, and lint components with visible component statuses. Add a CI assertion or documented command inventory that prevents pytest-only tests from silently dropping out again. |

### Suggested commit sequence

1. `fix(deps): make dependency and lint probes executable-aware` — R1-A.
2. `fix(report): make classification and coverage deterministic` — R1-B.
3. `fix(orchestrator): enforce queue identity and failure state` — R1-C.
4. `fix(inventory): preserve live hosts and iterative inputs` — R1-D.
5. `fix(results): preserve diff and merge contracts` — R1-E.
6. `fix(interop): export only protocol-correct executed state` — R1-F.
7. `fix(bulk): isolate endpoint state and validate concurrency` — R1-G.
8. `ci(test): run the complete local quality gate` — R1-H after all preceding tests are green.

### R1 exit gate

- `make lint`, unittest, pytest, smoke, and data audit all run and produce truthful independent statuses in both local and CI definitions.
- Repeated classifier stress runs are deterministic; no `id()`-reuse behavior remains.
- Failure injection proves malformed queues, failed dispatchers, unwritable outputs, copy failures, and invalid worker counts return nonzero without publishing success state.
- One-host TCP/UDP, multi-port, multi-user, IPv6, redacted, clean-assessed, skipped, and failed fixtures retain distinct identities through reports, merges, diffs, dashboard attribution, and Recce export. Legacy bulk state is migrated only when unambiguous and can never silently satisfy a colliding endpoint.
- No live network is required for the phase gate. An optional installed-Recce end-to-end run may supplement, but not replace, adapter contract tests.

## Phase R2 — endpoint, transport, and host-detection correctness

### Purpose and dependencies

R2 uses R1's canonical endpoint/state contracts to ensure that discovery, dispatch, authentication, and host-enumeration predicates assess the intended endpoint with the intended protocol. R1 must already have migrated unambiguous legacy artifact keys and made ambiguous legacy resume fail closed.

### Finding mapping and execution waves

| Wave | Findings | Primary production paths | Planned change and acceptance |
|---|---|---|---|
| R2-A — scale, key planning, and handoff contracts | S2-19, S2-20, S2-21, S2-22 | `standalones/ot/ot-enum.sh`, OT dispatchers, `ssh-key-triage.py`, `bulk-enum-linux.sh`, related schemas/tests | Implement a real bounded OT worker scheduler; filter/prepare keys before consuming attempt caps; define a machine-readable authorized-pair schema directly consumable by bulk enumeration before changing its endpoint consumers; and enforce one global start-rate limiter rather than per-worker sleeps. Deterministic clock/executor fixtures must prove maximum concurrency, cap semantics, handoff parsing, and minimum inter-attempt spacing. |
| R2-B — SSH endpoint fidelity | S2-05, S2-06, V-01 | `ssh-triage.sh`, `bulk-enum-windows.py`, `bulk-enum-linux.sh`, `aranumtoolkit/network/enum-ssh.sh`, `ssh-key-triage.py` | Carry the classified port into Windows-over-SSH, keep authenticated evidence keyed by user/host/port and unauthenticated banner/CVE evidence by host/port, consume the finalized authorized-pair schema, and pass bare IPv6 hosts to OpenSSH. Table-driven argv and multi-user/two-port evidence tests must cover IPv4, IPv6, usernames, nondefault ports, and contradictory banners without DNS or live SSH. |
| R2-C — protocol-aware discovery and dispatch | S2-07, S2-08, S2-09, S2-10, S2-11, S2-12 | `nmap-parse.py`, `_lib.sh`, `enum-ldap.sh`, `enum-imap.sh`, `enum-pop3.sh`, `enum-smtp.sh`, `enum-ftp.sh`, `enum-x11.sh`, new bounded vendor-correlation path and tests | Preserve LDAP/LDAPS/Global Catalog ports and schemes; feed commands to implicit-TLS IMAP/POP sessions; associate POP auth status with the PASS response; add implicit SMTPS/FTPS transports; let strong incompatible service evidence override X11's port heuristic; and add conservative Bambu correlation from compatible tuple, TLS identity, and banner signals. Tests require negative and partial-signal controls so a common port alone never identifies a vendor. |
| R2-D — Linux standalone result accounting | S2-13 | `standalones/linux/apt-source-check.sh`, shell fixtures | Count writable source files without pipeline-subshell loss and count the writable alternate configuration path. Test each path independently, together, and with no writable surface so the clean conclusion cannot contradict emitted hits. |
| R2-E — Windows/AD predicate accuracy | S2-14, S2-15, S2-16, S2-17, S2-18 | `standalones/windows/Get-ServiceMisconfig.ps1`, `Get-UnquotedServices.ps1`, `Invoke-PrivEscEnum.ps1`, `Get-ADCSMisconfig.ps1`, `wiki/windows.md`, PowerShell fixtures | Parse quoted executables and construct Windows loader candidate paths for unquoted services; use separate literal or regex credential patterns intentionally; interpolate the SYSVOL domain; require a low-privileged enrollment right for ESC1; and make the documented ESC coverage equal implementation. Prefer correcting the current claim now and tracking any additional ESC implementations as separately scoped features. |

### Suggested commit sequence

1. `fix(scale): enforce OT and SSH planning contracts` — R2-A.
2. `fix(ssh): preserve endpoint identity across transports and evidence` — R2-B.
3. `fix(protocols): select endpoint-aware implicit TLS probes` — the LDAP, mail, and FTP portion of R2-C.
4. `fix(discovery): prefer observed service signals and bounded vendor correlation` — the classification portion of R2-C.
5. `fix(linux): make apt surface counts match emitted evidence` — R2-D.
6. `fix(windows): correct service, SYSVOL, and ADCS predicates` — R2-E.

### R2 exit gate

- Structured endpoint data is unchanged from parser through transport argv and per-port evidence; IPv6 SSH destinations are unbracketed and nondefault ports survive.
- Local TLS servers/shims prove 465, 636/3269, 990, 993, and 995 take their implicit-TLS paths and exact command responses drive verdicts.
- Contradictory service banners override port heuristics safely. Bambu classification requires multiple compatible signals; prior authorized-lab fingerprints may seed fixtures, but a current live printer probe is not required or claimed.
- PowerShell parser tests and predicate fixtures pass on Linux. Final confidence for service ACL and ADCS behavior requires a disposable, domain-joined Windows lab with both privileged and low-privileged enrollment controls.
- Fake-clock concurrency tests prove hard worker bounds and global pacing without relying on wall-clock sleeps.

## Phase R3 — specialist verdict semantics, lifecycle, and coverage

### Purpose and dependencies

R3 makes specialist conclusions correspond to observed protocol state and closes the test, packaging, authentication, recovery, and documentation gaps that allowed overclaims. It depends on R1's complete CI gate. Specialist endpoint adapters should consume R2's transport conventions where applicable.

### Finding mapping and execution waves

| Wave | Findings | Primary production paths | Planned change and acceptance |
|---|---|---|---|
| R3-A — SMTP/DNS state machines | S3-04, S3-05, S3-06, S3-07 | `standalones/smtp/smtp-quickwin.sh`, `smtp-relay-test.sh`, `smtp-phish-send.sh`, SPF/DMARC checker, SMTP docs and fixtures | Parse one reply for each SMTP command, model relay boundaries as unauthenticated external-to-external delivery, require accepted RCPT and DATA completion before send success, and parse DNS TXT values without option confusion or unbound variables. Transcript matrices cover rejected/accepted stages, multiline replies, normal inbound delivery, external relay, SPF hardfail, absent DMARC, and lookup errors. |
| R3-B — Redis capability, restoration, packaging, and ACL auth | S3-08, S3-09, S3-10, S3-22 | `standalones/redis/redis-quickwin.sh`, `_redis_lib.sh`, module workflow, module build/docs, Redis fixtures | Probe the exact module-load capability rather than list access; snapshot original replication/auth state and restore it exactly; choose and document a reproducible offline artifact strategy instead of promising an absent binary; and support named ACL username plus password throughout shared command construction. Test denied/allowed module commands, standalone/replica restoration, legacy AUTH, ACL AUTH, build provenance, and no-compiler behavior. |
| R3-C — ActiveMQ evidence and discovery | S3-11, S3-12, S3-13 | `standalones/activemq/activemq-quickwin.sh`, `activemq-cve-2023-46604.py`, `activemq-queues.sh`, docs/tests | Acquire and validate version evidence before assigning a vulnerable-range verdict; bind and prove callback readiness before payload delivery; discover actual broker object names; and parse/URL-encode queue identifiers structurally. Tests include patched/affected/unknown versions, immediate callbacks, multiple brokers, whitespace/quoted queue names, and empty results. |
| R3-D — GraphQL result and method semantics | S3-14, S3-15, S3-16, S3-17, S3-18 | `standalones/graphql/gql.py`, GraphQL README, mock endpoint tests | Apply transport/error exit status before raw rendering; define data presence by field existence rather than truthiness; classify CSRF only with a meaningful state-changing operation and missing defense evidence; build alias tests from the selected schema operation with controls; and align documented commands with the parser. Fixtures cover refused connections, raw JSON, false/zero/empty values, read-only GET, mutation GET, alias controls, and every documented example. |
| R3-E — Jabber/Openfire certainty and lifecycle | S3-19, S3-20, S3-21, S3-26 | `standalones/jabber/jabber-user-enum.py`, `openfire-cve-2023-32315.py`, Jabber/Openfire docs/tests | Treat generic SASL rejection as indeterminate unless a differential control proves enumeration; validate plugin readability before creating an admin; verify upload/deployment and proof endpoint before reporting a full chain; persist prior/mutated state; and implement or truthfully narrow cleanup so its exit status reflects verified reversal. Test the two preflight branches separately: an omitted plugin argument and a supplied nonexistent/unreadable path must both make zero mutation calls, return nonzero, and emit distinct structured preflight/recovery reasons. Additional fixtures cover indistinguishable users, upload failure, deployed/not-deployed states, interrupted recovery, idempotent cleanup, and verification failure. |
| R3-F — semantic assurance and product contracts | S3-23, S3-24, S3-25 | `aranumtoolkit/tests/`, `.github/workflows/ci.yml`, `aranumtoolkit/tests/data_audit.py`, `docs/DATA-SOURCES.md`, root and credential-sweeper docs | Add the preceding specialist semantic fixtures to the standard gate; replace the two-path data audit with a manifest-driven inventory carrying source, version/date, checksum or derivation, owner, and freshness policy; and resolve the HTTP-only credential sweeper mismatch by correcting root claims now. Native SSH/database credential modules require a separately approved feature design rather than being implied by documentation. |

### Suggested commit sequence

1. `fix(smtp): derive findings from command-specific replies` — R3-A.
2. `fix(redis): prove capabilities and restore prior state` — capability/restoration portion of R3-B.
3. `feat(redis): support ACL auth and reproducible offline modules` — authentication/packaging portion of R3-B.
4. `fix(activemq): require version and ready callback evidence` — R3-C.
5. `fix(graphql): align exit, data, CSRF, and alias semantics` — R3-D.
6. `fix(jabber): make enumeration and Openfire lifecycle truthful` — R3-E.
7. `test(specialists): gate verdict semantics and data provenance` — R3-F, while subsystem regression tests land with their fixes.
8. `docs(scope): align credential capabilities with implementation` — product-contract portion of R3-F.

### R3 exit gate

- Each specialist has positive, negative, indeterminate, and transport-failure fixtures; raw-output modes preserve machine-readable output and meaningful process status.
- SMTP, Redis, ActiveMQ, GraphQL, Jabber, and Openfire findings require the exact evidence named in their conclusion. Unknown versions, generic rejections, and partial mutations cannot become confirmed critical results.
- Redis and Openfire lifecycle tests prove restoration from saved state and idempotent recovery after interruption. Authorized disposable lab runs are required before claiming real end-to-end mutation and cleanup success.
- Offline Redis packaging is reproducible from a documented source/toolchain or the runtime reports the missing prerequisite honestly; no undocumented architecture-specific binary is silently assumed.
- Every embedded or documented data/rule family appears in the data-source manifest and audit output. Root credential documentation exactly matches shipped transports.
- The complete R1 CI gate runs all new specialist fixtures.

## Cross-phase release gate

After all phases, run the following from the same identified revision and retain the output as release evidence:

```bash
make lint
python3 -m unittest discover -s aranumtoolkit/tests -p 'test_*.py' -v
python3 -m pytest aranumtoolkit/tests/ -q
bash aranumtoolkit/tests/smoke.sh
make data-audit
git diff --check
```

Add focused transport and specialist commands documented by each wave. A green aggregate is insufficient if any component was skipped unexpectedly; record each component's count and status separately. Repeat the deterministic cache, shard, concurrency, and state-machine stress fixtures at least ten times.

Before release, perform only the lab checks for which an explicitly authorized target exists: installed Recce interoperability, implicit-TLS endpoint negotiation, Windows/AD predicates, Redis replication restoration, and Openfire mutation/cleanup. Report fixture evidence separately from live end-to-end evidence and leave unavailable lab gates explicitly pending.

## Completion definition

- All 72 accepted findings are closed by tested changes or by an explicitly approved documentation/contract correction.
- The independent validator rechecks each phase against the definitive finding wording and confirms no rejected wording was reintroduced.
- Every phase has a changelog entry, migration note where state/schema changed, and no unrelated product changes.
- No acceptance claim depends only on HTTP status, command existence, or a high-level smoke pass when the production path requires deeper state evidence.
- Security of aranum itself remains out of scope; newly noticed self-security concerns are recorded separately and do not expand these remediation phases.
