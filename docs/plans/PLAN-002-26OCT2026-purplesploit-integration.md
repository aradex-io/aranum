# PLAN-002 — aranum as purplesploit's enumeration engine (26 OCT 2026)

**Status:** Phase 5 plan, **rev 4** — three Mythos review rounds folded in (34 findings, all
accepted). Phase 5 gate: **green except one recorded waiver** (§13 round 3: purge-on-mint not
re-reviewed; covered by FX-4L + A1 diff review). Ready for Phase 6: A1 now; P1/P2a once codex's CWP1–CWP9 tree is committed (its SHA = P1 base; codex TURN 11 accepted every P-item). No code changed in either repo.
**Owner go:** 26 OCT 2026 ("Yes and yes. Proceed") — draft this plan; hand the purplesploit
side to codex via `/srv/share/dev/purplesploit/interop-channel`.
**Sources:** `/srv/share/dev/purplesploit/interop-channel` TURN 1–9 (codex answers Q1–Q14);
`/srv/share/dev/purplesploit/docs/research/INTEROP_STUDY-26OCT2026-aranum-purplesploit.md`
(study, errata §7, account model §9); codex's accepted study
`/srv/share/dev/purplesploit/docs/ARANUM_INTEROP_STUDY-26OCT2026.md`; purplesploit
`docs/PURPLESPLOIT_IMPLEMENTATION_ROADMAP-26OCT2026.md` §7; review record §13.

Provenance labels: **measured** (run or inspected this session), **recorded** (cited artifact),
**inferred** (reasoned, not observed).

---

## 0. Frame

| | aranum | purplesploit |
|---|---|---|
| Path | `/srv/share/dev/aranum` | `/srv/share/dev/purplesploit` |
| Base | `main` @ `2493def` (S5 plan commits `16fd3f7..52f2fc0` sit unpushed on `dev/desktop-transports`) | `main` @ `c962994` + a large uncommitted CWP1–CWP9 working tree owned by codex |
| Executor | Claude (A-sprints), per aranum `CLAUDE.md` | **codex**, in its own session, per purplesploit `CLAUDE.md`; Claude does not edit purplesploit |
| Commit identity | `d0sf3t <github@aradex.io>`, conventional commits, CHANGELOG in the same commit | `jeremylaratro <62393443+jeremylaratro@users.noreply.github.com>`; hooks enforced; never `--no-verify` |
| Coordination | this file | `interop-channel` TURN 10+ (task briefs); codex replies in `.interop/` |

Neither repo's commits or PRs carry Claude/Anthropic attribution or model identifiers.

## 1. Objective

aranum becomes purplesploit's enumeration engine: an operator in purplesploit can launch aranum
against any scope (network, AD, `--local` Linux/Windows), and every host, service, posture
check, finding, KB remediation, and account context aranum produces lands in purplesploit's
common records **losslessly, with provenance, idempotently, and with local vs domain vs machine
accounts kept distinct** — including partial runs and local-only runs.

**Acceptance = AC-01..19 (§6)**, run against the fixture bundles of §5. Target: 19/19 green.

## 2. Standing scope rules (repeat verbatim in every delegated prompt)

- **In scope:** functionality, efficiency, capability.
- **Out of scope:** the tools' own security/integrity — hardening, authn/authz of the tools,
  secret storage, sandboxing, compliance controls. purplesploit's S19–S23 integrity block stays
  at the end of its roadmap; nothing here moves it earlier.
- **Standing deferral (owner 26 OCT):** intended tool behavior and its side effects are not
  defects and are not raised — e.g. enabling `xp_cmdshell`, writing logs/outputs in-repo,
  screenshots, evidence persistence, footprint. Deliberate defaults are features.
- Measurement that looks wrong is fixed in the fixture or the measurement, not by redesigning
  the tool.

## 3. What already exists (measured 26 OCT; Mythos re-verified each row, review §13)

| Surface | State | Provenance |
|---|---|---|
| purplesploit `interop/aranum.py` (234 lines) | Offline reader: `inventory.json` **required** (`:124-127,135`) + optional `findings.json` v2, `posture.json` v1, `run-state.json` v1, `queue.state.jsonl`; uuid5 identity keyed on run_id or bundle fingerprint (`:147,156-157`); `merge_into` idempotent by id; `seed_auto_enum` | measured |
| Registry detection | `aranum-bundle` matches only a directory containing `inventory.json` (`interop/importers.py:299`) | measured |
| Provenance placement | `source_tool/_version/_schema/_id/raw` in `Observation.attributes` (`interop/aranum.py:166-173`) | measured |
| Observation identity | `Observation.__post_init__` hashes `attributes` into `observation_id` when none is given (`core/execution.py:93-97`); other importers (containers/cloud/identity/nmap) also put source keys in `attributes` | measured |
| Finding projection | `raw_output=json.dumps(attributes)`; no KB enrichment; no `metadata["source_observation"]`; no ATT&CK | measured (`interop/aranum.py:202-216`) |
| Account model | no `auth_context`/`account_ref`/account `scope`/`local_host` in `core/execution.py` or the credential stores | measured |
| Live launcher | **absent** — deferred: "Aranum completion semantics are not yet stable enough" | recorded (roadmap §7) |
| aranum stages | three separately invocable stages writing one outdir: `run` (auto-enum.sh → inventory, run-state), `local` (local-enum.py → posture inputs; **writes no inventory.json**), `report` (report.py → findings.json, posture.json, SARIF, dashboard) | measured (`aranum.py:725-786`) |
| Partial-run handling | auto-enum exits 4 when any dispatcher failed (`auto-enum.sh:884`); `_run_auto_enum` and `_run_auto_enum_local` return before the report chain on any nonzero rc (`aranum.py:733,750,760`) ⇒ **a partial run yields no findings.json** | measured |
| Re-run into same outdir | run-state.json written once at the end (`auto-enum.sh:782`); no `trap`; `--resume` reuses the dir | recorded (Mythos R-3) |
| aranum `inventory.json` | **unversioned** (`nmap-parse.py --json`) | measured |
| aranum `findings.json` / `posture.json` | v2 (`report.py:58,395,2834`) / v1 (`report.py:2898-2910`); no published JSON Schema | recorded |
| aranum SARIF | `report.py:2667-2696`; `driver.version` = findings schema "2", `rules: []` | recorded |
| aranum KB | `finding-kb.json` keys `schema, categories(10), service_categories, classes(199), checks(99)`; no `version` key; loader drops classes whose category is absent (`report.py:195-205`) | recorded (Mythos R-8) |
| aranum credential scope | domain comes from `-d` **or** from username shape (`HOST\user`, `local-enum.py:737-740,824-829`); `_lib.sh:249-259` adds `-d` only when `ENUM_DOMAIN`; **no `--local-auth` exists anywhere in aranum** | measured |
| Dispatcher set | 74 `enum-*.sh` + 2 alias symlinks (https→http, xmpp→jabber); no machine-readable list | recorded |

## 4. Account model (constraint — owner decided "fuller version, ride along", 26 OCT)

Not re-litigated. Spec = interop-channel TURN 7 (decisions) + TURN 8 (placements):

- `auth_context = {account_ref, scope ∈ {local, domain, machine}, domain, local_host,
  auth_method ∈ {password, hash, kerberos, null-session, anonymous}}`.
- Carried on `ExecutionRequest`, `ExecutionResult` (copied from the request on every outcome,
  including early errors), and `Observation` (first-class). Nested as `auth_context.scope` —
  never a top-level `Observation.scope` (that already means aranum's host/domain/run subject).
- Credential records (all three stores) gain `account_ref` (new explicit stable key), `scope`,
  `local_host`. Account identity = `(username, scope, domain, local_host)`.
- **No inference anywhere** — not in purplesploit's normalizer, and not in aranum's emitter
  (§9 A3): scope is set only when declared or unambiguous from the invocation; otherwise null.
- Derived analysis (local-credential reuse, domain effective-on-host edges, machine principals)
  is **P4**.
- Launcher invocation mapping (P3): domain → `-d <domain>`; local → no `-d` + `--local-auth`
  (added to aranum in A3); machine → `account$`.

## 5. Fixture bundles (shared acceptance inputs)

Generated by a `make fixtures-interop` target added in A1, committed under
`aranumtoolkit/tests/fixtures/interop/`, copied into purplesploit by codex with the source digest
recorded (purplesploit tests stay self-contained). Synthetic or lab-derived only — no engagement
data, real target IPs, or captured credentials (aranum §9).

| ID | Content | Version history |
|---|---|---|
| FX-1 network | from aranum's `all-services.xml` (14 hosts, 35 ports) → inventory v1, run-state, manifest (`run` stage only) | A1 |
| FX-2 mixed posture | Linux + Windows + AD posture and findings; local, domain, machine, null-session contexts; two same-named local accounts on different hosts | **v0 in A1** (no `kb`, no `auth_context`); **v1 in A2** (+kb subset); **v2 in A3** (+auth_context). Each regen bumps the recorded digest |
| FX-2L local-only | `local` + `report` stages, **no inventory.json** | A1 (v0) → A3 |
| FX-3 partial/error/redacted | one failing dispatcher (rc 4) that still reaches `report`; service errors; `posture_quarantine`; redacted fields; unknown triage value; manifest `status: partial` | A1 |
| FX-4 stale re-run | run 1 complete, run 2 interrupted in the same outdir | A1 (drives AC-18) |
| FX-4L stale local re-run | `local`+`report` complete, then `local` re-run without `report` in the same outdir | A1 (drives AC-18) |

## 6. Acceptance checks (codex TURN 4 Q13 + account checks + review round 1)

Every check reports **pass / fail / inconclusive** (fixture absent or prerequisite unmet ⇒
inconclusive, never pass).

| # | Check | Pass condition | Sprint |
|---|---|---|---|
| AC-01 | Registry completeness | every entry of aranum's published `dispatchers.json` (A1) resolves as `recon/aranum:<svc>`; aliases resolve; "Run Selected Services" exists; drift between vendored list and the bundle's `tool_version` list = diagnostic | A1+P3 |
| AC-02 | Inventory fidelity | every FX-1 host/port/service/version/tunnel survives import | P2b |
| AC-03 | Finding fidelity | each findings.json record → exactly one Finding; FAIL/WARN posture findings imported once (from findings.json); posture.json contributes observations only | P2b |
| AC-04 | Observation fidelity | every posture check, `per_host` roll-up (roll-up only), `summary.coverage[]` row present | P2b |
| AC-05 | Provenance | `source_tool/_version/_schema/_id/raw` first-class on every imported Observation; `auth_context` present where aranum stamped one, null otherwise | P1+A3+P2b |
| AC-06 | KB enrichment | line→Description, why→Impact, fix[]→Remediation, refs[]→References, test[]→"Validation / retest", source note "Aranum KB <version>, <kb_id>, digest"; ATT&CK `T1558.003`-form | A2+P2b |
| AC-07 | Exact re-import | same bundle twice ⇒ 0 new records | P2b |
| AC-08 | Cross-run linking | re-run of FX-2 ⇒ new occurrences; group by `logical_id` (A2.4): every new finding has ≥1 prior with the same `logical_id`, and per-group counts match between runs; `Finding.metadata.source_identity = (source_tool, source_schema, source_id)` retained; a changed-line case is a new `source_id` but the same `logical_id` | A2+P2b |
| AC-09 | Partial/error visibility | FX-3: partial/errors/quarantine/redaction become data-quality observations; import marked partial | A1+P2b |
| AC-10 | Auto-enum handoff | selected services coalesce into one aranum run; purplesploit does not re-run aranum-owned baselines for the 8 overlap services | P3 |
| AC-11 | Offline portability | FX-2 v1+ imports with no aranum installed (KB inline, schemas pinned) | A1+A2+P2b |
| AC-12 | Invocation discipline | fake process runner: default templates add no aggressive/desktop/write/exploit flags; `-o` at the operator-chosen root; **auto-enum rc=4 ⇒ report chain still runs, manifest `partial`** | A1+P3 |
| AC-13 | Report rendering | golden-file compare: for every FX-2 finding with `kb_id`, Markdown and HTML (and XLSX if shipped) contain Remediation and Validation sections with the KB text plus an `auth_context` label | P2b |
| AC-14 | Account separation | two same-named local accounts on different hosts stay two credential records in all three stores | P1 |
| AC-15 | Round-trip | `to_dict`/`from_dict` preserves `auth_context` through distributed + assessment storage | P1 |
| AC-16 | No inference (purplesploit) | DOMAIN option set, no declared scope ⇒ `auth_context.scope` null | P1 |
| AC-17 | Local-only import | FX-2L (no inventory.json) is detected by the registry and imports | A1+P2b |
| AC-18 | Stale-manifest safety | FX-4 imports as interrupted/unknown, FX-4L imports without the prior run's findings (reported as unlisted) — neither as complete-with-stale-data | A1+P2b |
| AC-19 | Identity stability | an Observation persisted before P1 re-imports after P1 with 0 new ids (all importers, not only aranum) | P1 |

## 7. Benefit metric and baselines

**Metric:** AC-01..19 passing, measured by the **P2a acceptance harness** against FX-1..4.
P2a lands alongside P1 (before A2), so every later sprint reports a **measured** AC delta.
A1's own Phase-8 number is the first harness run (A1 creates the fixtures; before A1 every AC is
inconclusive by construction — that is the honest baseline, not 0/19).

**Regression baselines:**
- **A1 (base exists: `main@2493def`)** — captured in Phase 5, in a disposable worktree
  (`build/worktrees/plan002-base`): `python3 -m pytest aranumtoolkit/tests/ -rA -q -p
  no:cacheprovider` and `bash aranumtoolkit/tests/smoke.sh`; raw output + rc in
  `docs/test-strategy/raw/PLAN-002-A1-baseline-2493def-*`. Re-captured only if A1's base moves
  (e.g. S5 merges first). **Result (measured, rc 0): pytest 588 passed, 5 skipped, 100
  subtests (verified from raw output by Claude); smoke rc 0, PASS 407 / FAIL 0 / SKIP 0, fp-harness "no FPs, TP markers intact".**
- **P1/P2a (base `cc491ae`, purplesploit `main` after codex merged PR #113/#114, 27 OCT)** —
  captured by Claude in worktree `purplesploit/build/worktrees/p1` (branch
  `codex/plan002-p1-auth-context`) with venv `purplesploit/build/venv-plan002` (`pip install -e
  '.[dev,ai]'`; the system interpreter lacks fastapi/prompt_toolkit/openpyxl ⇒ 17 collection
  errors, an environment defect, not a code result): `python -m pytest -rA -q -p no:cacheprovider
  -o addopts=''` ⇒ **4830 passed, 1 skipped (`test_api_surface.py:135`, google.protobuf absent),
  rc 0**; per-test manifest `docs/test-strategy/raw/PLAN-002-P1-baseline-cc491ae-manifest.tsv`
  (4830 rows), raw `…-pytest.txt`.
- **P1 execution split (structural Step-0 guarantee):** codex run A = Step 0 snapshot + P2a harness,
  test-only (no `python/purplesploit/` edits), committed by Claude **before** codex run B (P1
  behavior) starts.
- **A2, A3, P2b, P3–P5 — deferred to each sprint's own Phase 6** (authorized by Claude;
  reason: their base SHAs do not exist yet — each branches from the previous integrated tip, and
  purplesploit's base is a moving uncommitted codex tree). Captured at the real base immediately
  before the first edit; consequence accepted.

## 8. Sprint map and order

```
A1 ──────────── A2 ── A3 ──┐
P1 ── P2a ─────────────────┴── P2b ── P3 ── P4 ── P5
```

A1 ∥ (P1 → P2a): disjoint repos, spec fixed. P2a (harness) needs only the AC definitions and
FX fixtures as they appear. P2b needs A3 (final FX-2) and P1 (fields). Each sprint: own branch,
independently shippable and revertable.

---

## 9. aranum sprints (Claude executes)

Branch `dev/<topic>` per sprint from the integrated tip of the previous one; A1 from `main`
(2493def, or the S5 merge tip if S5 lands first — then re-baseline). Conventional commits,
CHANGELOG `[Unreleased]` in the same commit; release version assigned at integration,
coordinated with S5's v0.35.0. Every A-sprint is MINOR-level (additive output; no consumer-parsed
format removed). Tests in `aranumtoolkit/tests/`; suite = §7 commands.

### A1 — Published contract, per-stage completion manifest, partial runs, fixtures

**Closes:** completion-semantics blocker; R-1..R-4, R-11; feeds AC-01/02/09/11/12/17/18.

| Sub-component | Files | Change | Failure mode introduced |
|---|---|---|---|
| A1.1 inventory version | `nmap-parse.py` | `schema_version: "1"`, `tool`, `tool_version` in the `--json` envelope | a consumer requiring exact key sets breaks (none found) |
| A1.2 JSON Schemas | new `aranumtoolkit/schemas/{inventory-1,findings-2,posture-1,run-state-1,bundle-manifest-1,dispatchers-1}.schema.json` | Draft 2020-12; strict envelopes, `additionalProperties: true` at record level | schema/emitter drift — caught by A1.6 |
| A1.3a stage records | new `aranumtoolkit/network/manifest.py` (`stage_begin`, `stage_end`); called by `auto-enum.sh`, `local-enum.py`, `report.py` | each stage owns **one file** `stages/<run|local|report>.json`: `stage_begin` writes `{status: running, run_id, started_utc, invocation{…} (A3), consumed[]}`; `stage_end` rewrites it `{status ∈ complete/partial/failed, exit_code, finished_utc, produced[]{path(relative), schema}}`. Apart from purge-on-mint (A1.3c), a stage never reads or rewrites another stage's record. **bash `run` stage:** `trap 'stage_end run "$?"' EXIT` immediately after `stage_begin` so every `exit N` (`auto-enum.sh:239,247,252,348,417,452,840,857,884`) records its status; SIGKILL still leaves `running` ⇒ interrupted (correct). `--plan-only` ⇒ `complete`; in every mode the run stage's `produced[]` includes each root file it wrote (`plan.json`, `queue.jsonl`, `guidance.json`, inventory, run-state) so none trips P2b's unlisted-file diagnostic (R-28, H15) | an interrupted stage leaves `status: running` ⇒ folds to **interrupted** |
| A1.3b derived manifest | same module, `build_manifest(outdir)`; called at every `stage_begin` (after deleting the old manifest) and every `stage_end` | `bundle-manifest.json` is a **pure function of the tree**: reads all `stages/*.json`, digests every file they list **now** (no digest carried forward), writes atomically `{schema_version, run_id, tool_version, kb{digest}, stages{…}, files[]{path, schema, sha256, produced_by}, status}`. Fold: any `failed` ⇒ failed; any `running` ⇒ interrupted; any `partial` ⇒ partial; records disagreeing on `run_id` ⇒ `stale` ⇒ partial (should be unreachable given A1.3c purge-on-mint; kept as a defensive fold); absent stages are simply absent (fold over present stages; no stage record ⇒ unknown); `manifest.run_id` = the single id the records share | manifest is never authoritative over the tree — rebuild is always safe (structural fix for R-2/R-3/R-17) |
| A1.3c run_id + purge-on-mint | `auto-enum.sh` (existing `RUN_ID`, `:188`), `local-enum.py`, `report.py:1710-1714` | `run` mints; `local` mints only if no `stages/run.json` exists, else inherits; `report` inherits (stages/run > stages/local > run-state) and never mints. **A stage that mints deletes every other `stages/*.json` at its `stage_begin`** (R-26), so records from two runs can never coexist; outputs of the previous run left on disk (e.g. findings.json) are then listed by no stage ⇒ P2b reports them as unlisted, never imports them as complete. findings.json, posture.json, manifest all carry the run_id (R-21) | a re-run without `-report` leaves an old findings.json visible on disk but excluded from the bundle — intended and reported |
| A1.4 partial continues | `aranum.py:731-733,749-751,759-760`, `_run_report_chain` (`:663-665`) | auto-enum rc **4** proceeds to `local`/`report`; **report-stage** rc 1 (partial diagnostics, `report.py:2917`) maps to stage `partial`; dashboard renders on complete or partial. **Exit precedence (R-23, R-27):** fold ∈ {interrupted, failed, unknown} ⇒ first nonzero stage rc, else 1; else any stage rc ∉ {0,4} (excluding report rc 1) ⇒ that rc; else 4 if the fold is partial/stale; else 0 | operators relying on "rc≠0 ⇒ no report" now get a report on partial runs — intended |
| A1.5 dispatchers list | new `aranumtoolkit/network/dispatchers.json` + generator in `make fixtures-interop` | `{name, script, alias_of, category, uses_credentials, tool_family[]}` from `enum-*.sh` (`uses_credentials` = references `ENUM_USER`; measured 16/74 by Mythos), validated against the file tree (R-11, R-18) | stale list — A1.6 fails if a script is missing from it |
| A1.6 tests | new `test_interop_contract.py` | emitter outputs validate against schemas; manifest digests match the tree; **two-process chain `run`→`report` ⇒ manifest lists inventory.json under `produced_by: run`** (H6); FX-4 ⇒ `interrupted`; **FX-4L (local-only re-run without `-report`) ⇒ prior findings.json not in `files[]`, status not complete** (H11); rc-4 path produces findings.json + `partial` + exit 4; unbound-variable abort in auto-enum ⇒ launcher rc ≠ 0 (H12); `--plan-only` ⇒ `stages/run.json` complete (H13); dispatchers.json ≡ `enum-*.sh` set | — |
| A1.7 fixtures | `aranumtoolkit/tests/fixtures/interop/` | FX-1, FX-2 v0, FX-2L v0, FX-3, FX-4 via `make fixtures-interop` | — |

**RED proofs (Phase 7c):** corrupt one file after the manifest ⇒ digest test red; drop `status`
⇒ schema test red; make `report` skip `build_manifest`'s read of `stages/run.json` ⇒ H6 test red;
make `stage_begin` not write `running` ⇒ FX-4 test red; remove purge-on-mint ⇒ FX-4L test red;
remove the EXIT trap ⇒ H12/H13 tests red; add an `enum-x.sh` without listing it ⇒
dispatcher test red; revert A1.4 ⇒ rc-4 test red (and H1 at the pre-fix commit is the first RED).

**Decision — completion signal.** (a) **per-stage status files + manifest derived from the tree
on every stage boundary** (chosen, rev 3); (b) run-state.json + exit code; (c) `.done` sentinel;
(d) one manifest written only by auto-enum; (e) one manifest carried forward and patched by each
stage (rev 2). (b) has no exit code offline and no file list; (c) carries no status/digests; (d)
is single-stage (R-2); (e) loses or mis-carries other stages' records across processes (R-17).
(a) removes cross-process state entirely: each stage writes only its own record, and every digest
is recomputed. Flip if: aranum collapses to one stage.

**Decision — schema strictness.** (a) **permissive records, strict envelopes** (chosen);
(b) fully strict — breaks consumers on every additive field. Flip if: a field changes meaning ⇒
bump that schema's version instead.

**Exit:** A1.6 green; fixtures valid; no regression vs the §7 A1 manifest. **Rollback:** revert the
A1 merge; purplesploit's current reader does not depend on any A1 output.

### A2 — SARIF correctness, run-pinned KB subset, ATT&CK ids, logical id

**Closes:** SARIF commitments, Q12 KB placement, R-7, R-8; feeds AC-06/08/11, P5.

| Sub-component | Files | Change |
|---|---|---|
| A2.1 SARIF | `report.py:2667-2696` | `ruleId = rule_id`; `rules[]` from KB (name=title, shortDescription=line, fullDescription=why, help=fix, helpUri=refs[0]); `logicalLocations` `host:port`; `driver.version` = aranum VERSION; `properties {category, kb_id, confidence, scope}`; SARIF 2.1.0 schema-validated in tests |
| A2.2 inline KB subset | findings envelope `report.py:2832-2896` | `kb: {schema, aranum_version, digest, categories{referenced}, classes{referenced}, checks{referenced}}`; entries byte-identical to the installed KB; digest = sha256 of the installed `finding-kb.json`; new `kb-subset-1.schema.json` (R-8) |
| A2.3 ATT&CK ids | same | subset entries add `attack_ids[]` normalized from refs (`/techniques/T1558/003/` → `T1558.003`) |
| A2.4 logical id | record builder `report.py:360-395` | additive `logical_id = sha256(rule_id|host|port|service|user|artifact_id)` (the non-line `finding_id` inputs, `report.py:1440-1444`; empty `rule_id` (`report.py:365` default) ⇒ substitute `evidence_identity`, R-34) for cross-run linking (R-7, R-20); `finding_id` unchanged; within-run collisions measured on `tests/fixtures/bulk-enum` and a network tree (H10) and reported, not hidden |
| A2.5 tests | `test_findings_fidelity.py`, new `test_sarif_contract.py` | subset closed under reference and reloadable by aranum's own KB loader; ATT&CK table; SARIF validation; `logical_id` stable across a banner change |
| A2.6 fixtures | regenerate FX-2 → v1, bump digest | — |

**RED proofs:** KB with a referenced class removed ⇒ closure test red; subset without
`categories` ⇒ reload test red; perturb host in `logical_id` input ⇒ stability test red.

**Decision — inline KB default-on vs `--inline-kb` flag.** (a) **always emit** (chosen: only
referenced entries, additive, AC-11 needs portability without a remembered flag); (b) opt-in
flag (Q12 wording). Flip if: subset > 10% of FX-2's findings.json (hypothesis H4, measured in A2)
— then gate behind the flag and have the launcher always pass it. Deviation recorded for codex.

### A3 — Auth-context stamping without inference

**Closes:** aranum half of §4; R-5; feeds AC-05, AC-14 (via FX-2 v2), P4.

| Sub-component | Files | Change |
|---|---|---|
| A3.1 declared scope | `aranum.py` CLI, `local-enum.py`, `_lib.sh`, credentialed dispatchers | new optional `--auth-scope {local,domain,machine}` stamped `scope_basis: "declared"`, applied through a **per-tool-family mapping table** (R-19), shipped as data beside `dispatchers.json`: nxc (domain ⇒ `-d D`; local ⇒ `--local-auth`; machine ⇒ `-d D` + `account$`), impacket (domain ⇒ `D/user`; local ⇒ `./user` or `HOST/user`; machine ⇒ `D/account$`), ldapsearch/LDAP family (domain/machine ⇒ bind `user@D`; local ⇒ **skipped**), ssh/other non-domain families (scope recorded, argv unchanged). Under declared `local`, domain-only checks are skipped and **recorded at check granularity** (R-30): the dispatcher writes `<svc>/<ip>/_skipped-checks.json [{check, reason}]`; report.py appends `skipped_checks[]` to that endpoint's coverage row (field added to the A1.2 findings/coverage schema), so anonymous checks still run and AC-04 stays lossless. Declared `domain`/`machine` without `-d` ⇒ usage error rc 2 (R-31). **`--local-auth` is new to aranum** |
| A3.2 invocation carrier | `stages/run.json` and `stages/local.json` (A1.3a) for run-global facts; per-host `_meta.json` (`local-enum.py:1014-1020,1091-1097`, read at `report.py:1936-1980`) extended with the same block + `domain` for per-host credentials | `invocation {domain_arg, local_auth_flag, username_form ∈ {bare, backslash, slash, upn, machine$}, credential_kind ∈ {password, hash, key, ticket, none}, auth_scope_declared}` — argv facts only, written by the stage that built the argv (`auto-enum.sh:374-375` env, `nxc_creds_array`, `resolve_cred` `local-enum.py:280-301`, `_win_user` `:737-740`, argv split `:824-829`); report.py reads them — it never re-derives (R-18) |
| A3.3 scope rule | report.py | without a declared scope, `scope` is set **only** when unambiguous: `local_auth_flag` ⇒ `local`, `scope_basis: "invoked"`; no credential ⇒ `auth_method` null-session/anonymous; **everything else ⇒ `scope: null`**. `domain`/`machine` never come from username shape or `-d` alone |
| A3.4 emission | record builder `report.py:360-395`, posture subjects | `auth_context {account_label (username only, no secret), scope, scope_basis, domain, local_host, auth_method, invocation}` on **every finding from a `uses_credentials` dispatcher (incl. null-session attempts) and every local-stage posture subject**; null for findings from `uses_credentials: false` dispatchers — dispatcher-level wins, so a mixed dispatcher like `enum-smb.sh` stamps all its findings (R-25, R-32). **Population rule (R-29, per TURN 7):** `local_host` = target host iff scope ∈ {local, null}, else null; `domain` = declared domain iff scope ∈ {domain, machine}, else null (a bare `-d` value lives only in `invocation.domain_arg`). aranum emits `account_label`, never `account_ref` |
| A3.5 tests | new `test_auth_context.py` | for each declared scope × tool family: argv **and** stamp; declared local ⇒ LDAP authenticated checks listed in `skipped_checks[]` while anonymous checks still run (H8, H14); declared domain on 10 hosts ⇒ one identity tuple (`local_host` null); `--auth-scope domain` without `-d` ⇒ rc 2; `-d WORKSTATION` without `--auth-scope` ⇒ `scope: null`; `HOST\admin` on two hosts ⇒ two null-scope contexts with distinct `local_host`; declared local on two hosts ⇒ two distinct identity tuples; a live `--dry-run -u x -d Y` run leaves the invocation block in `stages/run.json` (H7, pre-fix RED) |
| A3.6 fixtures | FX-2 → v2, FX-2L → v1, bump digests | — |

**RED proofs:** strip `--local-auth` from the argv builder ⇒ A3.5 red; reintroduce
`-d ⇒ domain` inference ⇒ the `-d WORKSTATION` test red.

**Decision — where scope comes from.** (a) **declared, else unambiguous-invocation-only, else
null** (chosen); (b) stamp-as-invoked from `-d`/username shape (rev 1 — rejected per R-5: it
encodes the forbidden inference upstream). Flip if: never — excluded by the owner's model.

---

## 10. purplesploit sprints (codex executes; Claude reviews via the channel)

Briefs go to codex via interop-channel TURN 10+. codex follows purplesploit's roadmap rules, its
Mythos review cadence, and its CLAUDE.md commit policy.

### P1 — CWP1 ride-along: provenance + auth_context + credential scope

Placements: interop-channel TURN 8.
- **Step 0 (before any edit, R-22):** serialize the outputs of every importer (containers, cloud,
  identity, nmap, aranum, interchange) over their existing fixtures at P1's base into a
  committed fixture directory with a recorded digest — the AC-19 "pre-P1 persisted" set.
- `core/execution.py`: `AuthContext` once (~line 32); on `ExecutionRequest` (after
  `options`/`options_locked`), `ExecutionResult` (beside `tool`/`tool_version`; copied from the
  request on every outcome), `Observation` (first-class). Promote `source_tool,
  source_tool_version, source_schema, source_id, raw` to first-class `Observation` fields.
- **Identity stability (R-12):** the `observation_id` input must be unchanged for existing records —
  either include the promoted fields in the identity input in the same canonical position they
  had inside `attributes`, or freeze the pre-promotion dict for hashing. Applies to every importer
  (containers, cloud, identity, nmap, aranum). The aranum inventory schema token
  (`aranum/inventory-unversioned;adapter=1`) stays pinned for identity even after inventory v1
  appears, or P2b ships a one-shot id migration. Test = AC-19.
- Carry path: `framework._complete_module_results` + early error constructors;
  `ExternalToolModule.execute_command`; `normalize_observations` (no inference, AC-16).
- Credential stores (session dict, legacy SQLite, ORM/API + schemas + sync + routes):
  `account_ref`, `scope`, `local_host`; identity `(username, scope, domain, local_host)`;
  additive migrations, null = unknown (AC-14). **Null scope never merges** — such records stay
  per host (R-29). `account_ref`: P3 copies the request's; P2b (offline) resolves by identity-tuple
  match against the stores, else null.
- `to_dict`/`from_dict` (AC-15). Read compat for the old attribute placement.

### P2a — Acceptance harness (lands with P1)

`python/tests/integration/interop/test_aranum_acceptance.py` (codex TURN 11): one parametrized check per AC-01..19,
tri-state pass/fail/inconclusive, consuming FX bundles from a vendored directory with recorded
digests. Run at P2a's base to record the measured baseline; re-run at each later sprint.
RED proof: mutate FX-2 to drop a finding ⇒ AC-03 red; disable idempotency ⇒ AC-07 red.

### P2b — Importer v2

- **Manifest-first:** manifest present ⇒ verify digests; occurrence key = `manifest.run_id`
  (not the content fingerprint, so re-rendering a local-only tree keeps ids — H9);
  run-state.json optional when `stages.run` is absent; import every listed document; **inventory optional** when the manifest lists none (AC-17);
  registry detects any directory with a manifest **or** inventory.json. No manifest ⇒ import,
  mark `interrupted/unknown` (never complete; AC-18). `partial` ⇒ import marked partial (AC-09).
  Unlisted `*.json` in the root ⇒ diagnostic observation, never silently ignored.
- Validate each document against the vendored aranum schemas (pinned by digest).
- Mapping per study errata §7 (FAIL/WARN once from findings.json; posture observations only;
  per_host roll-up; coverage seeds service rows; partial/errors/quarantine/redaction/generation
  → data-quality; line ≤300 → description; full record → `raw`; `new` → DRAFT; unknown kept raw).
- KB enrichment from the inline subset (installed-KB fallback only if version+digest match);
  ATT&CK ids; `Finding.metadata["source_observation"]` (incl. `auth_context`) and
  `Finding.metadata["source_identity"]` + `logical_id` for AC-08.
- Replace codex's invented KB fixture shape (`checks.<id>.remediation.steps`) with FX-2.

### P3 — `recon/aranum` backend module + auto-enum coalescing

- One module; operations registered from the vendored `dispatchers.json` (AC-01), aliases, and
  "Run Selected Services"; scope options (network, AD, `--local` Linux/Windows) and transport
  choice pass through; `auth_context` → `--auth-scope` and invocation per §4.
- Completion = manifest status after the process exits; then auto-import via P2b.
- Auto-enum: coalesce selected services into one run (`--only`, `-P`, `--service-parallel`);
  aranum owns the baseline for the 8 overlap services (SMB, LDAP, WinRM, RDP, SSH, MSSQL, DNS,
  HTTP/S); purplesploit keeps specialist follow-ups (Q10).
- Fake-runner tests: AC-01, AC-10, AC-12 (incl. rc 4 ⇒ partial import).

### P4 — Account-derived analysis + Linux posture (CWP2/CWP5 extension)

Local-credential reuse across hosts ⇒ finding; domain effective-on-host ⇒ graph edge; machine
accounts distinct — derived only from non-null `auth_context.scope`; null scope ⇒ no derivation
(reported as "scope unknown" coverage). CWP5 Linux importer consumes `linlocal` posture.

### P5 — Interchange (CWP7)

aranum's corrected SARIF (A2.1) through the existing SARIF 2.1 path as a fallback lane;
round-trip fixture. Native bundle import stays primary.

---

## 11. Review and gates

- **Plan review (Phase 5):** Mythos (owner directive 25 OCT) — validity + hypotheses with
  falsifiers. Recorded in `docs/review/REVIEW-PLAN002-R{1,2,3}-26OCT2026-mythos-plan-review.md`
  (verbatim copies of the raw outputs); dispositions in §13. Max 3 patch rounds, then escalate.
- **A-sprints:** Phase 6 diff review by an independent model; Phase 7 test card in
  `docs/test-strategy/` incl. the RED proofs listed per sprint; Phase 8 measured AC delta via
  P2a's harness (vendored copy run against aranum's fixtures) or, if P2a is not yet landed,
  labeled inferred.
- **P-sprints:** codex's own cycle; Claude reviews P1, P2a, P2b, P3 diffs through the channel
  against this plan and §2.

## 12. Open items for the owner (non-blocking)

- A2 inline-KB default-on deviates from the Q12 "flag" wording (rationale §9 A2; H4 measures it).
- `auth_method` enum lacks `key` (SSH key auth exists: `local-enum.py --key`). Proposed additive
  value `key`; until approved, A3 stamps `credential_kind: key` in `invocation` and leaves
  `auth_method` null for key auth.
  **Owner ruling 27 OCT: APPROVED** — "yes add key. we want as many ways in / out as possible."
  `auth_method` gains `key` on both sides: aranum A3 stamps `auth_method: key` for key auth;
  purplesploit `AuthContext` accepts `key` (P2b brief, additive enum value). Owner also restated:
  the tool is unsafe by design — spend no effort hardening/locking it down (§2 scope rule).
- A1 base: whether S5 (`dev/desktop-transports`) merges before A1 branches (re-baseline if so).

## 13. Review record

### Round 1 — Mythos, 26 OCT 2026 — verdict RED (high R-1..R-5)

Raw: `build/scratch/plan002-review/review-1.md` (rc 0). Spot-checked by Claude before acceptance
(measured): `aranum.py:731-733` (report skipped on rc≠0), `auto-enum.sh:884` (exit 4),
`local-enum.py:737-740,824-829` (domain from username shape), no `--local-auth` in aranum,
`core/execution.py:93-97` (attributes in identity), `docs/review/` exists.

| ID | Sev | Disposition | Where |
|---|---|---|---|
| R-1 local-only bundles unimportable | high | accepted | §3, FX-2L, AC-17, P2b |
| R-2 manifest single-stage for a three-stage run | high | accepted | A1.3 per-stage manifest |
| R-3 stale manifest verifies complete | high | accepted | A1.3(i), FX-4, AC-18, P2b run_id check |
| R-4 partial run never reaches report | high | accepted | A1.4, FX-3, AC-12 |
| R-5 stamp-as-invoked = upstream inference | high | accepted | A3 rewritten; `key` → §12 |
| R-6 FX-2 depends on A2/A3 | med | accepted | §5 versioning, AC-05 sprint column |
| R-7 AC-08 undecidable | med | accepted | AC-08 redefined, A2.4 `logical_id` |
| R-8 KB subset loses categories; shape unpinned | med | accepted | A2.2, kb-subset schema, P2b fixture swap |
| R-9 A1 baseline wrongly deferred | med | accepted | §7 — captured now |
| R-10 A-sprint benefit unmeasurable | med | accepted | P2a split, lands with P1 |
| R-11 no dispatcher source of truth | med | accepted | A1.5, AC-01 |
| R-12 promotion changes observation ids | med | accepted | P1 identity stability, AC-19 |
| R-13 AC-13 undecidable | low | accepted | AC-13 golden files |
| R-14 manifest "refuse/mark" contradiction | low | accepted | P2b: import, mark interrupted |
| R-15 no RED proofs for A-sprints | low | accepted | per-sprint RED proof lines |
| R-16 `docs/reviews/` → `docs/review/` | low | accepted | §11 |

Sweeps (class → match identity → count → resolution):
- *Single-stage assumption* → searched rev 1 for "run end", "end of run", "auto-enum", "exit code"
  → 4 hits (A1.3, A1 decision, P3, AC-12) → all rewritten to per-stage.
- *Inference of account scope* → searched rev 1 for "domain passed", "username", "infer",
  "as invoked" → 3 hits (A3.2, A3 decision, §4 bullet) → all replaced by the A3.3 rule.
- *Undecidable acceptance wording* ("linked", "render", "likely") → 3 hits (AC-08, AC-13, §7
  baseline estimate) → redefined / removed.

Hypotheses H1–H5 adopted as Phase-6 probes: H1 ⇒ A1.4 test (pre-fix RED proof), H2 ⇒ AC-17 at
P2a base, H3 ⇒ FX-4 construction, H4 ⇒ A2 flip check, H5 ⇒ A2.4 motivation test.

### Round 2 — Mythos, 26 OCT 2026 — verdict RED (high R-17, R-18)

Raw: `build/scratch/plan002-review/review-2.md` (rc 0). All 16 round-1 dispositions confirmed
present; R-9 lacked its result line (added in §7).

| ID | Sev | Disposition | Where |
|---|---|---|---|
| R-17 delete-at-stage-start loses other stages' records | high | accepted — **escalated to a design change** (recurring class, see below) | A1.3a/b, A1 decision (e) |
| R-18 no carrier for invocation facts into report.py | high | accepted | A3.2 carrier = `stages/*.json` + `_meta.json`; `uses_credentials` in A1.5 |
| R-19 `--local-auth` covers 7/16 credentialed dispatchers | med | accepted | A3.1 per-family mapping table, coverage-reason skips |
| R-20 `logical_id` collides within a run | med | accepted | A2.4 adds `user|artifact_id`; AC-08 group-level |
| R-21 `run_id` undefined for local/report | med | accepted | A1.3c; P2b keys on `manifest.run_id` |
| R-22 pre-P1 observation set never captured | med | accepted | P1 step 0 |
| R-23 composite exit code undefined | low | accepted | A1.4 precedence rule |
| R-24 manifest cites a KB version before A2 | low | accepted | A1.3b `kb{digest}` only |
| R-25 "authenticated" undefined | low | accepted | A3.4 definition |

**Recurring class — cross-process stage state** (R-2 → R-3 → R-17): each patch to "who writes the
manifest when" opened a new hole because aranum's stages are separate processes. Escalation per
the 3-round rule: replaced patching with a structural guarantee — each stage writes only its own
`stages/<stage>.json`; `bundle-manifest.json` is recomputed from the tree at every stage boundary
and never carries a digest forward. The same per-stage record is the R-18 carrier.
Sweep: searched rev 2 for "manifest", "carried", "stage", "first action", "last action" → 9
hits (§3 rows, A1.3, A1 decision, A1.6, RED proofs, P2b, P3, AC-18, §13) → all consistent with
the derived-manifest design.

New hypotheses H6–H10 adopted as Phase-6 probes (H6 → A1.6; H7 → A3.5 pre-fix RED; H8 → A3.5;
H9 → P2b; H10 → A2.4).

### Round 3 (final) — Mythos, 26 OCT 2026 — verdict RED (high R-26)

Raw: `build/scratch/plan002-review/review-3.md` (rc 0). All 25 prior dispositions confirmed
present and resolved; §3 line references re-verified; `stages/` placement measured safe for
report.py's collector (`report.py:1834,1865`; bulk-layout run with `stages/run.json`: identical
output, 25 findings, 0 diagnostics).

| ID | Sev | Disposition | Where |
|---|---|---|---|
| R-26 local-only re-run folds complete over stale findings | high | accepted — **design change: purge-on-mint** | A1.3c, FX-4L, AC-18, A1.6, RED proof |
| R-27 exit precedence returns 0 on crashed runs | med | accepted | A1.4 precedence rewritten; H12 test |
| R-28 bash run stage never reaches `stage_end` on early exits | med | accepted | A1.3a EXIT trap; plan-only `complete`; produced[] lists root files |
| R-29 `local_host`/`domain` population undefined | med | accepted | A3.4 population rule; P1 null-scope never merges; `account_ref` resolution |
| R-30 no check-level skip carrier | med | accepted (option a, lossless) | A3.1 `_skipped-checks.json` → `skipped_checks[]` |
| R-31 declared domain/machine without `-d` | low | accepted | A3.1 usage error rc 2 |
| R-32 mixed dispatcher stamping | low | accepted | A3.4 dispatcher-level wins |
| R-33 smoke result line | low | accepted | §7 |
| R-34 empty `rule_id` collapses `logical_id` | low | accepted | A2.4 substitute `evidence_identity` |

**Recurring class — cross-process stage state** (R-2 → R-3 → R-17 → R-26). Round 3 is the last
patch round, so the class is closed by a structural guarantee rather than a further fold-rule
patch: **a stage that mints a run_id purges every other stage record**, so records from two runs
can never coexist and "stale but complete" is unrepresentable. The `stale` fold remains only as
a defensive branch. Sweep: searched rev 3 for "mint", "stale", "newest", "run_id" → 8 hits
(A1.3b, A1.3c, A1.6, RED proofs, FX-4L, AC-18, P2b, §13) → all consistent with purge-on-mint.

**Phase 5 gate: `waived` for one item, green otherwise.** No fourth review round is opened (rule).
- *Waived item:* R-26's purge-on-mint design and the R-27..R-34 patches have **not** been
  re-reviewed by the plan reviewer.
- *Authorized by:* Claude, 26 OCT 2026, under the owner's "Proceed".
- *Reason:* the 3-round cap; the remaining risk is confined to A1.3/A1.4/A3 internals, which are
  covered by concrete falsifiers (FX-4L, H11–H15) and by the mandatory Phase 6 independent diff
  review of A1 and A3.
- *Consequence accepted:* if the A1 diff review or FX-4L disproves purge-on-mint, A1 stops and the
  design question goes to the owner — not a fourth patch.
- *Unaffected:* P1/P2a (purplesploit) do not depend on the A1.3 fold and may proceed now.

Hypotheses H11–H15 adopted as Phase-6 probes (A1.6 / A3.5 tests named above).

---

## 14. Sprint execution record

### P1 + P2a — purplesploit, 27 OCT 2026

- **Branch** `codex/plan002-p1-auth-context`, base `cc491ae`. Run A (codex, test-only: step-0
  snapshot + P2a harness) committed `75e0ce8` **before** run B started (structural Step-0
  guarantee). Run B + fix rounds C, D (codex) + R3-1 guard (Claude) committed `1cdb70f`.
  PR #115 (draft). Committed diff byte-identical to the tested diff
  (sha256 `1ad5502f…`).
- **Phase 6 — independent diff review (Mythos; implementer = codex):**
  - R1 RED: R-1 (pre-P1 stores backfill divergent uuid4 refs → startup sync duplicates every
    credential), R-2 (C2 terminal delete by name → silent 404), R-3 (API test mock lacks
    account_ref) high; R-4 (null-scope identical re-adds never dedupe) medium; R-5, R-6, R-8,
    R-10 fixed; R-7 → P2b brief (translate aranum's `auth_context` block); R-9 documented
    (host_database / api_surface / attack_formats absent from the AC-19 corpus; all use
    explicit ids).
  - **Ruling R-1 + R-4 (Claude):** `account_ref` deterministic over
    `(username, scope, domain, local_host)` for every scope; R-29's "null scope never merges —
    such records stay per host" read as: identical tuples dedupe, differing `local_host` stays
    distinct, null scope never merges into a declared scope.
  - R2 RED: R2-1 (deterministic backfill collides on pre-P1 duplicate rows → unique-index
    failure, store construction raises on every start) high; R2-2 (3 not-found tests mock only
    `.first()`) high. **Ruling R2-1 (Claude, owner-visible):** migrations never raise; duplicate
    identity rows fold into the lowest id, extra rows' material preserved in
    `metadata.folded_candidates` ("never lose findings").
  - R3 RED: R2-1/R2-2 resolved; R3-1 high (fold rewrite dropped the "only when absent" guard →
    every restart rewrites caller-supplied/renamed refs). R3-2, R3-3 low.
- **Phase 6 gate: `waived` for one item, green otherwise.** No fourth patch round (rule).
  - *Waived item:* the R3-1 fix was not re-reviewed by the peer.
  - *Resolution instead:* structural invariant from §10 P1 ("generated when absent") enforced at
    both backfill sites (`WHERE account_ref IS NULL OR account_ref = ''`), proven by two tests
    that **fail with the guard removed** (disposable copy) and pass with it.
  - *Authorized by:* Claude, 27 OCT 2026. *Consequence accepted:* a defect in the two-line guard
    would surface as ref rotation, which the two tests decide.
  - *Deferred (low, recorded):* R3-2 ORM `folded_candidates` reachable by raw SQL only (not via
    API) — satisfies "recoverable"; expose read-only later if needed. R3-3 each store keeps its
    own lowest id; legacy is the sync source of truth, by design.
- **Phase 7:**
  - (a) Full suite `python -m pytest -q -rA -p no:cacheprovider -o addopts=''` at `1cdb70f`:
    **4903 passed, 16 skipped**; per-test (whitespace-normalized ids) vs
    `PLAN-002-P1-baseline-cc491ae-manifest.tsv` and `PLAN-002-P1-runA-manifest.tsv`:
    **0 regressions** (73 / 38 new). Interim reds were classified: 2 setup errors = concurrent
    runs sharing `~/.purplesploit` (pass alone); 1 workflow timeout under host load (3/3 alone,
    green in the solo final run). Raw: `docs/test-strategy/raw/PLAN-002-P1-final-*`.
  - (b) New behavior: AC-14/15/16 pass; unit tests for AuthContext serialization, early-error
    carry, old-placement read, placement/None identity equivalence, caller-dict immutability,
    null-safe dedupe in all three stores, migration fold (each store + cross-store),
    ref stability across restarts, route lookup by ref / unique name.
  - (c) Gates RED-able: AC-14/15/16 strict xfail at `75e0ce8`; AC-16 fails under a
    DOMAIN→scope inference mutation; AC-19 fails under a mutated snapshot id (run A);
    R3-1 guard tests fail with the guard removed.
- **Phase 8 — benefit (measured, same harness):** AC-14, AC-15, AC-16 fail → pass; AC-19
  pass → pass; AC-01..13, 17, 18 inconclusive → inconclusive (fixtures arrive with A1–A3).

### A1 — aranum interop contract, 27 OCT 2026

- **Branch** `dev/a1-interop-contract`, base `main@2493def`; ff-merged to `main` at `337cc7a`,
  PR #10 (MERGED), remote+local branch deleted. Four commits: `2bfac0c` (plan docs), `636409d`
  (A1.1 inventory envelope + A1.2 six schemas), `a795965` (A1.3 manifest module), `337cc7a`
  (A1.3/A1.4 stage wiring + A1.5 dispatcher registry + A1.6 contract tests + A1.7 fixtures).
- **Implementer:** codex (`gpt-5.6-sol`, effort high) to the `.interop/a1-codex-prompt-1.md` brief
  (per the 27 OCT division of labor: Claude plans, codex implements).
- **Phase 6 — independent review (Claude; implementer = codex):** verified the auto-enum EXIT
  trap placement (SCRIPT_DIR defined, no pre-existing trap clobbered), local-enum mint/inherit +
  always-rc-0, report.py run_id resolution (run>local>run-state else null) stamped into both
  findings.json and posture.json on every emit path, aranum.py `_chain_exit_code` exit precedence
  + rc-4 continuation, `test_unified_cli` delegation shims (stub `_chain_exit_code`, no assertion
  weakened), dispatchers.json (76 records / 16 credential-aware / sorted, schema-conformant), and
  the findings-2/posture-1 nullable-`run_id` additions (match R-21).
- **Phase 7 — gate (host; codex's sandbox denies loopback binds):** `pytest aranumtoolkit/tests/`
  → **598 passed, 5 skipped, 100 subtests** (baseline 588 + 10 new contract tests); the 5 failures
  codex reported were all socket-bind denials under its sandbox and pass on the host. `smoke.sh`
  → **652 pass / 0 fail / 1 skip** (incl. fp-harness). RED proofs: codex measured 8 contract
  falsifiers and reverted them.
- **Phase 8 — benefit:** the interop contract is now machine-checkable — every published emitter
  validates against a pinned schema, bundles carry a tree-derived completeness status, and
  partial runs no longer drop findings. Importer-side benefit (AC-01..13) is realized in P2b.

## 15. Credential-reuse testing (owner addendum, 27 OCT 2026)

Owner refinement after the P1 merge: "I want the ability to test local accounts
across various hosts — e.g. for password reuse. think about all of the different
pentesting checklists and possibilities." Owner approved this as **its own sprint**
and chose the ownership split: **purplesploit drives (selects + accounts for
lockout); aranum executes (runs each credentialed test via its existing
dispatchers); P4/P6 derive findings.** Also approved `key` as an `auth_method`
(§12).

### 15.1 What this adds

The account model (P1) already keeps per-host local accounts distinct — the
foundation for reuse testing. P4 derives reuse *passively* from what was observed.
This adds the *active* side: take a credential set the stores hold, test it against
an explicit host set under a declared scope over chosen transports, and record the
outcome as the reuse signal.

**The matrix (the "checklists and possibilities"):**
- **Scope axis (identity):** local account across hosts (`--auth-scope local` /
  aranum `--local-auth`, A3) — the no-LAPS local-admin-reuse check; domain account
  effective-on-host (P4 edge); machine account (kept distinct, P1).
- **Secret axis:** password, NTLM hash, Kerberos ticket, SSH key (`key` auth_method).
- **Transport axis:** the same local secret tested over SMB / WinRM / RDP / MSSQL /
  SSH / VNC — reuse is cross-protocol, so the loop iterates transports, it does not
  assume one.
- **Discipline:** the host set and credential set are always operator-provided and
  explicit (never a discovery-driven open sweep — aranum §9 forbids mass-targeting);
  lockout/attempt accounting is tracked across the whole campaign; every result is an
  observation carrying its `auth_context` so P4/P6 can promote confirmed reuse.

### 15.2 Sprints

**A4 (aranum) — auth-outcome signal.** Credentialed dispatchers emit one explicit
`auth_outcome` observation per credentialed attempt:
`{host, transport, scope, account_label, outcome ∈ success|failure|lockout|error|
anonymous|null-session}` (account_label only, never the secret). Rides on A3's
`auth_context`/`invocation`; no new spray logic in aranum — aranum still runs one
credentialed pass per (cred, host-set, transport, scope) exactly as A3/P3 drive it.
This is the machine-readable reuse signal the importer reads. New fixture FX-5
(reuse): one local account that authenticates on 2 of 3 hosts, one that is locked
out, one domain account effective on a host it is not local to. Feeds AC-20..22.

**P6 (purplesploit) — reuse campaign.** Built on P1+A3+P2b+P3+P4; lands after P4.
- **Selector:** choose accounts × hosts × scope × transports from the stores
  (explicit, bounded sets; a "test this local cred against these hosts" operation).
- **Lockout accounting:** track attempts per account across the campaign; respect a
  configurable threshold; never exceed it; surface near-lockout.
- **Fan-out:** drive aranum per (cred, host-batch, transport, scope) via the P3
  `recon/aranum` module; import each bundle via P2b.
- **Derivation (extends P4):** a local secret confirmed on ≥2 hosts ⇒ a
  reuse finding; a domain account confirmed effective on a host ⇒ a graph edge; a
  machine account stays distinct; null scope ⇒ no derivation. All derived only from
  non-null `auth_outcome`/`auth_context` — never inferred.

### 15.3 Acceptance checks (append to §6)

| # | Check | Pass condition | Sprint |
|---|---|---|---|
| AC-20 | Auth-outcome fidelity | every credentialed attempt in FX-5 yields one `auth_outcome` observation with the right outcome and `auth_context`; anonymous/null-session recorded, not dropped | A4+P2b |
| AC-21 | Local reuse finding | a local account whose `auth_outcome=success` on ≥2 distinct hosts ⇒ one reuse finding naming those hosts; a one-host success ⇒ no reuse finding | P6 |
| AC-22 | No open sweep / lockout safety | the selector never emits a (cred,host) pair outside the operator's explicit sets; attempts per account never exceed the configured lockout threshold (fake runner counts attempts) | P6 |
| AC-23 | Cross-transport | the same local cred is tested over each selected transport; a cred blocked on one transport but accepted on another is reported per transport, not collapsed | P6 |
| AC-24 | Scope honesty | a domain-account success on a host is an effective-on-host edge, not a local-reuse finding; machine accounts never fold into local reuse; null scope ⇒ no derivation | P6+P4 |

### 15.4 Sprint map (revised)

```
A1 ✅ ─ A2 ── A3 ── A4 ──┐
P1 ✅ ─ P2a ✅ ─────────┴── P2b ── P3 ── P4 ── P6
```

A4 branches from A3's tip; P6 is the last purplesploit sprint, after P4. P5
(interchange) is independent and may land any time after A2.

### 15.5 Decision — new aranum spray mode vs. reuse-via-existing-dispatchers

(a) **reuse-via-existing-dispatchers + an explicit auth_outcome signal (chosen):**
aranum runs the credentialed dispatchers it already has, per (cred, host, transport,
scope); the only aranum addition is emitting the outcome. purplesploit owns the
corpus, the fan-out, and the lockout state. (b) a dedicated aranum spray engine —
rejected: duplicates purplesploit's account model and campaign state in aranum, and
pushes mass-iteration logic into the enumeration tool against §9. Flip if: driving
per-host from purplesploit proves too slow and a single aranum batch call is needed —
then add a thin `--reuse <credset> <hostset>` fan-out to aranum that still emits the
same per-attempt outcome.
