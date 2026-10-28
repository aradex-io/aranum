**PLAN-002 review (Phase 5 gate)**

§3 verification summary (all measured this session): provenance-in-attributes `interop/aranum.py:166-173` ✓; projection `202-216` ✓; no `auth_context`/`account_ref`/`local_host` in `core/execution.py` ✓; registry `importers.py:291`, `application.py:62` ✓; inventory envelope unversioned (`nmap-parse.py:613-626`) ✓; run-state `auto-enum.sh:782-813` ✓; findings v2 / posture v1 / SARIF lines ✓; no manifest writer ✓; 74 scripts + 2 symlinks ✓. The claims hold. The gaps are in what §3 did not look at: the run is multi-stage and the local-only path.

## (a) Findings

**R-1 · HIGH · §1, §3, A1, P2 — local-only bundles cannot be imported.**
Failure: operator runs `aranum local --targets … -report`; outdir has findings.json/posture.json but no inventory.json; purplesploit's registry predicate never matches and `import_aranum_bundle` raises.
Evidence (measured): `interop/aranum.py:124-127,135` (inventory required), `importers.py:291` (detect = `inventory.json` exists), `local-enum.py` only *reads* inventory (`:217,1111`), never writes one; `aranum.py:768-786` (`aranum local` path).
Fix: A1 contract makes inventory optional when a manifest is present (manifest lists which documents exist); P2 accepts manifest-bearing bundles without inventory. Add **AC-17: local-only bundle imports** (FX-2 should include a local-only variant).

**R-2 · HIGH · A1.3 — manifest has two writers but the run has three separately-invocable stages.**
Failure: `auto-enum.sh` writes `status: complete`, files = {inventory, run-state}; later `aranum report <dir>` adds findings.json/posture.json (and `--redact` rewrites them). P2 "verify digests" then either ignores unlisted findings (lossy) or fails on mismatch.
Evidence (measured): `auto-enum.sh:879-885` ends with "Next: report.py"; `aranum.py:657-676,725-736` report chain is optional (`-report`) and separate; `report.py:2896,2908,2913` writes; `local-enum.py` is a third stage (`aranum.py:739-765`).
Fix: one manifest module (`aranumtoolkit/network/manifest.py`) invoked at the end of every stage, writing per-stage records `stages{enum,local,report}` each with `status/exit_code/files[]`; top-level status is the fold; rewritten atomically each time. P2 reports unlisted `*.json` as diagnostics, never silently.

**R-3 · HIGH · A1.3 — stale manifest from a prior run in the same outdir verifies as complete.**
Failure: run 1 completes (manifest present). Run 2 into the same `-o` (or `--resume`) is interrupted before the end; run-state.json is only rewritten at the end, so every listed digest still matches run 1 and the import is marked complete while run 2's service dirs are ignored.
Evidence (measured): no `trap` in `auto-enum.sh`; run-state written once at `:782`; `--resume` reuses the dir (`:79,157`); nothing removes prior state at start.
Fix: each stage's first action removes `bundle-manifest.json`; P2 additionally requires `manifest.run_id == run-state.run_id` (and the new stage record) before "complete".

**R-4 · HIGH · P3, AC-09 — a partial run never produces findings via the launcher path.**
Failure: any dispatcher failure makes auto-enum exit 4; `_run_auto_enum` returns before the report chain, so `aranum run … -report` yields no findings.json exactly when AC-09 matters. FX-3 (synthetic) would pass while the live path cannot.
Evidence (measured): `auto-enum.sh:884` `exit 4` when `RUN_FAIL>0`; `aranum.py:731-733` `if rc != 0 or not generate_report: return rc`; same in `:749-751`. Secondary: `report.py:2917` returns 1 on partial and `aranum.py:663-665` then skips the dashboard.
Fix: A1 treats rc 4 as "partial, continue to report" in both chains and records `status: partial`; P3's fake-runner test (AC-12) adds the case "auto-enum rc=4 ⇒ findings.json + manifest partial still produced".

**R-5 · HIGH · A3.2 — "stamp-as-invoked" encodes the forbidden inference upstream.**
Failure: `domain passed ⇒ scope: domain`, but the domain arrives from `-d WORKSTATION` or from username shape (`HOST\admin` split in `exec_argv`), both routinely local accounts. aranum would ship `scope: domain` for two local admins on two hosts; purplesploit faithfully carries it; AC-14 is defeated at the source while AC-16 passes. The credentialed/no `-d`/no `--local-auth` case (nxc uses the target's own realm, unknowable client-side) is unspecified.
Evidence (measured): `local-enum.py:737-740` (`_win_user` prefix), `:824-829` (`DOMAIN\user` split), `:1119` (`-d`), `_lib.sh:249-259` (`-d` only when `ENUM_DOMAIN`; no `--local-auth` exists today, only a log string in `enum-mssql.sh:66`).
Fix: `scope_basis: invoked` records argv facts only (`domain_arg`, `local_auth_flag`, `username_form`, `credential_kind`); `scope` is set only when unambiguous (`--local-auth` ⇒ local; no credential ⇒ null-session/anonymous), otherwise null. `domain`/`machine` come only from `--auth-scope`. Also `auth_method` lacks `key` (local-enum `--key`, `:1117`) — owner-settled enum, additive value, flag for owner.

**R-6 · MEDIUM · §5, §8 — FX-2 depends on A2 and A3 but is "produced in A1".**
Failure: A1.4 validates fixtures against emitters that do not yet emit `kb` or `auth_context`; P2 binds to an FX-2 digest that must change twice.
Evidence (recorded): §5 FX-2 content vs A2.2/A3.3 emission; A1.5 "regenerated by `make fixtures-interop`".
Fix: A1 ships the generator plus FX-1/FX-3 and FX-2 v0; A2 and A3 exit criteria include regenerating FX-2 and bumping its recorded digest; AC-05 sprint column becomes P1+A3+P2.

**R-7 · MEDIUM · AC-08 — not decidable; "linked by stable source_id" is false for changed lines.**
Failure: identity includes the occurrence, so a second run yields new Finding ids with no link field; `finding_id` hashes the cleaned line, so any banner/timestamp change breaks "stable".
Evidence (measured): `report.py:376-379`; `interop/aranum.py:156-157`; codex errata §7 ("not a durable logical identity across runs").
Fix: define link = `Finding.metadata.source_identity=(source_tool, source_schema, source_id)` plus a prior-occurrence lookup; AC-08 pass = identical-line re-run produces N new findings each linked to one prior, and a changed-line case is documented as a new identity. Optionally A2 adds `logical_id = sha(rule_id|host|port|service)` for cross-run linking (cheap).

**R-8 · MEDIUM · A2.2 — inline KB subset omits `categories` and its shape is unpinned.**
Failure: aranum's loader drops any class whose category is absent (`report.py:195-205`), so a `classes`+`checks`-only subset loses every class on reload; codex's existing fixture already assumes a different invented shape (`checks.<id>.remediation.steps`).
Evidence (measured): `finding-kb.json` top keys `schema, categories(10), service_categories, classes(199), checks(99)`, no `version` key; `tests/fixtures/aranum/posture/findings.json`, `test_aranum.py:84`.
Fix: subset = `{schema, aranum_version, digest, categories{referenced}, classes{referenced}, checks{referenced}}`, entries byte-identical to the installed KB plus `attack_ids[]`; publish `kb-subset-1.schema.json`; codex replaces its fixture with FX-2.

**R-9 · MEDIUM · §7 — Rule 3 misapplied to the first sprint.**
Failure: A1's base exists today (`main@2493def`, measured); the skill requires Phase 5 to capture the first sprint's baselines ("always the first", SKILL.md:36-43). If A1 starts before the S5 decision, no pre-change regression manifest exists.
Fix: run `make test` at 2493def now, store the per-test manifest + raw output under `docs/test-strategy/raw/`; re-capture only if the base moves. Keep deferral for A2/A3/P*.

**R-10 · MEDIUM · §7, §11 — benefit is unmeasurable for A1–A3.**
Failure: the harness arrives in P2, after all aranum sprints, so three Phase 8 deltas are "inferred".
Fix: split P2a (fixture-driven harness + measured baseline, `inconclusive` for absent fixtures) to land with P1; A-sprints then report measured AC movement.

**R-11 · MEDIUM · AC-01, P3 — registry has no source of truth; drift is guaranteed.**
Evidence (measured): 76 paths, `enum-https.sh→enum-http.sh`, `enum-xmpp.sh→enum-jabber.sh`; dispatchers are added every release (CHANGELOG).
Fix: A1 publishes `dispatchers.json` (name, script, alias-of, category) generated from `enum-*.sh` and validated in A1.4; P3 registers from the vendored copy; AC-01 compares vendored list vs the bundle's `tool_version` list, drift = diagnostic.

**R-12 · MEDIUM · P1 — promoting provenance fields changes observation identity for other importers.**
Failure: `Observation.__post_init__` hashes `attributes` into the id; `_observations` recomputes ids for records lacking one; containers/cloud/identity/nmap importers put `source_id`/`source_tool` in attributes. Moving those keys changes ids → re-import of previously persisted artifacts duplicates. The inventory schema token change (`…unversioned;adapter=1` → `inventory/1`) likewise changes aranum ids (`aranum.py:153,156`).
Evidence (measured): `core/execution.py:93-97`; `importers.py` `_observations`; `containers.py:250`, `cloud.py:174`, `identity.py:122`, `nmap_importer.py:35`.
Fix: P1 includes the promoted fields in the identity input (or freezes the pre-promotion dict) and adds a test "pre-P1 persisted observation re-imports with 0 new ids"; P2 pins the identity token for inventory or ships a one-shot id migration.

**R-13 · LOW · AC-13** — "render" is not decidable. Pass = for every FX-2 finding with `kb_id`, Markdown and HTML contain Remediation/Validation sections with the KB text and an `auth_context` label; golden-file compare (codex's wording also named XLSX).

**R-14 · LOW · P2** — "refuse `status` absent ⇒ mark interrupted" is contradictory; choose "import, mark interrupted". Manifest `exit_code` must be per stage (R-2).

**R-15 · LOW · A1.4/A2.4/A3.4** — no RED proofs (only P2 has Phase 7(c)). Specify: corrupt a digest / drop `status` ⇒ A1.4 red; `ARANUM_FINDING_KB` with a referenced class removed ⇒ A2.4 closure red; strip `--local-auth` from the argv builder ⇒ A3.4 red.

**R-16 · LOW · §11** — `docs/reviews/` does not exist; aranum uses `docs/review/` (measured).

Completion-manifest verdict: the design closes the blocker **only if** R-2, R-3 and R-4 are folded in; as drafted it is a single-stage signal for a three-stage run. A3 stamping is truthful only after R-5.

## (b) Hypotheses with falsifiers

| # | Hypothesis | Falsifier | Cheapest test |
|---|---|---|---|
| H1 | `aranum run … -report` with one failing dispatcher leaves no findings.json | findings.json appears | stub `enum-unknown.sh` to `exit 1`, run `--only unknown -report` on `all-services.xml`, `ls raw/` |
| H2 | A local-only tree is undetectable by the registry | `default_registry().detect(dir)` returns `aranum-bundle` for findings+posture without inventory | 3-line Python against `tests/fixtures/aranum/posture` minus inventory.json |
| H3 | An interrupted re-run leaves run 1's run-state.json byte-identical | mtime/contents change at run 2 start | start auto-enum on an unroutable target, kill after 2 s, `cmp` |
| H4 | Inline KB subset on FX-2 stays under the 10% flip threshold | subset > 10% of findings.json | sum referenced-entry sizes from `finding-kb.json` for the posture fixture's `kb_id`s |
| H5 | At least one built-in rule yields a different `finding_id` across two runs of the same scope | all FX-2 ids identical after a banner change in one evidence file | run `report.py` twice on a fixture tree with one edited banner line, diff `finding_id`s |

## (c) Verdict

**RED** — unresolved HIGH: R-1, R-2, R-3, R-4, R-5. No blockers. MEDIUM R-6..R-12 should be patched in the same round; LOW items are editorial.
