# REVIEW-009 — S2 finding-KB / AD / dashboard: KB authoring + independent diff review

**Date:** 25OCT2026
**Sprint:** S2 (finding knowledge base, categories, AD view, run health) of
PLAN-001-25OCT2026.
**Base SHA:** `d4a19e1` (S1 merge) **Head reviewed:** `2c1d502`
**Author model:** Opus (integration/judgment). **Reviewer / authoring peer:**
Daybreak Blue (`gpt-daybreak-blue-latest`), Tier-2 cyber — independent of the
author model.

---

## Part A — KB authoring provenance (199 classes)

The KB (`network/finding-kb.json`) was produced by a hybrid strategy, recorded
under `docs/review/s2-kb-authoring/`:

- **34 Active Directory classes** hand-authored inline in `build_kb.py` (the
  attack-path families: relay/coercion, roasting, AD CS, delegation, GPP/LAPS/
  SYSVOL credential exposure, policy/hygiene). Hand-authored AD takes precedence
  over any peer draft (`CLASSES.setdefault`).
- **165 non-AD classes** delegated to Daybreak Blue in 4 batches
  (`batches/B{1-4}.*`), by category band: local (B1), app (B2), network (B3),
  platform (B4). Each batch ran non-interactively via file-handoff
  (`--output-last-message`), monitored on the output file + exit sidecar.
- **Denominator:** the 199 non-low, non-generic-fallback built-in `rule_id`s
  across all four rule lists (`worklist.json`). Generic fallbacks
  (`CRITICAL`/`[!!]`/`EXPOSED`/`UNAUTH`) are excluded by design — a catch-all has
  no single remediation; its findings get a service-default category only.

**Verification of the authored set (all programmatic):** coverage 199/199,
0 missing, 0 schema failures, every class carries ≥1 test and ≥1 fix. Category
spread: ad 34, network 41, linlocal 31, data 27, web 20, winlocal 15, creds 11,
devops 9, infra 6, backup 5. **OPSEC scan (CLAUDE.md §9):** 0 flags — every
`test` command is read-only target confirmation; `fix` commands are remediation
on the owner's own host (may write, e.g. `reg add`) which §9 permits; all
commands are inert templates that never execute.

---

## Part B — Independent diff review (Phase-6 gate)

Bundle handed to the reviewer: the 1011-line code diff (`report.py`,
`report-dashboard.py`, the two test files, `data-sources.json`, CHANGELOG), a
KB schema sample (schema + one class per category), the plan's S2 section, and
the declared out-of-scope list. Raw output: `diffrev/daybreak-review.md`.

**Verdict:** 0 blocker/high. 4 implementation + 3 test-quality findings, resolved
**by class** below. Max 3 patch rounds; resolved in **round 1**.

| Class | Reviewer findings | Disposition | Sweep (match identity) | Resolution |
|---|---|---|---|---|
| **A — malformed-KB / finding robustness** | 1 (loader accepts null category / `test:null` / no title → render-time crash), 2 (AD/Categories renderers deref mandatory `host`/`line`/`severity`) | **ACCEPT** | grep `_load_finding_kb` nested access; every `f["…"]` subscript in `render_ad`/`render_categories` | `_load_finding_kb()` normalizes categories (dict-valued only) and classes (known category, safe-typed `title`/`why`/`test`/`fix`/`refs`); renderers read fields via `.get` with string defaults. New tests `test_malformed_classes_are_normalized_and_do_not_crash`. |
| **B — port type** | 3 (`_dc_hosts` ignores numeric string ports) | **ACCEPT** (defensive; shipped inventory is int, DC rendered correctly pre-fix) | `_dc_hosts` port handling | coerce `int(port)` with try/except; covered by the strengthened DC section assertion. |
| **C — markdown injection** | 4 (prose/title/cmd inserted raw into report.md → forged heading / raw HTML / code-span break) | **ACCEPT** | every interpolation in `_render_top_risks` | added `_md_text` (flatten CR/LF, escape `<`/`>`) + `_md_code` (backtick-safe fence) applied to title/why/label/fix-text/cmd/refs. New test `test_markdown_injection_is_flattened`. |
| **D — denominator not pinned** | 5 (`>=150` lets up to 49 rule_ids vanish) | **ACCEPT** | the anti-vacuous assert in the coverage gate | pinned to exactly `199` with a deliberate-update note. |
| **E — well-formedness check weak** | 6 (`HTMLParser().feed()` is a tolerant tokenizer, not a validator) | **REJECT (rationale)** | the `_assert_wellformed` pattern repo-wide | matches the existing `test_report_dashboard.py` convention; the substantive assertions are the content/section checks, not the parse. A full HTML validator is out of proportion and not in stdlib. Documented as a known-limited smoke check. |
| **F — vacuous DC assertion** | 7 (`assertIn("10.0.0.10", ad)` passes from the finding row even if `_dc_hosts` returns `[]`) | **ACCEPT** | the DC assertion in `test_dashboard_kb.py` | now asserts the host inside the "Domain controllers" section and that the empty-state text is absent — this also exercises the Fix-B port coercion end-to-end. |

**Out-of-scope (declared up front, none invented):** individual remediation-text
accuracy of the 199 classes (separately authored/verified, Part A), generic
tool-hardening checklist items, the 199 denominator value itself, style.

**Reviewer's explicit no-findings (recorded):** cache behavior safe for the
supplied tests (`_fresh_kb` clears both globals); `_service_category` handles the
finalizer's string ports and smb→network without 88/389; `build_run_health` no
double-count; empty/missing KB does not crash; displayed host/line/cmd/category/
run-health values are HTML/attribute-escaped and the clipboard handler never
executes; no OPSEC violation in the sample.

---

## Part C — Gate status

- **Phase-6 diff review:** GREEN (0 blocker/high; all accepted classes fixed in
  round 1, 1 class rejected with rationale).
- **Phase-7:** (a) 0 regressions — all 455 baseline-PASSED still PASSED, 472/5/0
  at head (raw: `docs/test-strategy/raw/s2-head/`); (b) new behavior proven;
  (c) coverage gate shown RED (1 uncovered when a class is removed via
  `ARANUM_FINDING_KB`) → GREEN restored.
- **Phase-8:** M6 0.0% → 88.9%; M6b (any guidance) 0% → 100%; coverage gate
  199/199. See PLAN-001 S2 Phase-8 benefit.
