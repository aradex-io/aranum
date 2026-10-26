# TEST CARD — S1 findings fidelity

- **Date:** 25 OCT 2026
- **Sprint:** S1 (`dev/findings-fidelity`)
- **Base SHA (Phase-5 baseline):** `69fec13`
- **Head (worktree) over committed tip:** `575b525` + the Phase-6 review-response batch
- **Suite command:** `python3 -m pytest aranumtoolkit/tests -v -rA` (superset: pytest collects the unittest.TestCase classes too)
- **Raw output:** `docs/test-strategy/raw/baseline-69fec13/pytest.log` (baseline), `docs/test-strategy/raw/head-worktree-575b525/pytest.log` (head)

## (a) No regression — per-test manifest diff

| | Baseline `69fec13` | Head |
|---|---|---|
| passed | 413 nodeids (415 incl. subtest spellings) | 453 nodeids (455 incl. subtests) |
| failed | 1 (`test_apt_no_writable_surface_emits_only_clean_conclusion` — the PRE1 target) | 0 |
| skipped | 5 | 5 (identical signatures) |

- **Baseline-passing tests not passing at head:** NONE (`comm -23 base_pass head_pass` empty).
- The single baseline **failure** is the PRE1 item (apt clean-surface fixture, umask-sensitive); it is **green at head** — an accounted fix, not a regression masked by a new pass.
- **Skip signatures identical** (pywinrm, recce, and the other 3) — nothing was silently skipped away.
- Read from raw pytest output directly; delegate counts were never relayed.

## (b) New behavior proven (specific assertions, real inputs)

- **FP guard (G01/G02):** `emission_audit.py` M1 `neg_graded` 18 → **0**, M2 `crit_ungraded` 1 → **0**. `test_findings_fidelity` drives the real corpus and asserts every raw miss/log FP is suppressed while the `miss_ok` disabled-privilege TP survives.
- **Rule fidelity (G03):** M3 `tp_recall` 3 → **25/25**, M3b `tp_sev_exact` 0 → **25/25**. `test_rule_shadowing` pins exact severity + specific rule for 33 samples.
- **Attribution (G04/G05):** `test_endpoint_attribution` — bare `https://` → :443, ambiguous port → host scope, two hosts → run-scoped `(dispatcher)`, and (ROUND2 #5) tcp/udp same port keeps the port.
- **Dedup (G06):** `test_echo_dedup` — identical echo collapses; different port/secret/host stays two; multi-share and (ROUND2 #2) multi-WORD enumerations never collapse.
- **Round-2 fixes:** `TestFloorRuleId` (URL path kept / same fact collapses), `test_custom_rule_cannot_downgrade_a_marked_critical` (R2-9), `test_custom_rule_id_is_stable_across_line_moves` (#6).

## (c) New GATES shown able to go RED

Two new acceptance gates (both in `test_rule_shadowing.py`); ordinary unit tests above are NOT gates.

1. **`TestNoGenericShadowsSpecificAcrossCorpus`** — no generic fallback may win first-match over a specific rule on the whole real emission corpus (anti-vacuous floor ≥3 overlapping lines).
   - **RED proof:** generics composed FIRST → **85** offenders; shipped order (generics last) → **0**. Recorded.
2. **`TestExpectedRuleAndSeverity` per-sample provenance backstop** — every sampled TP must be graded by a SPECIFIC rule, asserted by pattern provenance `_derive_rule_id(g.pattern) ∉ _GENERIC_FALLBACK_IDS` (not a substring/`rule_id` check, which passes vacuously — ROUND2 #5).
   - **RED proof:** delete the kerberoast specific rule → the critical floor synthesises `crit-critical-…-kerberoastable-hash-…` (passes the OLD substring + `rule_id ∉ gen` checks) but the provenance check FIRES because the matched pattern is the generic `\bCRITICAL\b`; shipped order does not fire. Removal falsifier now works. Recorded.
   - Non-vacuity also pinned: `test_expectation_table_is_not_vacuous` (floor ≥25 unique samples), `test_corpus_is_large` (≥500), `test_raw_corpus_actually_contains_false_positives` (≥15).

`inconclusive` state: the audit harness reports absence of the corpus (extractor regressed) as a loud failure, never a silent pass.
