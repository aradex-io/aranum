# REVIEW-008 — S1 "findings fidelity" Phase-6 fix: independent peer review (round 1)

- **Date:** 25 OCT 2026
- **Sprint:** S1 (findings fidelity) — `dev/findings-fidelity`
- **Methodology:** dev-methodology Phase 6, independent diff-review gate (full cycle)
- **Reviewer:** Daybreak Blue (`gpt-daybreak-blue-latest`), Tier-2 CYBER, independent of the author model (Opus). Non-interactive file-handoff; prompt `/tmp/codex-out/s1-review-prompt.txt`, answer `/tmp/codex-out/s1-review.md` (exit 0), code diff `/tmp/codex-out/s1-code.diff`.
- **Range reviewed (round 1):** base `69fec13` .. head `575b525` (the committed D1.6 tip). The author's FIX-1/2/5/6 + gate-lock were applied in the working tree *in response to* this review and are the subject of round 2.
- **Verdict (round 1):** 4 HIGH, 4 MEDIUM, 0 blocker-by-scope. No style rejections. All 8 are real; disposition below.

Out-of-scope classes were declared in the prompt (tool self-hardening, write-to-target/persistence/cred-use/evasion per §9, probe redesign, deliberate constants). The reviewer raised nothing in those classes.

---

## Findings, dispositions, and by-class sweeps

Resolution key: **FIX** (addressed this sprint), **DEFER→S2** (new Phase-1 item, dashboard presentation layer), **NARROW** (claim tightened with evidence).

### #1 HIGH — Specific classifier rules shadowed by generic rules — **FIX (structural)**
`report.py` first-match ordering let generic `EXPOSED`/`UNAUTH`/`CRITICAL` outrank specific product rules (Spark/Solr/SSDP graded high over their medium rules; GitLab/Jenkins got the generic id).

**Fix:** the four generics were extracted out of the inline rule lists into `_GENERIC_FALLBACK_RULES` and are appended **last** at every assembly site through an idempotent `_compose_rules(*lists)` (de-dups any generic id present, appends one trailing copy). Sites: `_load_rules` return, bulk linux/win, `main`, and `report-dashboard.py`. `_classify_line` enforces a critical **severity floor** and swaps in a line-derived `_floor_rule_id` when a generic fallback wins, so distinct criticals keep distinct KB keys. This is a *structural guarantee* (generics cannot precede a specific rule by construction), not an ordering patch.

**Sweep (match identity = "a generic fallback id wins first-match over a specific rule, across the whole real emission corpus"):** shipped order → **0** offenders; the same gate with generics forced first → **85** offenders. RED→GREEN recorded. New gate `TestNoGenericShadowsSpecificAcrossCorpus` (anti-vacuous floor ≥3 overlapping lines).

### #2 HIGH — Echo dedup drops distinct multi-entity findings — **FIX + NARROW (sweep-backed)**
Only `$`-suffixed shares were protected; a multi-value summary (`… — Finance, Payroll`) could Jaccard-merge with a single-value per-host line and silently drop the rest.

**Fix (FIX-2):** `_protected_tokens()` now emits an `enum:<item>` token for every element of a comma-enumerated list, so a multi-value summary carries tokens the single-value per-host line lacks and the two no longer merge.

**Sweep (match identity = "dispatcher `hit`/`echo` lines that collapse ≥2 distinct entities into one comma/`;`/` and `-joined summary"):** the only real comma-enumerated summaries in the corpus are `ports=` lists (`enum-bambu.sh:29` `ports=5060,8080`), which FIX-2 protects (proven by `test_echo_dedup.test_multi_share_not_collapsed_into_single`). The reviewer's `UNAUTH SMB shares … — Finance, Payroll` is **not a present emission** — `enum-smb.sh` surfaces shares via raw `nxc --shares` output, not a single collapsed summary line. **NARROW:** the broad residual (entities joined by an unrecognized separator, or distinguishing data beyond the 300-char truncation) has no current emission exhibiting it; logged as S2 item **GAP-S2-DEDUP** (structured-entity dedup: merge list-valued evidence only when the complete entity set matches). Not a blocker: no current emission can trigger the loss.

### #3 HIGH — Dashboard ignores the collector's authoritative port, double-counts — **DEFER→S2 (GAP-S2-PORT)**
`report-dashboard.py` re-derives a finding's port from text (`find_best_port`) instead of the collector's `f["port"]`, so a terse line with structured `port=8080` can be attached to every candidate port (false attribution to :80; dashboard shows 2 where `findings.json` has 1).

**Disposition:** real, but it lives in the dashboard **presentation** layer, not the S1 fidelity backbone (classifier + collector + `findings.json`). S1's acceptance criteria scope the collector and `findings.json`; the dashboard's port/host rendering is explicitly an S2 deliverable (dashboard overhaul). Logged as Phase-1 item **GAP-S2-PORT**: "dashboard must consume collector `host/port/protocol/scope` first; infer from text only for genuinely portless legacy findings; host-scoped findings stay host-scoped."

### #4 HIGH — Dashboard rebuilds topology from opaque directory names — **DEFER→S2 (GAP-S2-TOPO)**
For queue runs (`service/task-<hash>/`, real endpoint in `_task-context.json`) and bulk (`pair-<hash>/`, `_meta.json`) the dashboard records the hash dir as a host → phantom host page + detached real-host page. `collect()` already reports the real host; the dashboard bypasses it.

**Disposition:** same layer and scope as #3. Logged as **GAP-S2-TOPO**: "make canonical endpoint/topology part of the shared `Collection`, or reuse `_inventory_endpoints()`/`_bulk_identity()`; never infer a host from a storage directory name." **This directly narrows the D1.6 claim — see below.**

### #5 MEDIUM — Protocol ambiguity erases an otherwise-known port — **FIX**
Inventory records `…:5060/tcp/sip` and `…:5060/udp/sip` made `_endpoint_in_text()` fall back to `{host, port:"", protocol:""}`, losing the port; `finalize_findings()` could then overwrite a valid per-host port with the empty value.

**Fix (FIX-5a/5b):** `_endpoint_in_text` resolves hierarchically — if the matched records share a single `(host,port)` it returns that port with empty protocol (only genuinely distinct ports fall back to host scope). The attribution merge was changed from `finding.update(endpoint)` to a guarded merge that **never replaces an existing non-empty coordinate with an empty inferred one**.

**Sweep (match identity = "sites that overwrite finding endpoint coordinates"):** two sites — `_endpoint_in_text` fallback and the `finalize_findings` attribution merge — both guarded. No other call-site writes `host/port/protocol` onto a finding.

### #6 MEDIUM — Custom rule IDs neither stable nor content-derived — **FIX**
Custom rules got `custom:<line-number>` (comment insertion changes the id; `custom:1` collides across files).

**Fix (FIX-6):** custom rules now build `cre = re.compile(pattern, re.I)` and take id `"custom-" + _derive_rule_id(cre)` — the same content+flags hash as built-ins, namespaced `custom-`. Stable across line moves; distinct per pattern.

**Sweep (match identity = "every construction site of a `Rule` id"):** built-ins via `_derive_rule_id`, generics via `_build_rules`, custom via `custom-`+`_derive_rule_id`, criticals via `_floor_rule_id`. No remaining line-number-derived id.

### #7 MEDIUM — Shadow-audit substring check / vacuous pass — **FIX (gate-lock)**
Substring-in-`rule_id` could pass for a wrong rule whose slug contains the substring; the table didn't pin a unique-sample count (empty JSON would pass vacuously); `_emission_for` checked only the first corpus match.

**Fix:**
- **#7a (substring bypass):** `test_each_sample_matches_expectation` now also asserts `g.rule_id not in _GENERIC_FALLBACK_RULE_IDS` for every sample — an exact-identity backstop: no sampled TP may be served by a generic fallback. RED proof: generics-first → 8 samples served by the generic `EXPOSED` id; shipped → 0.
- **#7b (vacuity):** new `test_expectation_table_is_not_vacuous` pins a floor (≥25, the tp_labels) and total sample uniqueness. `test_findings_fidelity` independently pins corpus size ≥500 and raw false-positives ≥15.
- **#7c (first-match only):** addressed at the class level by `TestNoGenericShadowsSpecificAcrossCorpus`, which iterates **every** corpus hit (not the first) and rejects any generic winning first-match. The expectation table was expanded 25→33 (added Spark/Solr/SSDP/GitLab/Hadoop + kerberoast/AS-REP/lsarpc criticals).

### #8 MEDIUM — Equivalent IPv6 spellings not attributable — **DEFER→backlog (GAP-S2-IPV6)**
`2001:db8::53` does not match the expanded `2001:0db8:0:0:0:0:0:53`; the matcher uses `ipaddress` only to pick a regex family, then compares the original textual spelling, so the finding stays `(dispatcher)`-scoped.

**Disposition:** real but narrow (no IPv6 target appears in the current fixture/corpus; `measured` absence). Deferred as **GAP-S2-IPV6**: "extract address tokens and compare canonical `ipaddress.ip_address()` values; handle brackets and zone ids separately." Low relevance to the stated FP/AD/local objective; backlogged with its scores for S2 triage.

---

## Narrowing the D1.6 "cannot diverge" claim (required by #3/#4)

**Original claim (plan + prior review):** "a single shared `collect() -> Collection` that BOTH `report.main` and `report-dashboard.build_index` consume, so `findings.json` and the dashboard cannot diverge."

**Corrected claim (errata):** `collect()` is the single authoritative source for the finding **set** and each finding's structured `host/port/protocol/scope`; `findings.json` and the dashboard consume the same collected findings and therefore **agree on which findings exist and their collector-assigned coordinates**. They can still **diverge in the dashboard's presentation layer**, which currently re-derives a finding's port from text (#3) and re-derives host topology from storage directory names (#4) instead of using the collected coordinates. D1.6 removed the *data-source* divergence; it did **not** remove the dashboard's independent *topology inference*. Closing #3/#4 in S2 (GAP-S2-PORT, GAP-S2-TOPO) makes the stronger "cannot diverge" claim true. This errata is mirrored into PLAN-001 §D1.6 and the Phase-8 benefit section.

---

## New Phase-1 items opened for S2 (dashboard sprint)

| ID | Type | From | Evidence |
|----|------|------|----------|
| GAP-S2-PORT | Bug (mis-attribution) | #3 | `report-dashboard.py` `find_best_port` ignores `f["port"]`; terse line → attached to all candidate ports |
| GAP-S2-TOPO | Bug (mis-attribution) | #4 | `report-dashboard.py:~429` records `task-<hash>`/`pair-<hash>` dir as host; real host in `_task-context.json`/`_meta.json` |
| GAP-S2-DEDUP | Gap (robustness) | #2 | structured-entity dedup; no present emission triggers loss, but the fuzzy path is unsafe for future multi-value summaries |
| GAP-S2-IPV6 | Bug (normalization) | #8 | canonical `ipaddress` comparison; no IPv6 in current corpus (measured absence) |

Round-2 review (of the FIX-1/2/5/6 + gate-lock working-tree diff, independent) is recorded separately once complete.

---

## Round 2 — independent review of the fix diff (25 OCT 2026)

- **Reviewer:** Daybreak Blue (`gpt-daybreak-blue-latest`), independent of author. Non-interactive file-handoff: prompt `/tmp/codex-out/s1-fix-r2-prompt.txt`, diff `/tmp/codex-out/s1-fix-r2.diff` (round-1 head `575b525` .. working tree), answer `/tmp/codex-out/s1-fix-r2.md` (exit 0).
- **Range:** the FIX-1/2/5/6 + gate-lock changes that respond to round 1.
- **Result:** #5 and #6 confirmed **CLOSED**; the #3/#4/#8 S2 deferral judged **DEFENSIBLE** (no S1 `findings.json` data-integrity impact); **4 items required further work** — all fixed in this same sprint (round-2 patching, within the 3-round limit).

| ID | Sev | Class | Round-2 verdict | Resolution |
|----|-----|-------|-----------------|------------|
| R2-1 | HIGH | `_floor_rule_id` URL path loss | #1 PARTIAL | **FIX** — strip URL scheme+authority only (`https?://[^/\s]+`), keep path/query; `/admin` and `/debug` now get distinct KB keys, same fact across hosts still collapses |
| R2-2 | HIGH | comma-enum false merge | #2 PARTIAL | **FIX** — run-aware `_ENUM_RUN_RE`: elements may contain internal spaces; add a whole-run `enumrun:` token. `Finance Team, HR Team` ≠ `Legal Team, HR Team` |
| R2-5 | MED | shadow gate still vacuous | #7 NOT-CLOSED | **FIX** — per-sample gate now checks PROVENANCE `_derive_rule_id(g.pattern) not in GEN_IDS`; removing a specific rule (floor synthesises a `crit-*` id containing the substring) now flips RED instead of passing |
| R2-9 | MED | custom rule bypasses critical floor | NEW | **FIX** — `_classify_line` restructured: `miss_ok` bypasses marker SUPPRESSION only; a `[!!]`/CRITICAL mark still floors severity via shared `_apply_critical_floor()`. `[!!] ACME` with a custom `low` rule now grades critical |
| R2-3/6 | HIGH | #3 dashboard port | S2 DEFERRAL DEFENSIBLE | GAP-S2-PORT (unchanged) |
| R2-4/7 | HIGH | #4 dashboard topology | S2 DEFERRAL DEFENSIBLE | GAP-S2-TOPO (unchanged) |
| R2-8 | MED | #8 IPv6 | S2 DEFERRAL DEFENSIBLE | GAP-S2-IPV6 (unchanged) |

**Round-2 fix evidence (recorded):**
- R2-1: `/admin@.1 → crit-critical-endpoint-exposed-admin-621c0b85`, `/debug@.2 → …-debug-e7f6f68d` (distinct); `/admin@.9 → …-admin-621c0b85` (collapses). Test `TestFloorRuleId`.
- R2-2: summary `{enum:finance team, enum:hr team, enumrun:finance team, hr team}` ≠ per-host `{enum:legal team, enum:hr team, enumrun:legal team, hr team}` → not merged. Test `test_multi_word_enum_elements_not_collapsed`.
- R2-5 RED proof: with the kerberoast specific rule deleted, the OLD rule_id+substring check PASSES vacuously but the NEW provenance check FIRES (matched pattern is the generic `\bCRITICAL\b`); shipped order does not fire. The removal falsifier now works.
- R2-9: `[!!] ACME-WIDGET` + custom `low` → `severity=critical, miss_ok=True, id=custom-acme-widget-…`; `[-] ACME-WIDGET present` stays `low`. Tests `test_custom_rule_cannot_downgrade_a_marked_critical`, and `TestOperatorCustomRulesNeverSuppressed` still green.

Reviewer-suggested regression tests for the already-CLOSED items were added: `test_protocol_only_ambiguity_keeps_the_port` (#5 tcp/udp same port), `test_custom_rule_id_is_stable_across_line_moves` (#6 reorder stability).

**Round 3 (verification):** the round-2 fixes are gate-proven and the full suite is re-run clean; no round-2 finding recurs and no new class was introduced by the round-2 patches (verified by re-reading `_classify_line`, `_apply_critical_floor`, `_ENUM_RUN_RE`, and the floor-id strip). The review loop closes at round 2 with 0 unresolved in-scope findings; the 3-round ceiling was not reached.
