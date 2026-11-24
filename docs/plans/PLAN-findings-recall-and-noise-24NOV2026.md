# aranum report.py — findings recall, noise & fidelity: next-round plan (24NOV2026)

**Path:** full cycle, lean (target-metric gated). **Deliverable now:** Phases 0–5 (plan).
Execution (6–8) is the next round. Supersedes the sketch `PLAN-structured-findings-promotion-24NOV2026.md`.
**Origin:** PLAN-003 automation assessment (`vuln-research/plan003-goad-workup-24NOV2026/AUTOMATION-ASSESSMENT.md`).
**REVISED after Review round 1** (independent Opus review, 24NOV2026): the baseline was re-measured on
the full finding `line` (not the truncated title), which corrects both numbers and the problem framing —
the gap is **narrower** than first stated. All six review findings are folded in; see **Review round 1**.

## Phase 0 — Frame
- Repo: `aranum` (`/srv/share/dev/aranum`), git, base SHA **550f1cd59544bdfc9b4a8842d97909f5f8a9eed5** (main, = current HEAD, verified).
- Contract (CLAUDE.md): stdlib-only; branches `dev/<topic>`, ff/squash to main when green; author
  `jeremylaratro`; **no Claude/Codex attribution**; enumeration/validated-PoC only. Test gate: `make test`
  (lint+unittest+pytest+smoke+data-audit), i.e. `python3 -m pytest aranumtoolkit/tests/ -q`.
- Target file: `aranumtoolkit/network/report.py` (3338 lines). **No findings.json schema change** (reuse
  `_structured_finding()` → existing fields). Out-of-scope (unchanged): dispatchers, auto-enum.sh,
  multi-domain sweep, share-collection, exploit-chaining (separate efforts); tool-hardening/compliance
  (lab tooling); the deferred cross-family peer review.

## Phase 1 — Objective + gap inventory
**Objective (metrics), corrected baseline measured on the full `line` across enum/enum-north/enum-essos:**
- **Detection-class recall 0.88 → 1.0.** Base 7/8 — adcs, asreproast, coerce, delegation, kerberoast,
  relay, web are ALREADY surfaced (as coarse `[!] CRITICAL:`/`[!] HIGH:` dispatcher-summary findings).
  Only **shadow_creds is fully missing** (the lone 1/8 recall gap).
- **Finding precision 0.80 → 1.0.** Base 10 genuine-noise / 49 total. The genuine noise is **only** the
  delegation `#`-comment echoes (`# filter`, `# requesting`). The `[!] CRITICAL:`/`[!] HIGH:` lines are
  **REAL signals** (truncated title + generic host), **not** noise — the original plan miscounted them
  (Review round 1, F1).

**Acceptance:** (1) every collected AD-signal class present in a tree appears as ≥1 typed finding
(incl. shadow_creds); (2) 0 comment/marker-only findings; **(3) informative titles** — a real
`[!] CRITICAL: …` signal no longer displays as `SMB: [!] CRITICAL` (F1/`_finding_title` truncation);
**(4) correct host attribution** — relay/coerce/kerberoast signals are attributed to the real host/IP, not
the generic `(dispatcher)` scope.

| ID | Type | Point | Evidence (measured on full `line`) | Provenance |
|----|------|-------|------------------------------------|------------|
| NR-1 | bug (precision) | 1 noise | Delegation rule `\bmsDS-AllowedToActOnBehalfOfOtherIdentity` matches the ldapsearch **comment** lines in `ldap/<ip>/delegation_3268.txt` (`# filter: (msDS-Allowed…=*)`, `# requesting: …`), emitting them as findings. 10 across 3 trees. | measured (findings.json) |
| QT-1 | bug (title) | 1 fidelity | Real signals display as `SMB: [!] CRITICAL` / `LDAP: [!] CRITICAL` / `SMB: [!] HIGH` because `_finding_title` (report.py:536) truncates at the first `:`; the full `line` carries the real content (certipy/relay/petitpotam summaries). | measured |
| QT-2 | bug (attribution) | 1 fidelity | relay/coerce/kerberoast summaries are emitted from `<svc>/_dispatcher.log` with host `(dispatcher)` (report.py:2143–2164); `_endpoint_in_text` finds no IP in the line, so they are run-scoped not host-scoped. | measured |
| RC-1 | gap (recall) | 2 missing-class | `smb/_shadow_creds_hint.txt` collected; **no** shadow_creds finding in findings.json on any tree — the only fully-missing class. | measured |
| ST-1 | gap (structure/recall-to-truth) | 2 | ADCS present only as one coarse `[!] CRITICAL: Certipy found AD CS misconfiguration(s)` line; per-CA/per-template ESC detail (`ldap/**/certipy_Certipy.json`: enum=1 CA-vuln, essos=1 CA + 5 template-vulns) is not promoted per-entity. | measured |
| ST-2 | gap | 2 | Relay present only as `[!] CRITICAL: 2 SMB host(s) … NTLM-relay candidates`; the per-host IPs in `smb/_relay_candidates.txt` (.22/.23) are not emitted as per-host attributed findings. | measured |
| ST-3 | gap | 2 | Kerberoast present only as a coarse summary; per-SPN hashes in `**/_kerberoast_hashcat.txt` (`$krb5tgs$`: north/essos) not promoted per-account. | measured |
| ST-4 | gap | 2 | AS-REP present only as a coarse summary; per-user hashes in `**/*asrep*` (`$krb5asrep$`: north) not promoted per-account. | measured |

**Root cause (recorded):** two distinct, narrow faults — (a) a **rule over-match**: the delegation regex
matches ldapsearch filter/requesting comment lines (NR-1); (b) a **fidelity/granularity gap**: the AD
signals ARE promoted, but only as coarse, colon-truncated, run-scoped dispatcher-summary lines, so recall
*to the mind-map class* looks fine while recall *to the underlying entities* (which ESC template, which
relay host, which SPN) and attribution are poor, and shadow_creds falls through entirely. It is **not** a
collection failure and **not** (as first framed) a wholesale dispatcher→report rule-coverage gap.
**Pre-existing:** none introduced by this effort; `report.py` tests pass at base SHA (verify in Phase 5 manifest).

## Phase 2 — Triage
| ID | Relevance | Complexity | Tier | Lane |
|----|-----------|-----------|------|------|
| NR-1 deleg comment-noise | 5 (sole precision defect; false findings erode trust) | 1 (per-line `#` skip) | P0 | now S1 |
| QT-1 title truncation | 5 (real criticals read as `[!] CRITICAL`) | 2 (`_finding_title` edit, global) | P0 | now S1 |
| QT-2 attribution | 4 | 2 (resolved by ST per-host promoters + dedup) | P1 | now S2 |
| RC-1 shadow_creds | 4 (only fully-missing class) | 1 | P1 | now S2 |
| ST-1 ADCS per-template | 5 (top-priority avenue; granularity+truth) | 3 (JSON parse + sev map + cross-source dedup) | P0 | now S2 |
| ST-2 relay per-host | 5 | 1 | P0 | now S2 |
| ST-3 kerberoast per-SPN | 5 | 2 | P0 | now S2 |
| ST-4 asrep per-user | 4 | 2 | P1 | now S2 |

All `now`. ST-1/2/3 are relevance-5 because they are the missed top-priority issue classes at the
entity granularity truth is scored against.

## Phase 3 — Sprint map (each independently testable; **merge together — see Sequencing**)
- **S1 — Noise + title fidelity (NR-1, QT-1).** Branch `dev/findings-noise` from base. Exit: 0 comment-noise
  findings on the 3 trees; real `[!] CRITICAL:`/`[!] HIGH:` signals carry informative titles; delegation
  still produces its real findings; `make test` green. Blast radius: the walker line-scan call sites +
  `_finding_title`. Rollback: revert branch.
- **S2 — Structured per-entity promotion + attribution + shadow_creds (ST-1..4, QT-2, RC-1).** Branch
  `dev/findings-structured-ad` from **S1's integrated tip**. Exit: class-recall 8/8 (incl. shadow_creds),
  per-entity typed findings with real host attribution, coarse summaries subsumed (no double-count), 0
  regressions, `make test` green. Blast radius: new promoter functions + the `walk_findings` wiring +
  cross-source dedup. Rollback: revert branch.

## Phase 4 — Research (cited, on-disk first)
- `_structured_finding(host,port,service,severity,line,evidence_path,service_metadata,protocol,rule_id)`
  (report.py:562) = the canonical finding constructor → reuse so new findings flow through KB-attach/dedup/
  emit unchanged (no schema change). **Verified**: auto-enum trees take report.py:3155
  `finalize_findings(out_dir, walk_findings(out_dir, rules, service_metadata))`; chaining promoter output
  into that iterable (or `yield from` at the tail of `walk_findings`) flows through `_attach_kb`
  (report.py:1897), `logical_id` recompute (1912), exact-identity dedup (1917–1924) and `_dedup_echoes`
  (1935). Wire **only on the auto-enum/`walk_findings` path** — a pure bulk-enum tree never calls it.
- Classification is **strictly per-line** (`for line in text.splitlines(): _classify_line(...)`,
  report.py:2128/2151). There is **no multi-line/block delegation capture** (Review round 1, F3) — NR-1 is
  a per-line comment over-match, fixed with a per-line `#` skip.
- Severity rules: `_DEFAULT_RULES` (report.py:657+), `_AD_DEPTH_RULES` (1309–1366, incl. the ADCS text rule
  `ESC([1-9]|1[0-6])\s*\(Vulnerable\)` at 1313 and the delegation rules at 1333–1334). The auto-enum walker
  is `walk_findings` (report.py:2063–2165): per-host `rglob` scan (emit site ~2132) + top-level `_*` scan
  (emit site ~2155, host `(dispatcher)`). `.json`/`.xml`/`.pem` are skipped by the walker
  (`_SKIP_SCAN_SUFFIXES`, report.py:896) — so a certipy JSON promoter must read the JSON directly.
- Existing harness: `tests/test_structured_findings.py`, `tests/test_findings_fidelity.py`,
  `tests/test_rule_shadowing.py`; fixtures `tests/fixtures/ad-signals/` (certipy-esc1, delegation-uncons,
  laps-readable, gpp-cpassword, bloodhound-zip, pn-exploitable). **Caution (F4):**
  `certipy-esc1/certipy_20260520.txt` contains `(Vulnerable)`, so the text rule already surfaces ADCS from
  it — the JSON-promoter fixture must NOT reuse a `(Vulnerable)` text file (see Phase 5 S2 test plan).
- Reference implementation (proven, stdlib): `vuln-research/plan003-goad-workup-24NOV2026/automation/
  structured_findings.py` — per-entity promoters for all classes; whole-lab 40 findings / 0 noise. Port its
  *promotion* logic, but **not** its coerce severity heuristic verbatim (F5) and **not** its dedup key
  (F4; report.py dedups on evidence_identity/logical_id, not `(category,title,host)`).
- Captured trees are the Phase-7/8 fixtures-of-record (enum/enum-north/enum-essos). Verified artifact
  presence: `_relay_candidates.txt` (2 IPs), `_kerberoast_hashcat.txt` (`$krb5tgs$`, north/essos),
  `*asrep*` (`$krb5asrep$`, north), certipy JSON (CA/template vulns: enum 1, essos 1+5),
  `_shadow_creds_hint.txt`, `_petitpotam_signal.txt` (enum = `NT_STATUS_ACCESS_DENIED`, i.e. NOT vulnerable).

## Phase 5 — Plan (methods, tests, baselines, rollback)

### S1 — Noise + title fidelity (closes NR-1, QT-1)
- **NR-1 — delegation comment over-match.** Fix at the walker **line-scan call sites** (report.py ~2132 and
  ~2155): skip a line before classification/emit when it is comment/marker-only. Introduce
  `_is_noise_line(line)` matching exactly three shapes — `^\s*#`, blank, and a bare
  `^\s*\[!\]\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*$` **with no trailing content**. Apply it **at the call
  sites, NOT inside `_structured_finding`** (Review round 1, F2 — an internal guard would later eat S2's own
  promoter findings whose evidence is a `#`-comment hint file). *Alternative considered:* tighten the
  delegation rule to not match `#` lines — equivalent for NR-1 but narrower; the call-site skip also covers
  any future comment over-match, so prefer it. **Do NOT** add the original plan's "suppress bare `[!]
  CRITICAL/HIGH`" item: those lines carry real content after the colon (F1), so the `…\s*$` anchor is
  correct precisely because it must **not** fire on them.
- **QT-1 — title truncation.** `_finding_title` (report.py:527–539) currently titles on
  `line.split(":",1)[0]`, so `[!] CRITICAL: Certipy found …` → `[!] CRITICAL`. Change: when the colon-head
  is only a dispatcher marker (`[!]`/`[+]`/`[-]`/`[*]`) and/or a bare severity word, title on the
  informative remainder after the first colon (truncated to the existing width); otherwise keep current
  behavior. This is a **global** title change — validate against the base regression manifest that no test
  asserts the old truncated form.
- **Contract:** fewer findings (NR-1) + changed titles (QT-1); schema unchanged. **Failure mode:**
  over-filtering could drop a real one-token finding → mitigated by the three narrow noise shapes and
  asserted in tests; title change could alter an existing asserted title → caught by the manifest.
- **Test plan** (`tests/test_findings_noise.py`): (a) a `delegation_*.txt` fixture with the real
  `# filter:`/`# requesting:` comment lines + a real result line → the real delegation finding is present
  AND the two `#`-comment findings are absent; (b) a `_structured_finding`-level test that `_is_noise_line`
  matches `# x`, ``, `[!] CRITICAL` (bare) and does **not** match `[!] CRITICAL: real content`; (c) QT-1:
  a fixture `[!] CRITICAL: Certipy found AD CS misconfiguration(s)` line → title contains "Certipy", not
  "[!] CRITICAL". **RED proof (non-vacuous):** each of (a)/(c) fails at base SHA (the `#`-comment findings
  are currently emitted; the title is currently truncated) and passes after.
- **Baselines (capture at S1 base SHA, before edit):** regression manifest = `pytest -q` per-test status
  @ 550f1cd5 (raw kept); benefit = precision 0.80 (10 comment-noise / 49) on the 3 trees; harness =
  `report.py` per tree + the Phase-0 metric script. Target precision 1.0 (comment-noise removed).
- **Rollback:** `git revert`/branch delete; no data/contract change.

### S2 — Structured per-entity promotion + attribution + shadow_creds (closes ST-1..4, QT-2, RC-1)
- **Promoters (one per class, each reusing `_structured_finding`, service/severity per class), wired via a
  `_promote_ad_signals(out_dir, service_metadata)` generator `yield from`-ed on the `walk_findings`
  (auto-enum) path so output flows through `finalize_findings`:**
  - **ST-1 ADCS** `from_certipy_json`: read `ldap/**/certipy_Certipy.json` (the walker skips `.json`), emit
    **per CA-vuln and per vulnerable template** (ESC1/2/3/4/6/8/11 → critical, else high). Each finding
    carries the real host (CA DNS name / template host where known).
  - **ST-2 relay** per-host: one HIGH per IP in `smb/_relay_candidates.txt`, **host = that IP** (fixes QT-2).
  - **ST-3 kerberoast** per-SPN: count/emit `$krb5tgs$` from `**/_kerberoast_hashcat.txt`
    (+ `ldap/impacket_spns.txt`, `**/spns_*.txt`), HIGH.
  - **ST-4 asrep**: `$krb5asrep$` from `**/*asrep*` → HIGH (hashes) / INFO (userlist only). Dedup across the
    two asrep files (hashcat + bulk) so the same hash set is not counted twice.
  - **RC-1 shadow_creds**: emit **INFO** from `smb/_shadow_creds_hint.txt`, keyed on real content and framed
    as a viability hint (operator ACL confirmation required) — not a confirmed finding. Closes the 1/8 gap.
  - **coerce (QT-2 class)**: key severity on the **real result** in `smb/_petitpotam_signal.txt` (HIGH only
    on a positive/`vulnerable|pipe|open|success` result; the enum tree's `NT_STATUS_ACCESS_DENIED` → INFO/no
    HIGH). **Do NOT** derive HIGH from the static `_petitpotam_hint.txt` boilerplate (Review round 1, F5 —
    the hint template always contains "pipe", which would manufacture a false HIGH).
- **Cross-source dedup (Review round 1, F4 + QT-2 subsumption):** report.py's exact-identity dedup keys on
  `evidence_identity` (line content), so a text-rule `ESC\d (Vulnerable)` finding and a JSON-promoter ADCS
  finding for the **same** template do NOT dedup. Add explicit cross-source dedup:
  (A) key ADCS at entity granularity on **(host, CA/template, ESC)** so text and JSON sources collapse to one
  typed finding; (B) **class subsumption** — when ≥1 structured per-entity finding exists for a class
  (ADCS/relay/coerce/kerberoast) on a tree, collapse that class's coarse `[!] CRITICAL:`/`[!] HIGH:`
  `(dispatcher)` summary line into it (retain the summary's path as secondary `evidence_paths`, do not emit
  it as a separate finding). (B) also delivers acceptance criterion (4): the surviving typed findings carry
  the real host. *Option not taken:* rely on `logical_id` alone — rejected, it cannot dedup across sources
  (the very F4 double-count).
- **Contract:** findings.json gains per-entity rows and loses coarse duplicates; same schema. **Failure
  mode:** a malformed/empty artifact must not crash the report → each promoter `try/except`s to `[]`,
  asserted; a promoter emitting a `#`/empty `line` would be silently dropped by S1's call-site guard →
  each promoter MUST pass a non-comment, non-empty `line` (asserted).
- **Test plan:** extend `tests/fixtures/ad-signals/` — a **new** certipy-esc-json fixture whose certipy
  `.txt` has **no** `(Vulnerable)` (mirroring the real GOAD trees) plus a `certipy_Certipy.json`, so the
  ADCS "absent at base SHA" RED proof is genuine (F4 — reusing `certipy-esc1`'s `(Vulnerable)` txt would make
  it vacuous); relay-candidates, kerberoast-hash, asrep, petitpotam-signal (negative + positive),
  shadow-creds fixtures. Extend `test_structured_findings.py`: each promoter emits exactly its expected
  typed finding(s) with the right service+severity+host; a malformed/empty artifact emits 0 and does not
  raise; coerce emits INFO (not HIGH) on the ACCESS_DENIED signal; a tree with both the text `(Vulnerable)`
  rule and the JSON promoter yields **one** ADCS finding per (host, template, ESC) — asserts no double-count.
  **RED proof (non-vacuous, per promoter):** the typed finding (and, for ADCS, the per-template entity) is
  **absent at base SHA** and present after.
- **Baselines (capture at S2 base SHA = S1 integrated tip, immediately before S2 Phase 6 — DEFERRED per
  Rule 3):** regression manifest `pytest -q` @ S1-tip; benefit = class-recall (7/8 at base; shadow_creds
  missing) + per-entity recall-to-truth on the 3 trees. Target recall 8/8 + attribution/title criteria.
- **Rollback:** branch revert; promoters are additive; subsumption is pure dedup.

### Sequencing (Review round 1, F6)
Prefer **S2-first or S1+S2 merged together**; do not ship S1 alone to main. With the corrected framing S1
no longer *drops* the real ADCS/relay/coerce signals (it only skips `#`-comment noise and fixes titles), so
S1-alone is non-regressing on recall — but the QT-1 global title change and the class-subsumption dedup are
coherent only once S2's typed findings exist, so landing them together avoids a transient state where coarse
`(dispatcher)`-attributed summaries are the sole representation. Each sprint stays independently testable.

### Peer-review gate (Phase 5)
Status: **satisfied for the plan** by an independent Opus review (Review round 1, below) whose six findings
are folded in. Cross-family peer (Sol `gpt-5.6-sol` / Daybreak Blue) remained usage-capped until 25NOV; the
**Phase-6 diff review is mandatory** and is the independent gate on the implementation (re-run the
cross-family peer 25NOV+ on the diff). Not a silent skip.

## Review round 1 — independent findings + resolutions (24NOV2026)
| # | Sev | Location | Problem | Resolution in this revision |
|---|-----|----------|---------|------------------------------|
| F1 | BLOCKER | Phase-1 NR-2 / S1 guard | The `[!] CRITICAL:`/`[!] HIGH:` "bare markers" are content-bearing REAL signals (title only looks bare via `_finding_title` colon-truncation); the anchored guard can't match them, so the old precision target was unreachable and the baseline miscounted. | Baseline re-measured on full `line` → precision 0.80 (10 comment-noise/49), recall 7/8. `[!] …:` lines reclassified as real signals (QT-1 title + QT-2 attribution), NOT noise. NR-2 "suppress bare markers" item **dropped**. |
| F2 | BLOCKER | S1 decision | A `_is_noise_line` guard inside `_structured_finding`/emit would later suppress S2's own promoter findings whose evidence is a `#`-comment hint file. | Guard placed **at the walker line-scan call sites**, not inside `_structured_finding`; each S2 promoter must pass a non-comment, non-empty `line` (asserted). |
| F3 | HIGH | Phase-1 NR-1 / S1 (i) | No "delegation multi-line capture" exists; classification is strictly per-line; NR-1 is the delegation regex matching ldapsearch `#` comment lines. | "bound the block" item removed; NR-1 fixed by a per-line `^\s*#` skip (or a tightened delegation rule). |
| F4 | HIGH | S2 ADCS / dedup / test | Text rule `ESC\d (Vulnerable)` vs JSON promoter don't dedup (different evidence_identity) → double-count; reusing the `(Vulnerable)` fixture makes the absent-at-base RED proof vacuous. | Added cross-source dedup keyed on (host, CA/template, ESC) + class subsumption; ADCS JSON fixture built from a certipy `.txt` with **no** `(Vulnerable)`; test asserts one finding per (host,template,ESC). |
| F5 | HIGH | S2 coerce | Reference keys coerce HIGH on `_petitpotam_hint.txt` boilerplate ("pipe"), firing even when the probe failed (`ACCESS_DENIED`). | Coerce severity keyed on the real `_petitpotam_signal.txt` result; hint template is non-finding. Test asserts INFO (not HIGH) on the ACCESS_DENIED signal. |
| F6 | HIGH | Phase-3 / S2 baseline | Original S1 stripped the only ADCS/relay/coerce mention until S2; "recall unchanged at S1-tip" held only for the class metric. | Corrected S1 no longer drops real signals; Sequencing section recommends S2-first/merge-together and notes QT-1 + subsumption cohere only with S2. |

**Also affirmed by the review (no change needed):** the `_structured_finding` → `finalize_findings`
integration point is correct on the auto-enum path; base SHA 550f1cd5 is accurate; CB/ST recall is reachable
on the 3 trees given the verified artifacts; "full cycle, lean" sizing is appropriate.

## Benefit (Phase 8, pre-registered)
| metric | baseline @550f1cd5 | target | harness |
|---|---|---|---|
| detection-class recall (3 trees) | 7/8 = 0.88 (shadow_creds missing) | 8/8 = 1.0 | native report.py per tree + Phase-0 metric script |
| per-entity recall-to-truth (3 trees) | coarse-only (1 summary/class) | per ESC-template / relay-host / SPN / asrep-user | same |
| finding precision (3 trees) | 0.80 (10 comment-noise / 49) | 1.0 (0 comment-noise, no double-count) | same |
| title fidelity | real signals shown as `SVC: [!] CRITICAL` | informative titles | title assertion in tests |
| host attribution | relay/coerce/kerberoast = `(dispatcher)` | real host/IP | attribution assertion in tests |
Combined effort number re-measured after S1+S2 integrate.

## Phase 8 — OUTCOME (measured on final commit, 3 GOAD trees)
| metric | baseline @550f1cd5 | after S1+S2 | provenance |
|---|---|---|---|
| detection-class recall | 7/8 = 0.88 | **8/8 = 1.00** (shadow_creds added) | measured |
| finding precision (noise-free) | 0.80 (13 comment-noise) | **1.00 (0 noise)** | measured |
| per-entity findings | coarse summaries | 69 typed (per-ESC-template/relay-host/SPN) | measured |
| coarse-CRITICAL preserved (F3) | n/a | relay 3, kerberoast 2, asrep 1 (lossless) | measured |
| coerce-chain HIGH retained (F2) | dropped | 3 | measured |
| regression suite | 647 passed | 672 passed / 5 skipped / 0 fail (+25 tests) | measured |
Review: Phase-6 independent Opus, 2 rounds — 3 HIGH (coerce grading inverted, coerce-subsumption drop, kerberoast/asrep severity asymmetry) found→fixed→re-verified. Cross-family codex re-review OWED (capped until 25NOV). Commits: S1 8cca59a, S2 aa1d729, fix dc5db09.
