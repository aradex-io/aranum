# PLAN-001 — 25OCT2026 — findings fidelity, AD analysis, `--local` posture enumeration, posture dashboard

Gap analysis and triage: `docs/research/GAP-ANALYSIS-25OCT2026-fp-ad-local-posture.md` (IDs G01–G23, PRE1–3, B1).
Base: `main` @ `69fec13` (v0.34.0). Path: full cycle. Target release: **v0.35.0** (MINOR: new subcommand, flags, transports and collectors; findings-schema changes are additive only).

Peer review: round 1 verdict **REVISE** (`docs/review/REVIEW-005-25OCT2026-plan-peer-round1-daybreak.md`, codex Daybreak Blue). This revision answers every finding by class; see **Peer-review resolution record** at the end.

## Constraints (settled, not re-litigated)

- **§9 OPSEC invariants hold for every sprint:**
  - No target write without an explicit flag.
  - No exfiltration or third-party phone-home. **No tool in this effort stands up a listener, fetch-server, or upload endpoint, and no target-side code fetches a body from, or posts a result to, the operator.** Every byte of output returns through the same authenticated transport the operator already chose.
  - Outputs only under the operator-passed path.
  - No persistence.
  - No AMSI/ETW/EDR evasion, and no obfuscated or packed stagers.
  - Credentials are only those the operator supplies. Credentials discovered during a run are reported as *access candidates*, never auto-used.
- **Code style:**
  - Python 3.9+ stdlib-only in core.
  - Optional tools (nxc, impacket, pywinrm, vncdotool, sshpass) degrade with a clear `[!] <tool> not installed` and a non-zero per-host status. They never silently no-op.
  - PowerShell must run on Windows PowerShell 5.1: ASCII-only, `[CmdletBinding()]`, no inline `if` as a hashtable value, no `$IsWindows`, and no assignment to automatic variables.
- **findings.json stays schema `"2"`.** Every new key is additive. `finding_id` derivation is unchanged: `service|host|port|protocol|severity|sha256(clean line)`. Ids change only where attribution fixes a wrong host or port, and the CHANGELOG notes it under "Changed".
- **The user chose the transports:**
  - Windows: ssh, winrm, rdp, vnc, and an operator choice of wmiexec, smbexec or psexec.
  - Linux: ssh, rdp, vnc.
  - The flag is `--local`.
  - Capability is **tiered and stated honestly** (see M8): full-enumeration pathways (local, ssh, winrm) carry the whole collector; the exec-method and desktop pathways are compact-probe / assisted and say so in `--help` and the ADR. The user gets every transport; the tool never over-claims what a thin channel can carry.
- **Out-of-scope classes:** see the gap analysis. Repeat them in every peer prompt.

## Sprint map

| Sprint | Band | Items | Branch | Ships |
|--------|------|-------|--------|-------|
| S1 | P0 | G01–G09, PRE1 | `dev/findings-fidelity` | Marker/rule-aware guard, rule IDs + rule-order fix + shadow audit, endpoint attribution, token-safe echo dedup, new rules, structured shared collector |
| S2 | P1 | G10, G12–G15 | `dev/finding-kb-ad-view` | Finding KB keyed by rule id (category, how-to-test, how-to-fix), categories, AD page (uncorrelated signals), run-health panel, report.md/html remediation |
| S3 | P1 | G16, G21–G23 | `dev/host-posture` | `host-posture.sh` + `Invoke-HostPosture.ps1` (incl. consent-gated AD domain checks), strict POSTURE parser, posture.json with domain rollups, Posture page + host posture card |
| S4 | P1/P2 | G17, G18, G20 | `dev/local-access` | `local-enum.py` orchestrator, `aranum run --local` / `aranum local`, local + ssh + winrm full pathways and operator-chosen compact Windows exec probe, explicit mixed-tree collector |
| S5 | P2 | G19 | `dev/desktop-transports` | rdp (nxc `-x`, native output capture) and vnc (assisted-default) pathways, `--desktop-ok` gate |

Each sprint branches from the integrated tip of the previous sprint: S2's KB attaches to S1's cleaned findings, S3 extends S2's KB, and so on. Each sprint captures its own baseline pair at its real base SHA, so Rule 3 is deferred for S2–S5. Each sprint gets its own PR, merged by squash when green.

## Benefit metrics (pre-registered 25OCT2026, before any edit)

Harness: `docs/test-strategy/harness/emission_audit.py <repo>` and `tp_labels.json`. Plus the fixture run:

```
cp -r aranumtoolkit/docs/examples/dashboard/fixture $T && python3 aranumtoolkit/network/report.py $T --findings-only
```

| Metric | Baseline @69fec13 | Target | Sprint |
|---|---|---|---|
| M1 `neg_graded` (miss/log emissions graded) | 18 | 0 | S1 |
| M2 `crit_ungraded` | 1 | 0 | S1 |
| M3 `tp_recall` / 25 | 3 | >= 23 | S1 |
| M3b `tp_sev_exact` / 25 | 0 | >= 20 | S1 |
| M4 fixture `(dispatcher)` findings | 4 / 11 | 0 | S1 |
| M5 fixture duplicate findings (same fact twice) | 4 | 0 | S1 |
| M6 graded findings with a KB test + remediation block (fixture after S1) | 0 % | 100 % of non-low | S2 |
| M7 posture checks per OS with KB test + remediation | Linux 0 / Windows 0 | >= 30 / >= 35 | S3 |
| M8 access pathways runnable via `aranum run --local`, **by capability tier** | 0 | full-enum: local + Linux ssh + Windows winrm/ssh (4); compact-probe: wmiexec/smbexec/psexec (operator choice); assisted/native-capture: rdp + vnc | S4/S5 |

Rows M6–M8 measure capability rather than noise. Their baselines are measured by grep (gap analysis G12, G17, G19). M8 counts pathways **within the tier each can honestly deliver** — it is not a flat total, so a thin channel never inflates the number.

## Regression baseline (S1; S2–S5 capture their own at their base SHA)

Raw output: `docs/test-strategy/raw/baseline-69fec13/`. Manifest: `manifest.json`, with 1138 per-test identities built by `docs/test-strategy/raw/manifest.py`. Commands:

```
python3 -m unittest discover -s aranumtoolkit/tests -v      > unittest.log   # 331 ok, 4 skipped
python3 -m pytest aranumtoolkit/tests -v -rA                > pytest.log     # 413 PASSED (ids), 5 SKIPPED, 1 FAILED (PRE1)
bash aranumtoolkit/tests/smoke.sh                           > smoke-tagsfetched.log  # 384 PASS, 0 FAIL, 1 SKIP
git ls-files '*.sh' | xargs shellcheck -S warning -e SC1091 -e SC2046 -f gcc   # clean
python3 aranumtoolkit/tests/data_audit.py                                       # rc=0
```

---

## S1 — Findings fidelity (G01–G09, PRE1)

**Problem.** The classifier grades negative and progress lines. Rule order misgrades criticals. `(dispatcher)` lines fail endpoint attribution. Dispatcher echoes duplicate per-host evidence. About 22 true emissions are ungraded. All of these are in `aranumtoolkit/network/report.py`. The dashboard re-implements collection and diverges.

### D1.0 Rule identity (backbone for D1.2 and S2)

The built-in rule lists (`_DEFAULT_RULES`, `_BULK_RULES`, `_BULK_RULES_WIN`, `_AD_DEPTH_RULES`) change from `(pattern, severity)` 2-tuples to a `Rule(pattern, severity, rule_id, miss_ok=False)` `namedtuple`. `rule_id` is a stable kebab string, e.g. `http.tomcat-manager-unauth`. `_classify` returns the **matched `Rule`** (or `None`), not just a severity; callers that want the severity read `.severity`. Operator `--severity-rules` entries become `Rule(pattern, severity, f"custom:{n}", miss_ok=True)` so custom rules keep their current `(regex, severity)` *file* contract and are never suppressed by the guard. The finding dict gains additive `rule_id`.

**Explicit consumer migration (reviewer round-2 NEW-ISSUE).** A 4-field namedtuple does **not** satisfy the existing 2-value unpacking `for pat, sev in rules`; those sites would raise. Every in-repo consumer is migrated in the same commit, enumerated here so the change is bounded and testable (grep ground truth @69fec13):
- `_prefilter_for` (`report.py:470` key build, `:474` loop) → iterate `for rule in rules:` and read `rule.pattern`/`rule.severity`; the prefilter cache key becomes `(rule.pattern.pattern, rule.pattern.flags, rule.severity)`.
- `_classify` (`report.py:501` loop) → `for rule in rules:`; on match return the `Rule`.
- `_load_rules` (`report.py:507`, append at `:520`) → build `Rule(re.compile(obj["pattern"], re.I), sev, f"custom:{n}", True)`.
- **Test code is in scope too (reviewer round-3).** `aranumtoolkit/tests/test_structured_findings.py:109` has a `_brute` reference loop `for pat, sev in rules:` that also unpacks a 2-tuple; it is migrated to `rule.pattern`/`rule.severity`. The sweep is `grep -rnE "for .*, *[a-z_]+ in .*(RULES|rules)|, sev in|\[0\]|\[1\]"` over `report.py`, `report-dashboard.py` **and** `aranumtoolkit/tests/`.
- **Structural backstop, not grep accuracy.** A missed site is not a silent risk: unpacking a 4-field `Rule` as a 2-tuple raises `ValueError: too many values to unpack` at runtime, so any un-migrated consumer fails its own test. The Phase-7(a) requirement that the *entire* suite stay green is therefore the guarantee that migration is complete — the grep above only locates sites to edit; the green-suite gate is what proves none were missed.
A guard test additionally iterates every built-in rule list and asserts each element is a `Rule` with a non-empty unique `rule_id`, and that `_classify` returns a `Rule`; it fails if any list still holds a bare tuple. This is what makes the shadow audit (D1.2) and the KB (S2 D2.1) key on identity instead of re-matching text.

### D1.1 Negative and progress guard (G01, G02) — marker-and-rule-aware

**Option A (chosen).** A pre-classification guard in a new `_classify_line(line, rules)`. Every walker switches to it; `_classify` stays the raw-rule primitive. Suppression is decided by the **dispatcher marker only**, never by guessing negation from content:

- Suppress when the ANSI-stripped line's leading marker is the `_lib.sh` **miss** `^\s*\[-\]\s`, the `_lib.sh` **log** `^\s*\[\d{2}:\d{2}:\d{2}\]\s`, or the NetExec failure column `^\S+\s+\S+\s+\d{1,5}\s+\S+\s+\[-\]\s`.
- **Two overrides, in order, before suppression:**
  1. If the line matches any operator `--severity-rules` (custom, `miss_ok=True`) rule, it is never suppressed.
  2. If it matches a built-in rule whose `miss_ok=True`, it is never suppressed. `miss_ok` is set on exactly the rules that are *legitimately emitted through `Miss`/`Log`*, identified by sweeping the emission corpus (below), dash-agnostic on any literal `(disabled` / coercion text so a Unicode em-dash fixture cannot slip the override.
- **Content-negation matching (`NOT VULNERABLE`, `STATUS_*`) is dropped.** The reviewer is right that `STATUS_ACCOUNT_DISABLED` legitimately appears inside enumeration output; keying suppression on markers avoids hiding it.

**The sweep that sizes the override set.** `emission_audit.py` already extracts every `Miss(...)`/`Log(...)`/`[!!]` call site. The S1 gate enumerates every miss/log-markered line in the static corpus and asserts each is either suppressed (a true negative) **or** matched by a `miss_ok` rule (a true positive). Zero lines may be left unclassified. That set — not a hand-guess — becomes the `miss_ok` flag assignment. Known members today: the disabled-privilege hit (`Invoke-PrivEscEnum.ps1`) and `Test-CoercedAuth`'s "enabled via …" line; the sweep confirms the full set.

**Option B (not taken).** Per-rule negative lookbehinds (~150 edits, fragile). **Failure mode.** A future finding emitted through `miss`/`log` without a `miss_ok` rule is silenced. Mitigation: the corpus sweep is a gate, so a new such emitter fails CI until its rule is flagged `miss_ok`; and a dispatcher-contract note records that `miss`/`log` carry findings only through a `miss_ok` rule.

### D1.2 Rule order and a shadow audit (G03, G09) — expected-severity by rule id

Move the specific critical HTTP product rules above the generic `EXPOSED`/`UNAUTH` rules: Tomcat Manager and host-manager, the Jenkins API, and the Jenkins Groovy console. Fix the backup regex to match the emission (`(Rubrik|Cohesity|Dell PowerProtect Data Manager) backup API detected:` and the legacy form).

New **shadow-audit gate** (`tests/test_rule_shadowing.py`). It does **not** measure specificity by pattern length (the reviewer's correct objection: "longest literal" is not a validity measure). Instead:

1. A frozen table `tests/fixtures/rule_expectations.json` maps each corpus/label sample → its **expected `rule_id` and severity** (ground truth, authored once, reviewed).
2. For every graded emission in the static corpus and every labeled TP, `_classify_line` must return the expected `rule_id` at the expected severity.
3. Overlaps (a sample legitimately matched by more than one rule) are resolved by the expectation table, not by a metric; a deliberate overlap is allowlisted **by `(sample, rule_id)` pair with a reason**, not by length.
4. The test fails on any sample whose first-match rule id or severity differs from its expectation.

The corpus extractor moves from the docs harness into `aranumtoolkit/tests/_emission_corpus.py`, shared by the harness and the test. The docs harness keeps a frozen copy so the benefit number stays fixed. **Option not taken:** numeric rule priorities/weights. Evidence that would flip it: the expectation table needing more than ~10 overlap allowlist entries.

### D1.3 Endpoint attribution (G04, G05)

1. **Fold port-less records.** In `_inventory_endpoints`, a post-pass drops a port-less record `(host, "", "", svc)` whenever a port-specific record exists for the same `(host, svc)`.
2. **Infer scheme default ports.** In `_endpoint_in_text`, before matching, normalise `scheme://host` URLs without an explicit port to the scheme default for matching only (http 80, https 443, ldap 389, ldaps 636, ftp 21). The evidence text is unchanged.
3. **Host-level fallback.** If every match shares one host but the ports are ambiguous, attribute `host` with `port=""` and `attribution="host"`. One known host is better than `(dispatcher)`.
4. **Explicit run scope.** A line still unattributed keeps `host="(dispatcher)"`, documented in SCHEMA.md and used by merge-results.py and the interop README. It gains additive `scope:"run"`. Attributed findings get `scope:"endpoint"` or `scope:"host"`. The dashboard shows run-scope findings in a collapsed **Unattributed** panel and excludes them from host tables and severity KPIs.

**Option not taken:** renaming `(dispatcher)`, which breaks merge-results, recce interop and consumers. **Failure mode:** wrong-host attribution. Guards: the existing token-delimited matcher `_line_mentions_endpoint` is unchanged, and the new tests cover `10.0.0.1` vs `10.0.0.10` and multi-host lines.

### D1.4 Echo dedup (G06) — token-safe, one-to-one, across the echo boundary only

After attribution, merge a finding from a top-level `_*` dispatcher file into a per-host finding on the same `(host, service)` **only when all of the following hold** — the reviewer's over-merge concern is answered by making token equality a hard gate, not a similarity input:

- **Port/protocol compatible:** equal, or one side empty. Two distinct ports (`:445` vs `:3389`) never merge.
- **Protected-token-set equality (hard gate).** From each normalised text (strip markers, timestamps, the `UNAUTH:` prefix; lowercase; collapse whitespace) extract the set of **protected tokens**: any token containing a digit, `/`, `\`, `.`, `:`, or `@` (paths, IPs, ports, versions, hashes, secrets, share names). The two texts may merge **only if their protected-token sets are exactly equal.** A differing secret, share, path or version blocks the merge outright, so similarity can never override a real difference.
- **Prose agreement on what remains:** with protected tokens equal, the remaining alphabetic prose must agree by either containment (shorter ≥ 16 chars) or Jaccard ≥ 0.75 on 4-letter stems. This only decides wording, never facts.
- **One-to-one matching:** each dispatcher finding merges into at most one per-host finding and vice versa (greedy by best prose score); no fan-in/fan-out collapse.
- **Boundary restriction:** merging happens **only across the dispatcher-echo boundary**. Two per-host lines are never fuzzy-merged, protecting linenum/winenum SUID and share lines.

**The merge.** Survivor keeps the higher severity and its line; primary `evidence_path` prefers the per-host file; `evidence_paths` is unioned; additive `merged_ids` lists absorbed ids.

**Option not taken:** global fuzzy dedup. **Failure mode:** two distinct dispatcher facts about one host merging. Tests: same-host/different-port stay separate; same-path/different-secret stay separate; an SMB multi-share line is not collapsed into a single share finding; identical echo collapses to one.

### D1.5 Rules (G07, G08)

Add or adjust rules (each with a `rule_id` per D1.0) so every `tp_labels.json` entry grades at its labeled severity:

- `admin:admin WORKS` → critical.
- `OPEN RELAY CANDIDATE` → high.
- `VRFY enabled` → medium.
- NFS exports: `no_root_squash` → **critical**. Ground truth (grep `report.py`): this rule exists **only** in `_BULK_RULES`, graded `high` at line 644; there is no `_DEFAULT_RULES` NFS rule. The single existing rule is raised `high`→`critical`, and the rule is **also added to `_DEFAULT_RULES`** so a non-bulk NFS emission grades consistently. `no_all_squash` → medium and `insecure` → low are **new** rules (neither exists today) added to both lists.
- `POTENTIAL CRED LEAK` → high.
- JWT HMAC → medium.
- Terrapin (ssh-audit) → medium.
- Read-only kubelet → high.
- `BloodHound collection:` → high.
- RMI registry, KIBANA API → medium.
- Product "detected:" fingerprints (Jenkins, GitLab, SonarQube, Grafana, Prometheus) → medium.
- `Vault reachable` → low.
- Generic `^\s*\[!!\]` → critical, as the last critical fallback. All 12 `crit` call sites are criticals (grep).

The shadow audit (D1.2) runs the expectation table against **every composed rule order** a walker actually uses — `_DEFAULT_RULES`+`_AD_DEPTH_RULES`, `_BULK_RULES`+`_AD_DEPTH_RULES`, `_BULK_RULES_WIN`+`_AD_DEPTH_RULES` — so a severity that is right in one list and wrong in another (exactly the `no_root_squash` case) is caught.

### D1.6 Shared collector (consistency) — structured result

New `report.collect(out_dir, rules_path=None, *, diagnostics=None) -> Collection`, where `Collection` is a small dataclass with **every field each consumer needs** (reviewer round-3 NEW-ISSUE: the dashboard must not reference a field the dataclass lacks):

```
Collection(findings: list[dict], per_host: dict | None, posture: dict,
           domains: dict, diagnostics: list[dict], mode: str, layout: str)
```

`per_host` is the `_per_host_verdicts` rollup (populated for bulk and mixed trees, `None` for a pure service tree — mirroring today's behaviour); `mode` is `"auto-enum" | "bulk-enum" | "mixed"` and `layout` carries the mixed sub-counts (D4.4). S1 populates `findings`/`per_host`/`mode`; S3 fills `posture`/`domains`; the signature never changes. **`report-dashboard.build_index` is rewritten to call `collect()` and render from the returned `Collection` — it no longer runs its own bulk detection or its own binary `bulk` branch** (`report-dashboard.py:381`). `report.main` calls the same `collect()`. Neither re-implements collection; the dashboard shows per-host, posture and domain rollups from the one structured result without a second pass. The dashboard's dead `known_hosts` re-attribution block goes; its `(dispatcher)` checks become `scope == "run"` checks with a host-string fallback for older findings.json. `aranum.py`'s auto-enum copy step is extended to copy `posture.json` alongside findings.json/report.* (documented in D4.4) so the structured result survives the chain.

### PRE1 (adopted ride-along)

Fix the test fixture: `chmod 0o555` on the `apt.conf.d` directory, restored in teardown. No tool change. Recorded here because it is a test defect present at base.

### S1 test plan

- **(a) Regression.** Rerun the full manifest. Every base PASS must still pass. The PRE1 FAIL becomes PASS. Tests asserting old wrong behaviour may only change if listed here; the sweep is at Phase 7.
- **(b) New behaviour.** New `tests/test_findings_fidelity.py`:
  - The guard on each graded miss/log corpus line (suppressed) and each `miss_ok` line (preserved), including the Unicode-dash disabled-privilege fixture and the `Test-CoercedAuth` line.
  - A custom `--severity-rules` pattern on a `[-]`-markered line is **not** suppressed.
  - The rule id + severity on the Tomcat and Jenkins samples.
  - Attribution on the fixture: zero `(dispatcher)`, iLO → 10.0.0.30:443, SMB → 10.0.0.5:445.
  - Echo dedup: identical echo collapses; same-host/different-port stays two; same-path/different-secret stays two; multi-share line not collapsed.
  - The host-level fallback and run-scope for a line with no known host.
  - Dashboard ↔ report count parity on the fixture (both via `collect()`).
  - Every `tp_labels` entry at its labeled severity and expected rule id.
- **(c) New gates.** (i) the **shadow/expectation audit** and (ii) the **miss/log corpus-classification sweep**. RED proof for (i): run at the pre-fix commit, where Jenkins/Tomcat samples resolve to the generic rule id at the wrong severity; and a mutation moving the generic UNAUTH rule back above the Tomcat rule in a disposable worktree goes RED. RED proof for (ii): inject a corpus line with a `[-]` marker that matches a non-`miss_ok` rule → the sweep flags it unclassified. Both gates assert the corpus is non-empty (≥ 500 emissions) and that the Tomcat sample exists, so an extractor regression cannot pass vacuously.
- **Benefit.** M1–M5 re-measured with the frozen harness.

**Blast radius:** report.py, report-dashboard.py, findings.json content (additive `rule_id`), dashboard counts. **Rollback:** revert the S1 squash commit `d4a19e1` (PR #6, merged into `main` 25OCT2026 on top of base `69fec13`). No data migration; findings are regenerated from raw trees.

### S1 Phase-8 benefit (measured 25OCT2026, frozen harness, base `69fec13`)

| Metric | Baseline | After | Δ | Target | Provenance |
|---|---|---|---|---|---|
| M1 `neg_graded` (miss/log FPs) | 18 | **0** | −18 | 0 | measured (`emission_audit.py .`) |
| M2 `crit_ungraded` | 1 | **0** | −1 | 0 | measured |
| M3 `tp_recall` | 3/25 | **25/25** | +22 | ≥23 | measured |
| M3b `tp_sev_exact` | 0/25 | **25/25** | +25 | ≥20 | measured |
| M4 unattributed `(dispatcher)` (fixture) | 4 | **0** | −4 | 0 | measured (`dup_audit.py`) |
| M5 duplicate findings (fixture) | 4 | **0** | −4 | 0 | measured |

Same frozen harness as the Phase-5 baseline; the extractor moved to `tests/_emission_corpus.py` with the docs harness keeping a frozen copy, so the number is comparable. All six targets met or exceeded. Regression: 0 previously-passing tests fail (Phase-7 card); the one baseline failure (PRE1) is now green.

> **Errata (D1.6 "cannot diverge" claim).** The original claim that the shared `collect()` makes `findings.json` and the dashboard unable to diverge is **too broad** and is narrowed here: `collect()` is authoritative for the finding *set* and each finding's `host/port/protocol/scope`, so the two agree on which findings exist and their collector-assigned coordinates. The dashboard's *presentation* layer still independently re-infers a finding's port from text and host topology from storage directory names (peer-review #3/#4), so it can still mis-present. That inference is removed in S2 (GAP-S2-PORT, GAP-S2-TOPO); only then is the unqualified "cannot diverge" true. See REVIEW-008.

---

## S2 — Finding knowledge base, categories, AD view, run health (G10, G12–G15)

### D2.1 KB keyed by rule id (no second regex system)

New `aranumtoolkit/network/finding-kb.json`, registered in `data-sources.json` with a reviewed date and owner. The KB is keyed by the **`rule_id` attached at classification time** (D1.0), so a finding's remediation comes from the rule that graded it — there is no second regex pass that could drift from the grading pass (the reviewer's D2.1 concern). Shape:

```
{"schema": 1,
 "categories": {"ad": {"title": "Active Directory", "order": 1}, ...},
 "classes": {"smb.signing-not-required": {"category": "ad",
   "title": "...", "why": "...",
   "test": [{"label": "Confirm with NetExec", "cmd": "nxc smb <host> --gen-relay-list relay.txt"}],
   "fix":  [{"label": "Require SMB signing (GPO)", "text": "... 'Microsoft network server: Digitally sign communications (always)' = Enabled"},
            {"label": "PowerShell", "cmd": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"}],
   "refs": ["https://learn.microsoft.com/..."]}}}
```

- **Lookup:** `kb.classes[finding["rule_id"]]`. A custom (`custom:n`) or absent rule id falls back to a **service → category** map in the same file (`ldap`/`kerberos` → ad, `http` → web, `redis`/`mongo` → data; `smb` → ad only when the host also exposes 88 or 389, else `network`). The finding records `kb_match` = `"rule"` or `"service-default"`.
- **Findings gain additive keys:** `category`, `kb_id` (= the matched class key), `kb_match`.
- **Commands are templates.** `<host>`/`<port>` are filled at render time from the finding; nothing executes; the dashboard shows copyable text only.

**Coverage target (M6).** Every non-low built-in `rule_id` (across all four rule lists) has a KB class with ≥ 1 test and ≥ 1 fix. The gate test enumerates `rule_id`s straight from the rule lists (not from samples) and fails naming any non-low rule id with no class — exact, no ambiguity.

### D2.2 Presentation

- **report.md and report.html:** a "Top risks" section grouped by category. Each finding shows Why, How to test and How to fix.
- **Dashboard:**
  - An **Active Directory** page. It shows domain controllers (inventory hosts with 88+389 or 88+445), then AD findings grouped by attack-path family: relay and coercion, roasting, AD CS, delegation, credential exposure (GPP/LAPS/SYSVOL), and policy and hygiene. **Chain hints are labelled "uncorrelated signals" in S2** and carry an explicit caveat that they are not confirmed to share a domain — S2 has no domain identity yet. True same-domain correlation waits for S3's `domains` rollup, at which point the AD page upgrades these to confirmed chains keyed on domain identity. (Reviewer D2.2: do not assert a correlated chain before domain identity exists.)
  - A **Categories** page.
  - The finding card gains "How to test" and "How to fix" expanders with copy buttons (reuse the existing dashboard.js copy handler).
  - A **Run health** panel on the index and coverage pages. It parses `[!]` lines from every `_dispatcher.log` that no rule grades (tool missing, refused, timeout, error), grouped by service, with counts (G10).
- **Option not taken:** a JS single-page application. The dashboard stays static HTML with no external assets.

### S2 test plan

- **(a)** The manifest from the S2 base.
- **(b)**
  - KB schema validation (class keys unique, categories exist, regex-free so no compile step, every class has test+fix).
  - Fixture findings carry `category`/`kb_id`/`kb_match`, and a known finding's `kb_id` equals its `rule_id`.
  - The AD page lists the fixture SMB-signing finding under relay, with the "uncorrelated signals" caveat present.
  - Run health lists a seeded nuclei-timeout line.
  - report.md contains "How to fix".
- **(c) New gate:** the KB coverage test over **rule ids**. RED proof: delete one class from a temp copy of the KB (`ARANUM_FINDING_KB` env override) → it fails naming the uncovered rule id. It asserts ≥ N rule ids were enumerated so an enumerator regression cannot pass vacuously.

**Rollback:** revert. The new keys are additive, and consumers ignore unknown keys. Merge SHA: `4507a3c` (PR #7).

### S2 Phase-8 benefit (measured 25OCT2026, same harness as the S2 base, base `d4a19e1`)

Harness: copy `aranumtoolkit/docs/examples/dashboard/fixture`, `finalize_findings(walk_findings(out, _load_rules(None)))`, count non-low findings. The only variable changed between base and head is the presence of `finding-kb.json` (identical fixture, identical rules) — so the delta is attributable to S2 alone.

| Metric | Baseline (`d4a19e1`) | After (S2 head) | Δ | Provenance |
|---|---|---|---|---|
| M6 — non-low findings carrying a class-specific test+fix block (`kb_id`+`category`) | 0.0 % (0/9) | 88.9 % (8/9) | +88.9 pp | measured |
| M6b — non-low findings carrying *any* KB guidance (`category`, `kb_match`≠"") | 0 % (0/9) | 100 % (9/9) | +100 pp | measured |
| KB coverage gate — non-low built-in `rule_id`s with a class (test+fix) | 0 / 199 | 199 / 199 | +199 | measured (`test_kb_covers_every_non_low_rule_id`) |

The remaining M6 gap (1/9) is the fixture's "UNAUTH SMB shares" finding, which matches only a **generic fallback** rule (`UNAUTH`) — a rule id excluded from the 199-class denominator by design. It receives a service-default category (`network`) and categorized guidance (M6b counts it) but no class-specific test/fix block, which is correct: a generic catch-all has no single remediation. M6-as-defined therefore cannot reach 100 % whenever a run contains a generic-fallback match; the structural guarantee is the coverage gate (199/199), not the fixture percentage.

Regression: full suite `470 passed / 5 skipped / 0 failed` vs the S2 base manifest `455 passed / 5 skipped` — every baseline-passing test still passes (per-test compared), +15 new S2 tests. Raw: `docs/test-strategy/raw/s2-head/`.

---

## S3 — Host posture collectors + posture model (G16, G21–G23)

### D3.1 Collector output contract — strict ASCII framing

Each check emits exactly one line:

```
POSTURE|<check-id>|<PASS|FAIL|WARN|INFO|NA|ERR>|<detail>
```

- **Framing is ASCII and escaped.** `check-id` and `status` are `[A-Z0-9-]` only. `detail` is a single physical line: the collectors replace any `|`, CR or LF in a detail value with ` ` (space) before emitting, so the field count is always exactly 4 and a detail can never inject a field or a line. The parser splits on the first three `|` only (`split("|", 3)`), so a stray `|` that somehow survives stays inside `detail`.
- **The parser is strict and anchored** (`^POSTURE\|[A-Z0-9-]+\|(PASS|FAIL|WARN|INFO|NA|ERR)\|`). A line that starts `POSTURE|` but fails the anchor, or whose `check-id` is unknown to the KB, or whose `check-id` repeats within one host, is **quarantined as a diagnostic** (`collect().diagnostics`, surfaced in Run health) — never dropped silently and never turned into a finding. `ERR` means the check could not run (permission, missing binary); it is never PASS.

**Option not taken:** JSON output. The collectors must also be readable on screen and must survive PS transcripts; a strict pipe line is grep-friendly and transcript-safe.

### D3.2 Collectors — read-only; host checks are localhost-only, AD checks are consent-gated DC queries

The header is corrected from the round-1 draft: **host** posture is localhost-only, but **AD domain** checks necessarily query the host's own domain controller over authenticated read-only LDAP. That is inherent to AD enumeration and is gated behind an explicit consent flag; it is not "no network beyond localhost." Both collectors are standalone and self-contained (no dot-sourcing) so bulk transports can stdin-pipe them.

**`standalones/linux/host-posture.sh`.** Pure POSIX tools, ~30–35 localhost checks: kernel EOL + pending security updates (read package cache only, never refresh); sysctl (ptrace_scope, kptr_restrict, dmesg_restrict, unprivileged_bpf, unprivileged userns, ASLR, suid_dumpable, ip_forward); LSM mode; firewall present; sshd_config (PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, ciphers); accounts (extra UID-0, empty-password — shadow only if readable else ERR, sudoers NOPASSWD count, umask, aging); mounts (/tmp, /dev/shm nosuid/noexec); logging (auditd, syslog); secure boot (`mokutil --sb-state` if present); world-writable PATH dirs, core dumps, cron/at perms, time sync, failed units (INFO); AD membership (sssd/realm/winbind joined = INFO, readable keytab = FAIL).

**`standalones/windows/Invoke-HostPosture.ps1`.** ~35–45 localhost checks, registry/CIM/native read-only: firewall profiles; Defender (RTP, tamper, signature age — read only); BitLocker, Secure Boot; SMB (SMBv1, server/client signing); name resolution (LLMNR, NBT-NS, WPAD); PowerShell (v2 engine, script-block logging, transcription); RDP (enabled, NLA); credential protection (RunAsPPL, Credential Guard, WDigest, LmCompatibilityLevel, CachedLogonsCount); elevation (EnableLUA/ConsentPrompt, LocalAccountTokenFilterPolicy, AlwaysInstallElevated); local Administrators (INFO + count), Guest; patching (last hotfix age, build EOL); spooler (WARN on DC), WinRM HTTP-only listener; LAPS client policy, AutoLogon password (FAIL).

**AD domain checks are consent-gated end-to-end (reviewer round-2 D3.2).** The gate is one logical flag threaded through every delivery layer, off by default:
- `Invoke-HostPosture.ps1` takes a `-AdChecks` switch; absent it, every `AD-*` check emits `POSTURE|AD-...|NA|ad checks not requested` and no DC query runs.
- `bulk-enum-windows.py --with-posture` gains `--ad`; when set, the script-block wrapper (D3.4) invokes the posture block as `& { <posture body> } -AdChecks`.
- `local-enum.py` and `aranum run --local` / `aranum local` gain `--ad`, forwarded to `bulk-enum-windows.py` and to the `--self` Windows collector. `--ad` is in `_LOCAL_ENUM_VALUE_FLAGS`-adjacent boolean handling (D4.4) and never auto-enabled.
- The Linux collector's AD-membership checks are localhost-only (sssd/realm/keytab) and issue **no** DC query, so they need no flag; only the Windows ADSI DC queries are gated.

**When `-AdChecks` is set and the host is domain-joined and FullLanguage:** read-only LDAP against the host's own DC, selected via `RootDSE` (`defaultNamingContext`, `dnsHostName`), with **bounded paging (page size 1000) and a per-query timeout**, so a large directory cannot hang the collector. Checks: domain password policy (min length, lockout threshold, max age); `krbtgt pwdLastSet` age (signed `LargeInteger` → FILETIME conversion); counts of kerberoastable users (SPN set, not computer, enabled), AS-REP users (`DONT_REQ_PREAUTH`, enabled), non-DC unconstrained-delegation computers, `adminCount=1` users, Domain Admins members (recursive); Protected Users count, `ms-DS-MachineAccountQuota`; **domain and forest functional level**; **LDAP signing / channel-binding requirement** (read from the DC's policy via `rootDSE`/registry where remotely readable, else `NA` with a note — not a false PASS); trusts (INFO); LAPS schema attribute present. Every AD line is tagged `domain=<dns>` in `detail` and carries an observer tag so D3.3 can roll up without double counting. Roastable/AS-REP/delegation filters and the `LargeInteger`→age and COM/ADSI→plain-object conversions are factored into **named helper functions** so they can be unit-tested off a Windows box with fixture inputs (reviewer D3.2 testability).

### D3.3 Parser and model — structured domains, no double count

`report.py`:

- New strict `_POSTURE_RE` (D3.1). Posture lines bypass the regex rules entirely.
- FAIL and WARN become findings with `service="posture"`. Severity comes from the KB check entry (`sev_fail`/`sev_warn`). The finding carries `posture_check`, `posture_status`, `kb_id`, `category`.
- PASS, INFO, NA, ERR are not findings; they live in **`posture.json`** beside findings.json: `{hosts: {host: {os, source, checks: {id: {status, detail}}}}, domains: {name: {checks: {id: {status, detail, observed_from: [...]}}}}}`.
- **AD/domain checks never become per-host findings.** They are parsed into the `domains` map keyed by domain identity. Each `(domain, check)` yields **one canonical finding** for KPIs, so three domain-joined hosts reporting the same policy produce one finding, not three (reviewer D3.3 double-count).
- **Per-observer evidence is preserved, not flattened (reviewer round-2 D3.3).** `observed_from` is a list of **records** `{host, status, detail}`, one per reporting host — not a list of bare hostnames — so a host reporting PASS and another reporting ERR (or FAIL) are both retained and visible; no observer's status/detail is lost.
- **The canonical status lattice is total over all six statuses (reviewer round-3 added `INFO`).** Partition into *determined* `{FAIL, WARN, PASS, INFO}` ranked `FAIL > WARN > PASS > INFO` (INFO is a real domain status — e.g. the trusts check emits it — and is the least-severe determined value), and *undetermined* `{ERR, NA}`. The canonical `(domain,check)` status is the **worst determined** status across all observers if any observer determined it (so one real FAIL beats any number of PASS/INFO/ERR; an INFO-only check stays INFO); if **no** observer determined it, the canonical status is `ERR` when any observer reported `ERR`, else `NA`. An undetermined status never outranks a determined one, so the ordering is total. A `detail` string on the canonical record notes a conflict when observers disagree among determined statuses (e.g. `conflict: host-a=PASS host-b=FAIL`).
- findings.json `summary.posture` gains additive `{hosts, pass, fail, warn, err}`; `summary.domains` gains `{count, worst_by_check}`.

### D3.4 Delivery — PowerShell script-block wrapper (5.1-safe)

- `bulk-enum-linux.sh` and `bulk-enum-windows.py` gain `--with-posture`.
- **Linux:** bash concatenation of the privesc script then the posture script over the SSH stdin stream (both are plain scripts; order fixed; `linenum-fast.sh` must not `exit` before the appended part — verified, no early exit today, re-checked in the sprint).
- **Windows:** the two advanced scripts are **not text-concatenated** (that breaks PS 5.1, where `[CmdletBinding()]`/`param()` must be the first statement of a script). Instead the transport emits a wrapper that invokes each collector body inside its own script block — `& { <privesc body> }` then `& { <posture body> }` — because `param()` *is* valid as the first statement of a script block. The combined payload is parsed under the 5.1 parser (dual-encoding + AST, the gotcha-doc method) in the test before it is ever shipped (reviewer D3.4).
- Output stays in `linenum.txt`/`winenum.txt`, so the existing walker and layout are untouched. S4's `local-enum.py` always enables posture.

### D3.5 Dashboard

- A **Posture** page: a host × category matrix of pass/fail/warn counts with a score, then a per-check table across hosts.
- The host detail gains a **Posture** card: checks grouped by category with status chips and KB test/fix expanders.
- The AD page gains a **Domain posture** table fed by `collect().domains`, and (per D2.2) upgrades the S2 "uncorrelated signals" hints to confirmed chains where a domain identity now ties them together.

### S3 test plan

- **(a)** The manifest at the S3 base.
- **(b) Linux collector.** Runs for real on this Linux host; assert ≥ 30 POSTURE lines, every id known to the KB, no `ERR` a non-root user could have satisfied. Hermetic fixtures set `ARANUM_POSTURE_ROOT=<tmp tree>` (the `apt-source-check.sh` pattern) and assert specific PASS/FAIL for sshd_config, login.defs, `/proc/sys` sysctls, and a fake `mounts`.
- **(b) Windows collector.** No Windows box: dual-encoding parse (UTF-8 + CP1252); PSScriptAnalyzer 5.1-profile rules; AST scan for 7-only syntax; **extract the AD helper functions via the AST and unit-test them** against fixtures — a disabled roastable account is excluded, a DC is excluded from delegation counts, recursive Domain Admins membership is counted once, a signed `LargeInteger` krbtgt age converts correctly, and a channel-binding value that is not remotely readable yields `NA` not PASS; run under pwsh on Linux and assert every `WIN-*`/`AD-*` check emits `NA|not windows` and exit 0; and assert that **absent `-AdChecks`** every `AD-*` check emits `NA|ad checks not requested` with no LDAP/ADSI call (the AD helper is AST-extracted and invoked with the switch off).
- **(b) Parser.** On fixture winenum/linenum with POSTURE lines: FAIL → finding at KB severity; PASS → only in posture.json; a malformed `POSTURE|` line → quarantined diagnostic, not a finding; the same domain check from two hosts → **one canonical finding** whose `observed_from` holds two `{host,status,detail}` records; a PASS-from-host-a + ERR-from-host-b pair yields canonical `PASS` (determined beats undetermined) with both records preserved; a PASS + FAIL pair yields canonical `FAIL` with a `conflict:` detail; an ERR + NA pair (no determined observer) yields canonical `ERR`.
- **(c) New gate:** the posture-KB coverage test — every check id emitted by either collector has a KB check entry with test+fix (ids extracted statically). RED: add a fake id to a temp copy of a collector → fail. Asserts ≥ 30 ids extracted (no vacuous pass). A second gate asserts the strict parser rejects a crafted field-injection detail (`a|b|c` inside detail) — RED by relaxing the split cap.

### S3 execution notes and errata (26OCT2026)

- **D3.4 erratum (Windows delivery, measured).** The literal `& { <body> }` wrapper
  matches the plan, with one requirement the plan did not state: over
  `pwsh -Command -` each block must be followed by a **blank line**, or the host
  waits for more input and the block never runs. A base64 variant
  (`[scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(…)))`)
  was tried and **rejected**: under ConstrainedLanguage it emits 0 lines
  ("Method invocation is supported only on core types"; review R1,
  `raw/s3-wip/r1-clm-red.txt`).
- **D3.4 deviation (Linux delivery).** The plan said plain concatenation. As
  shipped, the privesc body runs as `( <linenum-fast.sh> ) </dev/null`, followed
  by the posture body. bash reads the whole subshell before it runs it, so no
  command inside can eat the rest of the stdin stream, and an `exit` inside
  cannot skip the posture collector. Without `--with-posture` the default payload
  is byte-for-byte unchanged (tested).
- **Test-plan deviation (Windows helpers).** The plan said "AST-extract the AD
  helper functions". Instead the tests dot-source the shipped collector with
  `-LibraryOnly`, which defines the same functions and runs nothing. That covers
  everything AST extraction would, and it tests the exact file that ships.
  Daybreak asked for AST extraction in round 2 and the request was rejected with
  this rationale (REVIEW-010).
- **Grading hardening from review (REVIEW-010):**
  - Registry reads now separate "absent" from "unreadable". An unreadable value
    is ERR, never the absent-value default.
  - AD-LDAP-SIGNING grades signing **and** channel binding.
  - Every registry policy is read through one validated reader (`Get-RegPolicy`),
    so a value outside its documented set grades ERR. This is the round-3
    structural closure, guarded by an out-of-domain fuzz gate.
  - AD lines are domain-tagged before discovery.
  - RootDSE goes through the bounded searcher.
- **New items (Phase-1 IDs, not absorbed into S3):**
  - **N1:** WinRM `-EncodedCommand` 32K command-line limit. Relevant to S5.
  - **N2:** pre-existing duplicate bulk host pages, keyed both by directory name
    and by IP (the fixture shows "hosts: 6" for 3 hosts).
  - **N3:** `_AD_FAMILIES` matches by substring. This is an owner question.
  - **N4:** stdin buffering under Windows PowerShell 5.1 is unmeasured. A custom
    `--script` that calls `exit` would stop the posture block. Lab item for S5.
  - **N5:** account names in `sample=` detail are not redacted. The redaction
    contract covers IP, host and domain only.
  - **N6:** review R5 residual. ADSI bind and DC location are synchronous, so
    there is no hard wall-clock bound before the first LDAP result. No portable
    bound was demonstrable on this Linux host. Verify in the S5 Windows lab.
- **Review:** REVIEW-010, three rounds (round 1: 10 findings in 6 classes;
  round 2 verify: 7 closed, 3 partial, 1 new; round 3: the fall-through-PASS
  class recurred, so it was escalated to the structural `Get-RegPolicy` reader +
  gate, followed by a verify-only pass).
  Test card: `docs/test-strategy/cards/CARD-S3-26OCT2026-host-posture.md`.

### S3 Phase-8 benefit (measured 26OCT2026, same harness as the S3 base, base `7e62404`)

Harness: `docs/test-strategy/harness/m7_posture_coverage.py` (v2), re-run unchanged
at base and head.

| Metric | Baseline (`7e62404`) | After (S3 head) | Target | Δ | Provenance |
|---|---|---|---|---|---|
| M7 — Linux posture checks with KB test + remediation | 0 | 43 | ≥ 30 | +43 | measured (`raw/s3-base-7e62404/m7-baseline-v2.txt`, `raw/s3-head/m7-after-v2.txt`) |
| M7 — Windows host + AD posture checks with KB test + remediation | 0 | 56 | ≥ 35 | +56 | measured |

Both targets are met. The structural guarantee is GATE 1, the posture-KB coverage
test: every id a collector can emit has a KB test and fix, and no KB check is
orphaned.

Regression: the full suite gives `529 passed / 5 skipped / 0 failed` at head
`7ff27c2`, against the S3 base manifest of `472 passed / 5 skipped`. Every
baseline-passing test still passes (compared per test), the skip signatures are
identical, and 57 S3 tests are new. Raw: `docs/test-strategy/raw/s3-head/`.

**Blast radius:**
- new collectors under `standalones/`
- `--with-posture` / `--ad` on both bulk transports
- `report.py` posture parser, `posture.json` and redaction
- the dashboard Posture page, host card and AD domain posture
- the `checks` section of `finding-kb.json`

**Rollback:** revert the S3 squash commit. All new keys and flags are additive and
off by default, and findings are regenerated from raw trees. Merge SHA: `38ffedc` (PR #8).

---

## S4 — `--local` access layer (G17, G18, G20)

**New ADR-007 records the access-layer design and its §9 analysis before code.** Every delivery note below is enumeration-only; the invariants bind this sprint in full. **There is no relay and no fetch/upload server anywhere in this sprint** (round-1 blocker): output returns only through the transport that carried the command.

### D4.1 Orchestrator

New `aranumtoolkit/network/local-enum.py` (stdlib) and the CLI entries `aranum local ...` plus `aranum run ... --local`.

**Inputs:**
- `--targets FILE` (`host[:port] [os=linux|windows] [via=ssh,winrm,...] [user=...]`), **or** `--from-inventory <inventory.json>` (auto-builds candidates from open 22, 5985/5986, 445, 3389, 5900-5910 using nmap OS/service hints).
- Credentials (operator-supplied only): `-u/-p/--key`; `--creds FILE` (`host|* user pass-or-key-path`, mode 0600 else warn); `-H` NT hash for impacket/nxc.
- `--transport` order, `--win-exec {wmiexec,smbexec,psexec}`, `--self`, `--desktop-ok` (S5), `-P`, `--dry-run`, `-o`. (No `--lhost`/`--lport`; the relay is gone.)

**Per-host flow.** Resolve OS (hint → port heuristic → banner over the chosen transport); try transports in order until one authenticates (ADR-006 fall-through); run privesc + posture; write the bulk layout `<out>/{linux,windows}/<host>/_meta.json` + `linenum.txt`/`winenum.txt`, `_meta.json` carrying host, port, protocol, user, transport, os, status, fail_reason, artifact_id.

Default transport order:
- Windows: winrm → ssh → the chosen `--win-exec` method (only when `--win-exec` is given) → rdp/vnc (only with `--desktop-ok`).
- Linux: ssh → rdp/vnc (only with `--desktop-ok`).

**Delegation (Option A, chosen).** Delegate to the proven per-OS engines:
- Linux ssh → `bulk-enum-linux.sh` (KEY/PASS/KEY_THEN_PASS, ADR-006) `--with-posture`.
- Windows winrm/ssh → `bulk-enum-windows.py --transport winrm,ssh --with-posture`.
- `local-enum.py` implements only the *new* pathways: the local self-scan, the operator-chosen compact Windows exec probe, and (S5) the desktop transports.

**Option B (not taken):** reimplement every transport — duplicates tested code, voids ADR-006 coverage.

### D4.2 Local self-scan (G20)

`--self` (and `aranum local --self`) runs the matching posture + privesc collector for the current OS directly, no transport, filed as `host="localhost"`, `transport="local"`. Cheapest provable pathway and the backbone of the S4 end-to-end test — no credentials, no second host.

### D4.3 Operator-chosen Windows exec method (G18) — compact probe through the transport, no relay

The three impacket-family methods (wmiexec, smbexec, psexec) run a command through their **own** transient mechanism and return its stdout the same way (for wmiexec/smbexec this transits an ADMIN$/share output file — the existing ADR-003/006 SMB CAVEAT, consent-gated by `--use-smb-admin`; that is the method's mechanism, torn down by the method, not a new channel we add). The full ~20 KB enumeration script does not fit any of their command-line ceilings, so:

**Design decisions (recorded here and fully in ADR-007):**
- **The exec methods carry a *compact probe set*, not the full collector.** `local-enum.py` assembles the largest subset of high-value read-only posture/privesc one-liners (as a single `-EncodedCommand`) that fits the chosen method's measured ceiling (wmiexec ~8000 chars; psexec/smbexec far smaller). What fits is captured through the method's own stdout.
- **If even the compact set does not fit the chosen method's ceiling, the builder refuses** with a clear message to use winrm/ssh for full enumeration. It never truncates a command onto the wire and never silently drops checks. Full enumeration over these methods is **declared unsupported** — stated in `--help` and ADR-007, not implied as parity.
- **Method is explicit and consent-gated.** `--win-exec` must be chosen; none of the three is ever auto-added. `--use-smb-admin` consent and the admin-cred requirement are preserved.
- **No on-disk-artifact parity claim.** The SMB CAVEAT is restated: these methods transit a service and/or an ADMIN$ output file, so they lack the no-on-disk-artifact property winrm/ssh keep. Stated plainly.
- **§9 compliance.** No listener, no target-side fetch, no upload endpoint; output returns via the method's own stdout mechanism. No staging of our own file to the target; no persistence; no obfuscation/evasion. The probe body is reviewed, read-only, and the same checks shipped (in full) over winrm/ssh. Discovered credentials are access candidates only.

### D4.4 CLI wiring — explicit arg partitioning and an explicit mixed-tree collector

- `_COMMANDS` gains `local` (runner `local-enum.py`).
- **`aranum run` arg handling is partitioned explicitly** (reviewer D4.4): the run dispatcher parses its argv into an **auto-enum arg set** and a **local-enum arg set** by a declared table, rather than forwarding every value flag to `auto-enum.sh`. `--local`, `--transport`, `--win-exec`, `--self`, `--desktop-ok`, `--creds` and friends go only to `local-enum.py`; auto-enum never receives a flag it rejects. `_AUTO_ENUM_VALUE_FLAGS` stays correct for the auto-enum side; a new `_LOCAL_ENUM_VALUE_FLAGS` governs the local side; the final two argv lists are asserted by a test.
- `--local` on `aranum run` runs auto-enum first, then `local-enum.py --from-inventory <raw>/inventory.json`, then the shared report+dashboard over the combined tree. `aranum.py` copies `posture.json` along with findings.json/report.* at the end of the chain (D1.6).
- **Explicit mixed-tree collector** (reviewer D4.4): `collect()` learns a mixed layout. A new marker file `_aranum_bulk_root` is written at each `<out>/linux` and `<out>/windows` root by `local-enum.py`; `collect()` treats a marked directory as a **bulk root** (walked by the bulk walker, which already expects `<root>/<host>/{_meta.json,winenum.txt|linenum.txt}`) and every other top-level directory as a service dir (auto walker). The service walker is given an explicit exclude set so it never treats `linux`/`windows` as a service, and the bulk walker is handed the real bulk-root path so evidence paths are rebased to the full `<out>/windows/<host>/...` prefix (not a root-relative stub).
- **The binary mode becomes ternary (reviewer round-2 D4.4).** Today `findings.json` carries `"mode": "bulk-enum" if bulk_mode else "auto-enum"` (`report.py:1691`) and `per_host` is populated only in bulk mode. A tree with both a service dir and ≥1 marked bulk root is tagged **`"mode": "mixed"`**. In mixed mode:
  - **Findings** are the union of the auto-walked service findings and the bulk-walked host findings, one schema-v2 list.
  - **`per_host`** is computed for every bulk host (as today) **and** merged with host-attributed service findings via `_per_host_verdicts` over the unified list, so a host that appears both as a bulk root and as a service-finding target gets one combined verdict row.
  - **Inventory** is the union: service-dir endpoints plus one synthetic inventory entry per bulk host (host, os, transport from `_meta.json`).
  - **`summary`** gains `layout: "mixed"` with sub-counts `{service_findings, bulk_hosts}`; existing `"auto-enum"`/`"bulk-enum"` modes are unchanged for non-mixed trees (back-compatible).
  - **Dashboard** (`report-dashboard.build_index`): renders the normal service views **and** the per-host privesc/posture cards for bulk hosts in the same index, driven by `collect().findings` + `.per_host` + `.posture`; the `(dispatcher)`→`scope=="run"` change (D1.6) applies throughout. No view is dropped because the tree is mixed.
  The two walkers thus produce one unified, schema-v2 findings list and one dashboard, with `mode`/`per_host`/inventory all defined for the mixed case rather than falling through the old binary branch.

### S4 test plan

- **(a)** The manifest at the S4 base.
- **(b)**
  - Target-file and `--from-inventory` parsing → correct per-host OS, transport order, candidate build.
  - **Arg partitioning:** `aranum run --local --win-exec wmiexec -o X` yields the exact auto-enum argv (no local-only flags) and the exact local-enum argv, asserted by list.
  - `--dry-run` prints the plan and opens no socket (asserted under a no-network sandbox) — and because there is no relay, there is no listener to assert *absent* beyond this.
  - **The local self-scan runs for real on this host** and produces a valid bulk tree that `collect()` ingests into findings + posture with zero `(dispatcher)` noise.
  - The compact-probe builder for each of wmiexec/smbexec/psexec: assert the assembled command is **under that method's ceiling**; assert that a probe set enlarged past the ceiling (or a lowered ceiling) makes the builder **refuse**; tool stubbed on PATH, no real connection.
  - **Mixed-tree collector:** a fixture with one service dir and one `windows/` bulk root (with `_aranum_bulk_root`) yields one unified findings list; `findings.json` `mode == "mixed"` with `summary.layout == "mixed"` and non-zero `service_findings` + `bulk_hosts`; `per_host` contains the bulk host; `windows` is not reported as a service; evidence paths carry the full `windows/<host>/...` prefix; the dashboard renders both the service views and the bulk host card. A non-mixed bulk-only tree still reports `mode == "bulk-enum"` and a service-only tree `mode == "auto-enum"` (back-compat).
  - **`--ad` threading:** `aranum run --local --ad` forwards `--ad` to `bulk-enum-windows.py` and the `--self` Windows collector (asserted in the partitioned argv); without `--ad`, neither receives it.
  - Dependency-absent degradation: tool absent → non-zero host status + clear message, run continues.
- **(c) New gate:** the **exec-ceiling gate** — the assembled exec-method command for each method must be under that method's declared ceiling, and the builder must refuse when a requested probe set exceeds it. RED: lower a method's ceiling constant (or enlarge the probe set) in a temp copy → the builder must refuse and the "fits" assertion must fail. (The old relay-safety gate is retired with the relay.)

**Blast radius:** a new orchestrator, CLI dispatch + arg partitioning, the mixed-tree collector. **Rollback:** revert the squash; the new command and flag are additive.

### S4 Phase-8 benefit (measured 26OCT2026, M8 harness, base `41860c8`)

M8 counts access pathways runnable via the `--local` layer, by capability tier.
Harness: `docs/test-strategy/harness/m8_pathways.py` (written at the S4 base before
any S4 code; `local`(full) runs a real self-scan, the rest are dry-run PLAN checks).
Raw: `docs/test-strategy/raw/s4-base-41860c8/m8-baseline.txt` (base) and `raw/s4-head/`.

| M8 tier | Baseline (`41860c8`) | After (S4 head) | Target | Δ | Provenance |
|---|---|---|---|---|---|
| full (local, linux-ssh, windows-ssh, windows-winrm) | 0/4 | **4/4** | 4 | +4 | measured |
| compact (wmiexec, smbexec, psexec) | 0/3 | **2/3** | see erratum | +2 | measured |
| desktop (rdp, vnc) | 0/2 | 0/2 | S5 | 0 | measured (S5 scope) |
| **M8 total** | **0/9** | **6/9** | 6 (S4) | **+6** | measured |

At the base SHA the `local` command does not exist, so every pathway is 0/9 regardless
of harness scoring; the baseline is unaffected by the harness's refinement.

**Erratum — compact tier is 2/3, by design, not 3/3.** The pre-registered M8 row listed
wmiexec/smbexec/psexec as the compact tier without stating per-method capacity. Measured
on the S4 code: the compact-probe *core* (helpers + `whoami /priv` + first check) is 7146
chars. That fits wmiexec (ceiling 8000, carries 2 checks) and smbexec (7800, 1 check) but
is ~1.8× psexec's 4000 ceiling, so **psexec carries no posture and the builder refuses**,
routing the operator to winrm/ssh. psexec remains a valid *access* pathway; it is not a
*posture* pathway. This is the "refuse over truncate" contract (ADR-007 D4) exercised, not
a regression — `psexec` is a correct M8 FAIL. S4 target restated: full 4/4 + compact 2/3 =
**6/9**. Detail: ADR-007 erratum (26OCT2026).

---

## S5 — Desktop transports (G19)

**Problem.** Some hosts expose only RDP or VNC, and the user requires those pathways on both OSes. These are interactive GUI channels, so non-interactive enumeration is best-effort — and output capture differs by channel, which the design now reflects honestly.

### D5.1 Approach — native capture for RDP, assisted-default for VNC, no relay

- **`--desktop-ok` gate.** RDP and VNC are never in the auto order without this flag (they disconnect/lock interactive sessions and are noisier than winrm/ssh). The flag is the operator's explicit acceptance.
- **RDP (Windows targets), Option A chosen.** `nxc rdp <host> -x <cmd>` runs the **compact probe set from D4.3** and **captures its output through nxc's own result channel** — no relay, no GUI scraping. Expose `--cmd-delay`/`--clipboard-delay` passthrough. If nxc or its RDP support is absent, degrade clearly. **Option not taken:** OCR of the RDP framebuffer — brittle; last resort, not built.
- **VNC (both OSes) — assisted by default.** VNC has no command/exec channel and no reliable way to confirm keystrokes land in a focused, unlocked terminal, so blind keystroke automation cannot guarantee correct execution or any output capture (reviewer D5.1). Therefore the **default VNC pathway is assisted**: the tool prints a ready-to-paste compact-probe command and the operator runs it in the GUI and pastes back the output file path, which `local-enum.py` ingests. Blind keystroke automation (`vncdotool`) is available only under a **second explicit flag `--vnc-automate`** *and* `--desktop-ok`, requires a focus-check handshake (type a marker, read it back via the framebuffer before proceeding), and still cannot capture output — so it is documented as fire-and-verify-manually, not an enumeration pathway that returns findings.
- **Linux RDP (xrdp).** `nxc rdp` targets Windows RDP semantics and does not drive a Linux xrdp session for command execution. For a Linux-only-RDP host the tool falls through to ssh if available, else the assisted VNC path; it does **not** claim an automated Linux-RDP enumeration pathway. Recorded in ADR-007, and **M8 does not count an automated Linux-RDP pathway** (reviewer D5.1).
- **Assisted mode (general).** Whenever no non-interactive path succeeds, emit the ready-to-paste compact-probe command plus clear instructions, so the pathway stays useful without the tool driving a GUI blindly.

### D5.2 §9 and safety

No relay, no listener, no target-side fetch/upload (same as S4). RDP output returns via nxc's channel; VNC output returns via the operator in assisted mode. The automated VNC keystrokes (opt-in) only launch the reviewed read-only probe; they stage nothing, persist nothing, use no evasion. `--desktop-ok` is mandatory for either desktop transport; `--vnc-automate` is additionally required for blind keystrokes.

### S5 test plan

- **(a)** The manifest at the S5 base.
- **(b)**
  - The RDP argv builder (nxc rdp `-x` with the compact probe + delay passthrough) asserted by string, tool stubbed.
  - Assisted-VNC output: the printed operator command and the paste-back ingest path are present and well-formed.
  - `--vnc-automate` keystroke builder asserted by content *and* gated: absent `--vnc-automate`, the VNC path is assisted-only; the focus-check handshake step is present in the automated path.
  - `--desktop-ok` gating: without it, rdp/vnc are absent from the resolved order (asserted refusal).
  - Linux-only-RDP host resolves to ssh/assisted, never to an automated Linux-RDP claim.
  - Tool-absent degradation for both.
- **(c) New gate:** the **desktop-gate test** — rdp/vnc must not appear in any resolved transport order unless `--desktop-ok` is set, and blind VNC keystrokes must not run unless `--vnc-automate` is also set. RED: drop the `--desktop-ok` check (wrong-but-present: leave the flag defined, remove its enforcement) in a temp copy → the order must wrongly include rdp/vnc and the test must fail; likewise for `--vnc-automate`.

**Blast radius:** new transports in the S4 orchestrator, new CLI flags. **Rollback:** revert the squash.

---

## Effort-wide benefit (after S5)

Re-measure M1–M8 on the same harnesses. Run the full example fixture plus a local self-scan end-to-end and confirm: zero `(dispatcher)` noise, an AD page, a posture matrix, and a test + remediation block on every non-low finding and every failing posture check. Record the deltas and the merge SHAs here, and write errata against this plan if any pre-registered target is missed.

## Peer review (Phase 5 gate)

This whole plan goes to a second, independent Tier-2-cyber model (codex Daybreak Blue, `-c model_reasoning_effort=xhigh`, read-only, file handoff) before S1 code. Round 1 = REVISE; this is the revised artifact for round 2. Findings are answered by class with a recorded sweep each (below). The out-of-scope classes are repeated verbatim in the prompt.

## Peer-review resolution record (round 1 → this revision)

Each row: the finding class, the sweep's match identity (what was searched across the whole plan), the count found, and the resolution. Review: `docs/review/REVIEW-005-25OCT2026-plan-peer-round1-daybreak.md`.

| # | Finding (class) | Sweep match identity | Count | Resolution |
|---|---|---|---|---|
| BLOCKER | Relay target-fetch + upload violates §9 (D4.3/D5.2); loopback unreachable; not single-use | every mention of "relay", "lhost", "upload", "fetch-server", "GET/POST" in the plan | 1 design (touched D4.3, D4.4, D5.1, D5.2, Constraints, M8, S4/S5 tests) | **Relay removed entirely.** Output returns through the transport's own mechanism: impacket stdout for exec methods, nxc channel for RDP, operator paste-back for VNC. Exec methods carry a compact probe sized to the method ceiling, else refuse → winrm/ssh. §9 constraint strengthened to forbid any listener/fetch/upload. |
| D1.1 | Guard too broad (Unicode dash, `NtAdjustToken`, `STATUS_ACCOUNT_DISABLED`, blocks custom rules) | every suppression predicate in D1.1 | 4 predicates | Guard made **marker-only** + two overrides (custom-rule, built-in `miss_ok`); content negation (`NOT VULNERABLE`/`STATUS_*`) dropped; `miss_ok` set sized by a corpus sweep gate, dash-agnostic. |
| D1.2 | "Longest literal" is not a validity measure | the specificity rule in the shadow audit | 1 | Replaced with a frozen **expected rule-id + severity table**; overlaps allowlisted by `(sample, rule_id)`. Requires rule IDs (D1.0). |
| D1.4 | `(host,service)`+Jaccard can merge distinct ports/secrets | the dedup predicate | 1 (3 sub-conditions) | Added hard gates: port/protocol compatibility + **protected-token-set equality** + one-to-one; Jaccard now only decides prose. New non-merge tests. |
| D1.5 | `no_root_squash` dual severity across rule lists | grep `no_root_squash`/`squash`/`nfs` across all rule lists | 1 rule (only in `_BULK_RULES`, `high`; no default entry — reviewer premise corrected) | Bulk rule raised `high`→`critical` and added to `_DEFAULT_RULES`; `no_all_squash`/`insecure` added new; shadow audit runs the expectation table over **every composed rule order** so a per-list divergence is caught. |
| D2.1 | Second KB regex system drifts from grading | the KB lookup mechanism | 1 | KB keyed by **`rule_id` attached at classification** (D1.0); no re-match pass; coverage gate enumerates rule ids directly. |
| D2.2 | AD chain hints correlate before domain identity | every "chain" assertion on the AD page | 1 | S2 labels them "uncorrelated signals" with a caveat; confirmed chains wait for S3 `domains` identity. |
| D1.6 / D3.3 / D3.5 | `collect()->list` can't carry posture/domains; `aranum.py` copies only findings/report | the `collect()` signature + the auto-enum copy step | 2 | `collect()` returns a `Collection` dataclass (findings+posture+domains+diagnostics); both consumers use it; `aranum.py` copies `posture.json`. |
| D3.1 / D3.3 | Pipe protocol undefined escaping/framing/dup | the POSTURE line contract + parser | 1 | ASCII framing with `|`/CR/LF stripped from detail, strict anchored parser, unknown/dup/malformed quarantined as diagnostics. |
| D3.2 | ADSI contacts DC (contradicts localhost-only); missing forest level + LDAP signing/channel-binding | the D3.2 header + the AD check list | 1 header + 2 missing checks | Header corrected (host = localhost; AD = consent-gated DC query, bounded paging/timeouts); forest functional level + LDAP signing/channel-binding added (NA when not remotely readable). |
| D3.2 | Offline tests miss ADSI filters/conversions | the Windows-collector test list | 1 | Helpers factored out (filters, LargeInteger→age, COM→object) and unit-tested: disabled roastable excluded, DC excluded, recursive membership counted once, signed age correct, non-readable → NA. |
| D3.3 | Domain checks double-count per host | the posture finding emission for AD checks | 1 | Domain checks never become per-host findings; one canonical `(domain,check)` finding with `observed_from`; status lattice incl ERR. |
| D3.4 | Concatenating two PS advanced scripts breaks 5.1 | the Windows `--with-posture` delivery | 1 | Script-block wrapper `& {body1}; & {body2}`; combined payload parsed under 5.1 (dual-encoding+AST) before shipping. |
| D4.4 | `_AUTO_ENUM_VALUE_FLAGS` doesn't partition args | the `aranum run` arg forwarding | 1 | Explicit auto-enum vs local-enum arg partition table; final argv lists asserted by test. |
| D4.4 | Nested `<out>/{linux,windows}/<host>` breaks bulk detection | the mixed-layout collection path | 1 | Explicit mixed-tree collector: `_aranum_bulk_root` marker, service-walker exclude set, bulk walker handed the real root so evidence paths rebase. |
| D5.1 | Linux RDP not implemented | every claimed pathway in M8 and S5 | 1 | Linux-only-RDP falls through to ssh/assisted; **M8 drops the automated Linux-RDP pathway**. |
| D5.1 | Blind VNC keystrokes can't guarantee focus/output | the VNC pathway | 1 | VNC assisted-by-default; blind automation behind `--vnc-automate` + focus-check handshake, documented as no-capture. |
| S4 test | "raise body past ceiling" not a valid RED | the S4 new-gate RED proof | 1 | Gate retargeted to the **exec-ceiling builder**: lower a ceiling constant / enlarge the probe set → builder must refuse; relay counters retired with the relay. |

**Directionally endorsed by round 1 and kept:** endpoint folding + default-port attribution (D1.3), delegation to the proven bulk engines (D4.1), per-sprint baseline discipline.

### Round 2 → this revision

Round 2 (`REVIEW` verdict, saved to `docs/review/REVIEW-006-25OCT2026-plan-peer-round2-daybreak.md`) confirmed the blocker **RESOLVED** and 13 of 17 items resolved. Four remained; all are patched here (no structural redesign; the one structural fix — the relay — was already done in round 1):

| # | Finding (class) | Sweep match identity | Count | Resolution |
|---|---|---|---|---|
| D1.0 | **NEW-ISSUE:** 4-field `Rule` namedtuple breaks existing 2-tuple unpacking | grep `for pat, sev in`, `, sev in`, `[0]`/`[1]` over report.py/report-dashboard.py | 3 sites (`_prefilter_for` 470/474, `_classify` 501, `_load_rules` 520) | Explicit same-commit migration of every enumerated site to attribute access; a guard test asserts every rule is a `Rule` with a unique `rule_id` and that `_classify` returns a `Rule`, so a stray bare tuple fails CI. |
| D3.2 | `-AdChecks` not threaded through delivery; posture can't enable it | grep `-AdChecks`/`--ad` across collector, bulk engines, wrapper, CLI | 1 chain (4 layers) | `--ad`/`-AdChecks` threaded `aranum run/local` → `local-enum.py` → `bulk-enum-windows.py --with-posture` → script-block wrapper (`& {body} -AdChecks`); off by default; Linux AD-membership is localhost-only so ungated; test asserts NA-when-absent. |
| D3.3 | `observed_from:[host]` loses per-observer status/detail; ERR/NA ordering undefined | the domains rollup model in D3.3 | 1 | `observed_from` is a list of `{host,status,detail}` records; full lattice defined (determined `FAIL>WARN>PASS` beats undetermined; no-determined → ERR-if-any-else-NA; conflicts annotated); parser tests cover PASS+ERR, PASS+FAIL, ERR+NA. |
| D4.4 | Mixed-tree output model still binary bulk/non-bulk; `mode`/`per_host`/inventory unspecified | grep `"mode"`, `per_host`, `_is_bulk_enum` in report.py + build_index | 1 | Ternary `mode="mixed"`: unified findings, merged `per_host`, union inventory, `summary.layout="mixed"` sub-counts, dashboard renders both; non-mixed trees unchanged; tests assert all three cases. |

### Round 3 → this revision (final review round; 3-round cap reached)

Round 3 (`REVIEW-007-...`) confirmed item 2 (`--ad` threading) **RESOLVED**, items 1 and 3 **PARTIALLY RESOLVED**, and raised one NEW-ISSUE on item 4. All three residuals are low-severity *precision* corrections — a missed unpack site, a missing enum value in a lattice, a dataclass field-name mismatch — with no open design question. They are fixed here. Per the dev-methodology **3-round patch cap**, no fourth review round is opened; the one *recurring* class (the rule-unpack migration, swept too narrowly in round 2) is closed with a **structural guarantee** rather than another edge-case patch, which is the cap's prescribed escalation.

| # | Finding (class) | Sweep match identity | Count | Resolution |
|---|---|---|---|---|
| 1 | Migration sweep missed a test-file 2-tuple unpack | `grep -rnE "for .*, *x in .*(RULES|rules)|, sev in"` over report.py, report-dashboard.py **and `tests/`** | 1 (`test_structured_findings.py:109`, `_brute`) | Site migrated; sweep scope widened to `tests/`; **structural backstop added** — a 2-tuple unpack of a 4-field `Rule` raises at runtime, so the Phase-7(a) all-green-suite gate *proves* completeness; grep only locates edits. |
| 3 | Lattice omitted `INFO` (emitted by the trusts check) → not total | the determined/undetermined partition in D3.3 | 1 | `INFO` added as the least-severe *determined* status: `FAIL > WARN > PASS > INFO`; undetermined `{ERR,NA}` never outrank determined; ordering now total over all six. |
| 4 | **NEW:** dashboard consumes `collect().per_host` but `Collection` lacked it; `build_index` kept a binary bulk branch | the `Collection` dataclass fields vs D4.4 dashboard refs | 1 | `Collection` gains `per_host`, `mode`, `layout`; `build_index` rewritten to render from the `Collection` (no own bulk detection). Dashboard refs now backed by real fields. |

**Phase-5 gate: GREEN.** Rationale recorded here: the §9 blocker and every high finding are resolved across rounds 1–3; the three round-3 residuals are low-severity precision fixes now applied, with no unresolved design question; and the single recurring class is closed by a structural guarantee (green-suite gate), which the methodology prescribes at the round-3 boundary instead of a fourth patch round. Authorizer: planning model, reasoning above. Implementation (S1) may begin.
