**PLAN-002 rev 3 review (Phase-5 gate, round 3 — final)**

## Round-1 disposition check

All 16 round-1 items (R-1..R-16) are present in rev 3 text and resolve as recorded in §13 (checked against §3, §5, §6, §9 A1–A3, §10 P1/P2b, §11). Round-2 items R-17..R-25 are likewise all present (A1.3a-c, A1.4, A1.5, A2.4, A3.1–A3.4, P1 step 0). **None unresolved.** One residual on R-9: §7 line 142 still says "smoke: result pending at rev 3", but the artifact is complete — `PLAN-002-A1-baseline-2493def-smoke.txt` ends with PASS 407 / FAIL 0 / SKIP 0 (measured). Editorial, see R-33.

§3 re-verified this round (measured): `aranum.py:733,750,760`; `auto-enum.sh:15` (`set -uo pipefail`), `:188` RUN_ID, `:374-375`, `:782`, `:884`, no `trap`; `local-enum.py:280-301,737-740,824-829,1014-1020,1091-1097`, no `run_id`; `report.py:58,195-205,360-395,1440-1444,1710-1714,1936-1980,2667-2696,2834,2896-2917`; `_lib.sh:249-259`; 16/74 dispatchers reference `ENUM_USER`; `interop/aranum.py:124-127,135,147-157,166-173,202-216`; `importers.py:299`; `execution.py:104-108` (hash includes `attributes`). All hold. The `stages/` placement is safe for report.py's network collector: it only descends into host *subdirectories* (`report.py:1834`) and skips `.json` evidence (`:1865`); a bulk-layout run with a `stages/run.json` present produced identical output (measured, 25 findings, 0 diagnostics).

## (a) New findings (rev 3)

**R-26 · HIGH · A1.3b/A1.3c (plan :182-183) — stale detection is anchored only on the `run` record; local-only trees can fold `complete` with stale findings.**
Failure: local-only session. `aranum local` mints L1, `aranum local -report` writes `stages/report.json {complete, L1}`. Operator re-runs `aranum local` in the same session without `-report` — the launcher reuses the same raw dir (`aranum.py:197-201,781` default `-o`), and A1.3c says local mints a new id when no `stages/run.json` exists ⇒ `stages/local.json {complete, L2}`. Fold rule: stale = "run_id differs from the newest `run` record" — there is no run record ⇒ nothing is stale ⇒ `status: complete`. findings.json/posture.json carry L1 over L2 posture inputs; the manifest's own `run_id` is undefined when records disagree. P2b imports a stale findings set as complete under an ambiguous run_id — the local-only analogue of R-3, and AC-18 does not cover it (FX-4 is run-stage only). Evidence (measured): no `run_id` in `local-enum.py`; plan :182 fold text; plan :183 mint rule.
Fix: define an **anchor stage** = `run` if present else `local`; stale = any stage record whose `run_id` ≠ anchor's; `manifest.run_id` = anchor's; add **FX-4L** (local-only re-run without report) to A1.6/AC-18, RED proof: drop the anchor fallback ⇒ FX-4L folds complete.

**R-27 · MEDIUM · A1.4 (plan :184) — exit precedence returns 0 for `interrupted`/`failed` folds and treats a non-report rc 1 as "partial".**
Failure: `auto-enum.sh` runs under `set -u` (`:15`); an unbound-variable abort exits 1 with no `stage_end` ⇒ record `running` ⇒ fold `interrupted`. Precedence: rc 1 is in the exempt set, fold is not partial/stale ⇒ **launcher exits 0** on a crashed run. Evidence (measured): auto-enum's deliberate exits are only 0/2/3/4 (`:190,239,247,252,348,417,452,840,857,884-885`); `local-enum.py` usage errors exit 2 (`:105,1218`); only `report.py:2917` returns 1 meaningfully.
Fix: scope the rc-1 rule to the `report` stage; insert "fold ∈ {interrupted, failed, unknown} ⇒ first nonzero stage rc, else 1" before "else 0"; add a test (stub dispatcher that kills auto-enum ⇒ launcher rc ≠ 0).

**R-28 · MEDIUM · A1.3a (plan :181) — the bash `run` stage has eight exit paths after the natural `stage_begin` site and no mechanism to reach `stage_end`.**
Failure: parser failure `exit 3` (`auto-enum.sh:417`) or planner failure (`:239`) leave `status: running` ⇒ manifest `interrupted`; P3 ("completion = manifest status") reports a deterministic failure as an interruption. Worse, `--plan-only` succeeds with `exit 0` at `:247` and leaves `running` permanently, so a plan-only outdir reads `interrupted` until overwritten. Evidence (measured): exits listed above; RUN_ID minted at `:188`; no `trap` anywhere.
Fix: A1.3a specifies `trap 'stage_end run "$?"' EXIT` immediately after `stage_begin` (covers every `exit N`; SIGKILL still leaves `running` ⇒ interrupted, which is correct); plan-only ⇒ `complete` with `produced[] = plan.json, queue.jsonl, guidance.json` (these are root `*.json` files — unlisted they trip P2b's diagnostic). Note §3's "no trap" row is a current fact, not a design constraint.

**R-29 · MEDIUM · A3.4 (plan :239) / §4 — `local_host` and `domain` have no per-scope population rule; the spec (TURN 7) and the A3.5 tests pull in opposite directions.**
Evidence (recorded): interop-channel `:895-897` — `domain` set when scope ∈ {domain, machine}; `local_host` set when scope = local. Plan A3.4 lists both fields on every credentialed finding with no rule; A3.5 (:240) expects `local_host` populated under **null** scope. Failure: declared `--auth-scope domain -d CORP -u svc` over 10 hosts — if the emitter fills `local_host` = target host by default (the only reading that satisfies the null-scope test), P1's identity `(username, scope, domain, local_host)` creates 10 credential records for one domain account on import and P4's effective-on-host derivation has nothing to join. If instead `local_host` is null under null scope, the A3.5 test fails. Also `account_ref` is unresolvable for offline imports (aranum emits `account_label`; no request to copy from).
Fix: A3.4 rule — `local_host` = target host iff scope ∈ {local, null}, else null; `domain` = declared domain iff scope ∈ {domain, machine}, else null (the `-d` value lives only in `invocation.domain_arg`); P1 treats null scope as "never merge" (per-host records) and AC-14/AC-16 say so; P2b resolves `account_ref` by identity-tuple match against the stores, else null; P3 copies the request's `account_ref`.

**R-30 · MEDIUM · A3.1 (plan :236) — "domain-only checks skipped with a coverage reason" has no carrier at check granularity.**
Evidence (measured): coverage rows are per endpoint from per-dispatcher `record_service_result {status, rc, reason}` (`auto-enum.sh:192-207`, `report.py:1760-1806`); `enum-ldap.sh` runs anonymous checks unconditionally and gates authenticated ones on `ENUM_DOMAIN` (`:55,77,85`). Under declared local the dispatcher runs its anonymous half, exits 0 ⇒ `assessed_clean`/`confirmed`; the skipped authenticated half is invisible, so the "AC-04 stays lossless" claim is not implementable as written.
Fix: choose and state the carrier: (a) dispatcher writes `<svc>/<ip>/_skipped-checks.json [{check, reason}]`, report.py appends `skipped_checks[]` to the coverage row and A1.2's schema gains it; or (b) granularity = whole dispatcher (ldap/kerberos marked `skipped` via `record_service_result`), accepting loss of anonymous LDAP coverage under declared local. (a) is the lossless one; H8/A3.5 must assert on that carrier.

**R-31 · LOW · A3.1 — declared `domain`/`machine` without `-d` is unspecified.** nxc `-d D` / impacket `D/user` need D; today argv would be unchanged and the stamp `scope: domain, domain: null`, defeating the identity tuple. Fix: usage error rc 2 (`--auth-scope domain|machine requires -d`), test in A3.5.

**R-32 · LOW · A3.4 vs R-25 wording.** `enum-smb.sh` emits null-session rpcclient output (`:91-97`) and credentialed output in one dispatcher; "every finding from a `uses_credentials` dispatcher" and "null for pure banner probes" conflict inside it. State: dispatcher-level wins; "pure probes" = `uses_credentials: false` dispatchers.

**R-33 · LOW · §7 (:142).** Replace "smoke: result pending" with the measured PASS 407 / FAIL 0 / SKIP 0.

**R-34 · LOW · A2.4 (:218).** `_structured_finding` defaults `rule_id=""` (`report.py:365`); ungraded network lines for one endpoint collapse to one `logical_id`. Bulk fixture: 0 empty rule_ids, 1 collision group of 2 (measured, consistent with R-20). Fix: when `rule_id` is empty, substitute `evidence_identity`; H10 reports both counts.

Not raised: sprint order/dependency graph is sound (A1.5 `uses_credentials`/`tool_family` precede A3; P2b after A3+P1; P3 after P2b). AC-01..19 are decidable and mapped to the right sprints. Baselines and deferrals are real (pytest rc 0 / 588 passed; smoke complete). RED-proof obligations are concrete and falsifiable. The derived-manifest design closes the cross-process class (R-2/R-3/R-17) for run-anchored trees; R-26 is the one remaining path to a false `complete`.

## (b) Hypotheses

| # | Hypothesis | Falsifier | Cheapest test |
|---|---|---|---|
| H11 | Re-running `aranum local` in one session without `-report` yields a manifest folding `complete` while findings.json carries the prior run_id | fold is stale/partial, or manifest.run_id == findings.run_id | desk-check A1.3b fold against the two-record tree; after A1, run `aranum local` twice, `jq .status,.run_id` on both files |
| H12 | An unbound variable in auto-enum exits 1 with no stage_end and the A1.4 rule yields launcher rc 0 | rc ≠ 1, or launcher rc ≠ 0 | `bash -uo pipefail -c ': "$NOPE"'; echo $?` (1 confirms bash); then apply the A1.4 rule on paper to fold=interrupted |
| H13 | `auto-enum.sh --plan-only` leaves `stages/run.json` at `running` under the A1.3a draft | record reads complete/skipped | plan-only on `all-services.xml`, `cat stages/run.json` |
| H14 | `enum-ldap.sh` with `ENUM_USER` set and `ENUM_DOMAIN` unset exits 0 with reason "dispatcher completed", hiding the skipped auth checks | nonzero rc or a reason naming skipped checks | `auto-enum.sh --only ldap -u x -p y` on an unroutable target; `cat .run-state-*/ldap.json` |
| H15 | A1.2 `bundle-manifest` validation passes a bundle whose `files[]` omits `plan.json/guidance.json` while P2b flags them as unlisted root JSON | P2b ignores non-contract root files | after A1, plan-only then `aranum report`; run the P2a harness and count diagnostics |

## (c) Verdict

**RED** — unresolved HIGH: **R-26**. No blockers. R-27..R-30 should land in the same patch; R-31..R-34 are editorial/low. Per §11 this is the third round: R-26 needs a one-line fold-rule patch (anchor stage) plus FX-4L, then escalate to the owner with the rest.
