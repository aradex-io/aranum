**PLAN-002 rev 2 review (Phase-5 gate, round 2)**

## Round-1 disposition check

All 16 dispositions are present in the rev 2 text (recorded, §13 vs §3–§11). One is incomplete:

- **R-9 partially resolved.** The baseline was captured (measured: `docs/test-strategy/raw/PLAN-002-A1-baseline-2493def-{pytest.txt,pytest.rc,smoke.txt}`, pytest `588 passed, 5 skipped, 100 subtests`, rc 0; smoke clean at v0.34.0; worktree `build/worktrees/plan002-base` at 2493def). But §7 says "Result: see §13" and §13 records nothing. Editorial; add the line.

R-2 and R-5 are resolved as written, but the rewritten text opens two new gaps (R-17, R-18 below). §3 line references re-verified (measured): `aranum.py:733,750,760`, `auto-enum.sh:884`, `importers.py:299`, `report.py:58,2834,2902`, `nmap-parse.py:613-626` unversioned, `interop/aranum.py:124-127,147-157,166-173,202-216`, `execution.py:93-97`. All hold.

## (a) New findings

**R-17 · HIGH · A1.3 — "first action deletes the manifest" destroys prior stage records on every launcher run.**
Every chain is separate processes: `aranum run … -report` is `subprocess.run("run")` then `subprocess.run("report")` (measured `aranum.py:731-736,749-766`). As written, the report stage deletes the manifest, then writes `stages{report}` only. Under P2b rules, inventory.json is now an "unlisted `*.json`" → diagnostic, not imported → AC-02 fails on the P3 path. The plan never says read-before-delete, nor what happens to carried-forward records whose files changed in between (the exact R-3 scenario: run 2 rewrites inventory.json then dies; `aranum report` later carries run 1's digest forward).
Fix: manifest module = load existing → snapshot stage records → delete file → at stage end re-digest every carried-forward `files[]` entry; mismatch ⇒ that stage `status: stale`, fold ⇒ `partial`. Report stage also lists the documents it **consumed** (inventory.json, run-state.json). Define fold when a stage record is absent (`unknown`, never `complete`). Add RED proof: two-process chain whose manifest lacks `stages.run` ⇒ A1.6 red.

**R-18 · HIGH · A3.2/A3.4 — no carrier for invocation facts between the enumeration stages and report.py.**
A3.4 stamps in report.py, which runs as its own process and reads only files. Network stage: creds are run-global env (`auto-enum.sh:374-375`), `nxc_creds_array` builds argv only (`_lib.sh:249-259`), run-state.json carries no user/domain/flag (`auto-enum.sh:799-803`). Local stage: `_meta.json` carries `host,user,port,transport` only (`local-enum.py:1014-1020,1091-1097`; read at `report.py:1936-1980`) — no domain, no `--local-auth`, no credential kind. A3.2 says "stamp" inside a bash function with no file output. Result: the emitter cannot produce `auth_context` for the `run` stage at all; FX-2 v2 would be hand-authored to something the live path never emits; AC-05 passes on fixture and is null live.
Fix: specify the carrier. Run stage: auto-enum writes `invocation{domain_arg,local_auth_flag,username_form,credential_kind,auth_scope_declared}` into run-state.json (additive, or bump to 2). Local stage: extend `_meta.json` with the same block (+ `domain`). report.py reads both. Add `uses_credentials: bool` to `dispatchers.json` (A1.5; measured 16/74 dispatchers reference `ENUM_USER`) so A3.4 knows which findings are "authenticated". Moves one A1.5 field forward; order unchanged.

**R-19 · MEDIUM · A3.1 — `local ⇒ nxc --local-auth` covers 7 of 16 credential-consuming dispatchers.**
Measured: 9 non-nxc consumers (couchdb, elastic, ftp, imap, kerberos, mongo, pop3, rabbitmq, ssh); `enum-ldap.sh` gates every authenticated check on `ENUM_DOMAIN` (`:55,77,100,126,155`) and binds `user@domain`; local-enum exec uses impacket `DOM/user` (`:824-829`). Declared `local` with no `-d` therefore silently drops all LDAP/Kerberos/BloodHound/certipy coverage and leaves impacket semantics undefined; `machine ⇒ account$` says nothing about `-d`.
Fix: A3.1 ships a per-tool-family mapping table (nxc, impacket, ldapsearch, ssh) and "declared local ⇒ domain-only checks are skipped with a `coverage` reason", so lossless coverage reporting survives (AC-04).

**R-20 · MEDIUM · A2.4/AC-08 — `logical_id` collides within a single run.**
Measured on `tests/fixtures/bulk-enum` (25 findings): 1 of 24 `(rule_id,host,port,service)` groups holds 2 findings (rule `bse-impersonate-…` on `win-svc-imperson`); posture findings have no port and one rule matches several lines. AC-08 "each linked to exactly one prior" fails on the plan's own fixture class.
Fix: include `user|artifact_id` (already `finding_id` inputs, `report.py:1440-1444`) and redefine AC-08 as group-level: every new finding has ≥1 prior with the same `logical_id`, and per-group counts match.

**R-21 · MEDIUM · A1.3/P2b — `run_id` undefined for `local` and `report` stages; FX-2L has no run-state.json.**
Measured: no `run_id` anywhere in local-enum.py; report.py reads it only from run-state.json (`:1710-1714`). P2b "run_id agreement with run-state" has no counterpart for local-only bundles; purplesploit then keys identity on `bundle:<fingerprint>` which hashes every document incl. `generated_utc` (`interop/aranum.py:147,156`; `report.py:2836`) ⇒ every re-render yields all-new observation ids. And `len(run_ids)>1 ⇒ raise` (`interop/aranum.py:148-150`) kills the import if a stage mints a different id.
Fix: run stage mints (existing `RUN_ID`); local mints only when neither manifest nor run-state exists; report inherits (manifest > run-state) and never mints; findings/posture/manifest all carry it; P2b occurrence = `manifest.run_id`; run-state.json optional when `stages.run` is absent.

**R-22 · MEDIUM · P1/AC-19 — the pre-P1 persisted observation set is never captured.** AC-19 needs serialized outputs of every importer at P1's base, written before the first edit. Add as P1 step 0 (fixture dir + recorded digest).

**R-23 · LOW · A1.4 — composite exit code undefined.** report.py returns 1 on partial diagnostics (`:2917`) and `_run_report_chain` returns it (`aranum.py:663-665`); "final exit still 4" needs a precedence rule and confirmation the dashboard still runs.

**R-24 · LOW · A1.3 — manifest `kb{version,…}` cites a KB version that exists only after A2.2.** Use `kb{digest}` in A1, add `aranum_version` in A2.

**R-25 · LOW · A3.3/AC-05 — "stamped where authenticated" vs "no credential ⇒ null-session".** Define: stamp for every check from a `uses_credentials` dispatcher (incl. null-session attempts); null for pure banner/version probes.

Not raised: sprint order/dependency graph is sound (A1 ∥ P1→P2a; P2b after A3+P1; P3 after P2b). AC-01..19 are decidable except AC-08 (R-20). Completion manifest closes the blocker **only with R-17 and R-21**. A3's scope rule is truthful; it is unimplementable without R-18/R-19.

## (b) Hypotheses

| # | Hypothesis | Falsifier | Cheapest test |
|---|---|---|---|
| H6 | A1.3 as written yields a manifest without `stages.run` after `aranum run -report` | manifest lists inventory.json under `stages.run` | desk-check the manifest module draft; then run FX-1 chain, `jq .stages` |
| H7 | A live credentialed `aranum run` leaves zero credential/domain facts in the outdir | any outdir file contains the `-u`/`-d` values | `--dry-run -u x -d Y` on `all-services.xml`, `grep -r` outdir |
| H8 | Declared-local scope drops 100% of LDAP authenticated checks | `ldapsearch -D` runs with `ENUM_DOMAIN` empty | `bash -x enum-ldap.sh` with `ENUM_USER` set, `ENUM_DOMAIN` unset |
| H9 | Two `aranum report` runs over one local-only tree produce disjoint purplesploit ids | ids identical | report twice on `/tmp` copy, compare `_digest` inputs |
| H10 | `logical_id` collisions also occur on network (ported) findings | 0 groups >1 on a network raw tree | repeat the R-20 script on a `run` fixture tree |

## (c) Verdict

**RED** — unresolved HIGH: **R-17, R-18**. No blockers. R-19..R-22 should land in the same patch round; R-9 needs its result line; R-23..R-25 editorial.
