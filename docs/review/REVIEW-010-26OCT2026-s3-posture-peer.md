# REVIEW-010 — S3 host/domain posture: KB authoring + independent diff review

**Date:** 26OCT2026
**Sprint:** S3 (host posture — Linux/Windows collectors, AD domain posture,
`POSTURE|…` contract, posture KB, dashboard Posture page) of PLAN-001-25OCT2026.
**Base SHA:** `7e62404` (S2 merge) **Heads reviewed:** `0f80c45` (round 1),
`93ec61e` (round 2), `af45c48` (round 3), `f309050` (verify-only, structural closure); final head `7ff27c2`
**Author model:** Opus (integration/judgment). **Reviewer / authoring peer:**
Daybreak Blue (`gpt-daybreak-blue-latest`, `xhigh`), Tier-2 cyber — independent
of the author model.

---

## Part A — Posture-KB authoring provenance (99 checks)

Recorded under `docs/review/s3-posture-kb/`:

- **Catalog (hand-authored):** `catalog.py` → `catalog.json`, 99 check ids
  (linux 43, windows-host 41, ad 15) with os/scope/group/category/title,
  `sev_fail`/`sev_warn`, and the grading **semantics** each collector implements.
  The catalog is the contract; the peer never chose ids or grading.
- **Guidance (delegated):** why/test/fix/refs drafted by Daybreak Blue in two
  batches, non-interactively via file-handoff (`--output-last-message`, exit
  sidecar): `P1-linux` (`in=43 out=43 problems=0`) and `P2-windows-ad`
  (`in=56 out=56 problems=0`), each checked by `validate_batch.py` (id set
  equality, schema, ≥1 test and ≥1 fix, category known).
- **Hand-authored addition after review:** AD-LDAP-SIGNING gained the channel-
  binding why/test/fix/ref (`build_kb.py` `ADDITIONS`, appended — never replacing
  the batch text) when R2 made the check grade `LdapEnforceChannelBinding`.
- **Fold:** `build_kb.py` writes the `checks` section of
  `network/finding-kb.json`; the 199 S2 `classes` are untouched (verified on
  every regeneration: "199 classes unchanged").
- **OPSEC (CLAUDE.md §9):** every `test` command is a read-only query
  (`reg query`, `Get-*`, `stat`, `grep`, LDAP read); `fix` commands remediate the
  owner's own host, which §9 permits; all are inert templates.

---

## Part B — Independent diff review (Phase-6 gate)

Round-1 bundle: the S3 code diff (`diffrev/s3-code.diff`), test diff
(`s3-tests.diff`), the plan's S3 section (`plan-s3.md`), and the declared
out-of-scope list (`prompt.md`). Raw output: `diffrev/daybreak-review.md`
(`blockers: 0, high: 4, medium: 4, low: 2`).

### Round 1 — 10 findings, answered by class

| Class | Findings | Disposition | Sweep (match identity) | Resolution |
|---|---|---|---|---|
| **A — transport** | R1 (high: Windows payload `[scriptblock]::Create(FromBase64String)` dies under ConstrainedLanguage → 0 lines) | ACCEPT | every payload builder in `bulk-enum-windows.py`; every method call on non-core types in the delivered text | literal `& { … }` blocks closed by a blank line (`_script_block`); RED/GREEN under CLM recorded (`raw/s3-wip/r1-clm-red.txt`: old 0 POSTURE lines, new 56 incl. 15 AD). |
| **B — fail-closed status** | R2 (high: LDAP signing PASS without channel binding), R4 (high: `Get-RegValue` swallowed access-denied → absent-default PASS) | ACCEPT | every `Get-RegValue` call site and every check that maps "absent" to PASS | `Get-RegValue` separates ItemNotFound (`$null`) from other failures (propagate → ERR); RDP shared read rethrown inside both checks; `Resolve-LdapSigningStatus` grades both policies. Tests: grading matrix, absent-vs-error, all-registry-denied ⇒ 0 registry PASS. |
| **C — redaction** | R3 (high: posture identities — domain/realm/observer/trusts/quarantine — leaked through `--redact`) | ACCEPT | every posture field reaching posture.json / findings.json / SARIF / report.md | `_posture_identities` seeds the redactor; case-insensitive host matching; quarantine lines replaced by a length marker. Test greps all four outputs for 7 leak strings. |
| **D — AD discovery** | R5 (medium: RootDSE read unbounded), R6 (medium: CLM-NA / RootDSE-ERR lines untagged → quarantined) | R5 ACCEPT-partial, R6 ACCEPT | every LDAP/ADSI entry point in the AD block; every early exit before the domain tag | RootDSE via the bounded `Invoke-LdapSearch` (Base scope, `-TimeoutSeconds` threaded). Fallback `domain=… observer=…` tag before both early exits. R5 residual: ADSI bind/locator is synchronous — no portable hard wall-clock bound was demonstrable on this host (LdapConnection.Timeout hung >90 s under libldap; runspace bound left a foreground thread; Start-Job hung). **Deferred to the S5 Windows lab.** |
| **E — dashboard** | R7 (medium: domain findings linked to non-existent host pages), R8 (medium: malformed posture model crashes renderers), R10 (low: hostile-string test too narrow) | ACCEPT | every finding→page link in `report-dashboard.py`; every posture field the renderers deref | `target_page`/`target_link` (domain → `ad.html#domain-…`); `_normalize_posture` at the model boundary; hostile-string test scans every generated page. |
| **F — 5.1 test fidelity** | R9 (low: PS7-token deny-list is not a 5.1 check) | ACCEPT | every 5.1-compat assertion in the S3 tests | PSScriptAnalyzer 1.25 with the real 5.1 profiles (Win10 1809, Server 2016) over the collector **and** the delivered `--ad` payload, with a 3-construct canary that must trip all three rules. |

Fix commits: `1904ba3` (collector, delivery, redaction, KB), `93ec61e`
(dashboard). RED at `0f80c45`: `raw/s3-wip/round1-red-at-0f80c45.txt` (11 failed
/ 2 passed — the two passes are the hostile-string and PSSA tests, which pass at
base by design: they pin properties the base already had).

### Round 2 — verify-only (`diffrev/daybreak-r2.md`: closed 7, partial 3, open 0, new 1)

| Item | Verdict | Disposition | Resolution |
|---|---|---|---|
| R2 | PARTIAL — `Resolve-LdapSigningStatus 2 3` / `2 -1` → PASS (fall-through) | ACCEPT; **class "enumerated policy with fall-through PASS"** | Sweep: all 50 `'PASS'` emissions in `Invoke-HostPosture.ps1`. Enumerated policies range-checked → ERR outside domain: LDAPServerIntegrity/LdapEnforceChannelBinding (0..2), **LmCompatibilityLevel (0..5, same defect)**. Boolean DWORDs (EnableLUA, NoLMHash, UseLogonCredential, …) keep Windows' nonzero-is-on semantics — not the class. `b678dc0`. |
| R5 | PARTIAL — ADSI bind/locator still synchronous | ACCEPT as deferred (unchanged) | Windows-lab verification in S5; recorded in the plan as N6. |
| R9 | PARTIAL — skip when PSSA absent; AST extraction absent | Split: **ACCEPT** the skip → now **FAIL** when pwsh is present and PSSA is not (`b678dc0`). **REJECT** AST extraction: helper tests dot-source the whole shipped collector, which defines the same functions (a superset of AST extraction) and exercises the exact file that ships; with `-LibraryOnly` the collector runs nothing at dot-source time (`Invoke-HostPosture.ps1` tail). |
| NEW-1 (low) | uppercase MAC case-folded by `--redact` | ACCEPT | `raw`/`key` split in `Redactor._sub`; uppercase-MAC + mixed-case-host unit test. `af45c48`. |
| R1, R3, R4, R6, R7, R8, R10 | CLOSED | — | — |

RED at `93ec61e` for the round-2 tests: `raw/s3-wip/r2-red-at-93ec61e.txt`
(LDAP matrix + MAC test fail; LMCOMPAT fails exactly the two out-of-domain
cases `[7-ERR]`, `[-1-ERR]`, the three in-domain cases pass).

### Round 3 — verify-only (final round)

`diffrev/daybreak-r3.md`: closed 2, partial 2, open 0, new 0.

| Item | Verdict | Disposition |
|---|---|---|
| NEW-1 | CLOSED (uppercase MAC verbatim, verified directly) | — |
| R9 | CLOSED — the reviewer agrees the rejection of AST extraction is sound ("stronger than testing extracted copies") | — |
| R5 | PARTIAL — no regression in range; ADSI bind still not wall-clock bounded | deferred to the S5 Windows lab (plan N6) |
| R2 | PARTIAL — **the class recurred after the round-2 sweep**: `LDAPClientIntegrity=3`, `ConsentPromptBehaviorAdmin=6`, LAPS `BackupDirectory=4`, unvalidated `RestrictAnonymous`, and negative-sense booleans set to `2` (`UseLogonCredential`, `EveryoneIncludesAnonymous`, `LocalAccountTokenFilterPolicy`, `AlwaysInstallElevated`) all graded PASS | **ESCALATED → structural** (below) |

**Escalation (protocol: a class that recurs after its sweep, at the end of round
3, gets a design change, not a fourth patch round).** The round-2 sweep judged
each `'PASS'` emission by hand and missed cases. That judgment was the defect,
so the fix removes it:

- **One validated reader.** `Get-RegPolicy -Path -Name -Allowed` returns `$null`
  when the value is absent, the int when it is in the documented value set, and
  otherwise throws, so the check grades ERR.
  - All **37** policy reads use it. The only remaining `Get-RegValue` reads are
    `UBR` (build number, informational) and `PowerShellVersion`.
  - `PowerShellVersion` must be version-shaped, and `AutoAdminLogon` must be
    `0`/`1`.
  - It is CLM-safe: regex + `[int64]` cast, no `[ref]`/`TryParse`.
- **A gate that decides the property for every check, current and future.**
  `test_gate_out_of_domain_registry_values_never_grade_pass[99|-1|'x']` sets
  every registry value out of domain and asserts that no registry-backed host
  check PASSes.
  - The only PASSes allowed are the non-registry `WIN-PATCH-AGE`, plus `WIN-PS-V2`
    for the numeric fuzz, where `99` is a real non-2.x version.
  - It also asserts that the 11 previously reproduced checks are ERR with the
    domain message, with an ERR floor of ≥ 25.
  - **RED at `af45c48`** for all three fuzz values: WIN-AIE, ANON-RESTRICT,
    AUTOLOGON, NOLMHASH, WDIGEST, LAPS, CACHEDLOGONS, … PASS
    (`raw/s3-wip/r3-gate-red-at-af45c48.txt`).
  - **Mutation at `f309050`** (domain check removed): `99`/`-1` go RED, and `'x'`
    stays GREEN because the numeric guard was kept, which is the expected
    selectivity. Restored ⇒ 3/3 GREEN (`raw/s3-wip/r3-gate-mutation.txt`).
- Commit: `f309050`.

### Verify-only pass on the structural closure

`diffrev/daybreak-r4-verify.md`: `verdict: PARTIAL, false_err: 0, new: 0`.

- **Domains (Q2): 0 false ERR.** The reviewer checked every `-Allowed` set
  against Microsoft documentation: ConsentPromptBehaviorAdmin 0–5, LAPS
  BackupDirectory 0–2, LmCompatibilityLevel 0–5, CachedLogonsCount 0–50,
  LdapEnforceChannelBinding 0–2, RunAsPPL, service Start 0–4, and the 0/1
  booleans.
- **New defects (Q4): none.** The reader is CLM-safe, and the 5.1 profiles stay
  clean.
- **Q1, PARTIAL: `PowerShellVersion=99` ⇒ PASS.** That read was version-shaped
  only, and the gate whitelisted it. **ACCEPT:** the `PowerShell\1` engine key is
  now validated against its documented values `{1.0, 2.0}`, and the whitelist is
  gone.
- **Q3, PARTIAL: the uniform fuzz did not decide the property.** An early
  validated read threw before a later read ran: AIE HKLM masked HKCU, and the same
  happened in the firewall/SMB1/WPAD/RDP/LAPS/WinRM fallbacks. **ACCEPT:**
  - The gate now **discovers every registry read at run time** (≥ 39, including
    the second/fallback reads) and **fuzzes each one alone** while every other read
    is absent.
  - Per read it requires an ERR naming `<Name>=<value> … outside documented
    values`, and no PASS beyond the all-absent baseline.
  - `UBR` is the one exemption: it is an informational build suffix and is never
    graded.
- **RED proofs** (`raw/s3-wip/r4-gate-red.txt`, at `7ff27c2`):
  - **M1**, the reviewer's own counterexample (HKCU AIE read unvalidated): 3/3 RED
    on exactly that key.
  - **M2**, the PS-V2 domain reverted to version-shaped: 3/3 RED.
  - **Restored:** 3/3 GREEN.
  - **Pre-fix `af45c48`:** 3/3 RED (first failing read: firewall policy
    `EnableFirewall`).
- **Commit:** `7ff27c2`.

These two follow-ups fix the gate's own decisiveness, found by the verify-only
pass. They are not a fourth patch round on product findings. They were closed by
evidence, with the reviewer's own counterexample now RED, so no further peer
round was opened.

**Out-of-scope (declared up front in every prompt):** tool-hardening/compliance
controls of aranum itself, deliberate constants, style, new features.

---

## Part C — Gate status

- **Phase-6 diff review:** GREEN.
  - 0 blocker/high open.
  - Round 1: 10 findings in 6 classes, all accepted.
  - Round 2: 1 new finding, fixed. The AST-extraction ask was rejected, and the
    reviewer agreed in round 3.
  - Round 3: the recurring class escalated to a structural guarantee. The
    verify-only pass found 0 false ERR and 0 new defects, and both of its
    gate-decisiveness points were fixed with RED proofs.
  - **Open by design:** R5 residual (ADSI bind/locator wall-clock bound), deferred
    to the S5 Windows lab as plan item N6.
- **Phase-7:**
  - (a) 0 regressions: all 472 baseline-PASSED still pass, 529/5/0 at `7ff27c2`,
    identical skips.
  - (b) new behavior proven.
  - (c) 5 gates shown RED and restored GREEN.
  - Details: `docs/test-strategy/cards/CARD-S3-26OCT2026-host-posture.md`.
- **Phase-8:** M7 went from 0/0 to 43/56 on the same v2 harness (targets ≥ 30 /
  ≥ 35). Both targets are met.
