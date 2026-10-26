# TEST CARD — S3 host / domain posture

- **Date:** 26 OCT 2026
- **Sprint:** S3 (`dev/host-posture`)
- **Base SHA (baseline):** `7e62404` (S2 merge)
- **Head:** `7ff27c2` (after review rounds 1–3, the structural closure and its verify pass)
- **Suite command:** `python3 -m pytest aranumtoolkit/tests -v -rA` (collects the unittest.TestCase classes too)
- **Manifest:** lines matching `^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS) ` from the `-rA` summary, sorted
- **Raw output:** `docs/test-strategy/raw/s3-base-7e62404/{pytest.log,manifest.txt}` (baseline),
  `docs/test-strategy/raw/s3-head/{cmd.txt,pytest.log,manifest.txt}` (head)

## (a) No regression — per-test manifest diff

| | Baseline `7e62404` | Head `7ff27c2` |
|---|---|---|
| passed | 472 | 529 |
| failed | 0 | 0 |
| skipped | 5 | 5 (identical signatures) |

- **Baseline-passing tests that do not pass at head:** NONE
  (`comm -23 base_pass head_pass` is empty).
- **New test identities:** 57, all in `test_host_posture.py` and
  `test_dashboard_posture.py`. No baseline identity was renamed away.
- **Skip signatures are byte-identical:** 4× pywinrm not installed, plus recce not
  importable. Nothing was skipped away.
- Read directly from the raw `-rA` output (`raw/s3-head/pytest.log`, 211 s).
  Earlier heads were also compared the same way: `af45c48` 525/5 and `f309050`
  529/5, each with 0 baseline-pass losses.

## (b) New behavior proven (specific assertions, real inputs)

New test files: `aranumtoolkit/tests/test_host_posture.py` (collectors, parser,
gates, delivery) and `aranumtoolkit/tests/test_dashboard_posture.py`.

- **Linux collector:** `test_linux_collector_real_run` (real host, ≥30 well-formed
  lines, every id in the KB); `test_linux_collector_hermetic_specific_results`
  (fixture root → exact status+detail per check); pipe flattening in detail;
  `test_linux_collector_survives_concatenation_and_stdin` (appended to another
  script on one stdin, it runs and does not eat the rest of the stream).
- **Windows collector (pwsh, mocked providers):** off-Windows ⇒ exactly the 56 KB
  ids, all `NA`; mocked-registry host checks with exact status/detail (AutoLogon
  value never printed); AD helpers against fixture directory objects; the
  `-AdChecks` consent gate issues **no** LDAP query when off.
- **Fail-closed grading (review R2/R4 + round 2):** LDAP signing matrix
  (11 rows, incl. out-of-domain values ⇒ `ERR`); `Get-RegValue` absent ⇒ `$null`
  vs access-denied ⇒ throw; all-registry-denied ⇒ every registry-backed check
  `ERR`, the only `PASS` is the non-registry `WIN-PATCH-AGE`; LmCompatibilityLevel
  `7`/`-1` ⇒ `ERR`, `5/4/2` ⇒ `PASS/WARN/FAIL`.
  `Get-RegPolicy`: absent ⇒ `$null`, `2` and REG_SZ `' 2 '` ⇒ `2`, `3`/`-1`/`abc`
  against `@(0,1,2)` ⇒ throws with the domain message.
- **AD discovery (R5/R6):** RootDSE goes through the bounded searcher
  (`RDSE|Base|7|(objectClass=*)`); CLM-NA and RootDSE-ERR lines are domain-tagged
  and aggregate into `col.domains["corp.local"]` (15 checks).
- **Delivery (R1, D3.4):** Windows payload is literal `& { … }` blocks each closed
  by a blank line (exact framing pinned), parses under 5.1 rules, and **runs over
  stdin under FullLanguage and ConstrainedLanguage**; Linux `--with-posture`
  survives a stdin-reading script and its `exit`; the default payload is
  byte-unchanged.
- **5.1 compatibility (R9):** PSScriptAnalyzer 1.25, real 5.1 profiles
  (Win10 1809 / Server 2016), over the collector **and** the delivered `--ad`
  payload ⇒ 0 findings; missing PSSA with pwsh present ⇒ FAIL (not skip).
- **Parser/model:** FAIL/WARN ⇒ finding, PASS/INFO/NA ⇒ posture-only; malformed /
  unknown / duplicate / untagged-domain lines quarantined without marking the
  report partial; a domain check seen from two hosts ⇒ one canonical finding;
  domain status lattice (parametrized, incl. conflict flag).
- **Redaction (R3, NEW-1):** `--redact --sarif` ⇒ none of 7 leak strings in
  posture.json / findings.json / findings.sarif / report.md, quarantine line
  replaced by a length marker; uppercase MAC returned verbatim, mixed-case host
  ⇒ one token.
- **Dashboard (R7/R8/R10):** Posture page matrix + per-check rows; host posture
  card; AD page domain posture and correlation; domain findings link to
  `ad.html#domain-…` with a `domain` chip and never become a host page;
  malformed posture structures do not crash any renderer; hostile strings escaped
  on every generated page (content, attributes, observers, quarantine).

## (c) New GATES shown able to go RED

Five new gates; the ordinary assertions above are not gates.

1. **GATE 1 — posture-KB coverage** (`test_gate_every_collector_id_has_kb_test_and_fix`):
   every id either collector can emit has a KB check with ≥1 test and ≥1 fix, and
   the KB has no orphan check. Anti-vacuous floor (≥30 Linux / ≥35 Windows ids
   extracted).
   - **RED proof (in-test, required-presence ⇒ removal-style falsifier):**
     `test_gate_coverage_goes_red_on_an_unknown_id` injects `LIN-FAKE-CHECK` into a
     copy of the collector ⇒ `_uncovered == ["LIN-FAKE-CHECK"]`. GREEN on the
     shipped collector.
2. **GATE 2 — parser field-injection** (`test_gate_parser_keeps_injected_pipes_inside_detail`):
   `split("|", 3)` keeps `a|FAIL|b` inside detail; injected id/status shapes are
   rejected.
   - **RED proof (mutation):** split cap removed ⇒ the gate FAILS
     (`raw/s3-head/gate2-red.txt`, "At index 0 diff: 'a' != 'LIN-SSH-ROOTLOGIN'");
     restored ⇒ GREEN.
3. **PSSA 5.1-profile gate** (`test_windows_collector_and_payload_pass_pssa_51_profiles`):
   - **RED proof (in-test canary):** a 3-construct PS7-only canary (`??`,
     `Get-Content -AsByteStream`, `System.Text.Json`) must trip all three rules
     (`PSUseCompatibleSyntax/Commands/Types`) in the same run — a silent or
     misconfigured analyzer cannot pass. **Inconclusive state:** PSSA missing ⇒
     FAIL, never a skip-as-pass.
4. **CLM delivery gate** (`test_bulk_windows_payload_parses_under_51_rules_and_runs_over_stdin`):
   - **RED proof (pre-fix commit):** the `0f80c45` base64 payload under
     ConstrainedLanguage ⇒ `PRIV-RAN=0 POSTURE=0` ("Method invocation is supported
     only on core types"); `1904ba3` ⇒ `PRIV-RAN=1 POSTURE=56 AD=15`
     (`raw/s3-wip/r1-clm-red.txt`).

5. **Out-of-domain registry gate** (`test_gate_out_of_domain_registry_values_never_grade_pass[99|-1|'x']`,
   from the REVIEW-010 round-3 structural closure).
   - **How it works:** every registry read the host checks make is discovered at
     run time (≥ 39, including fallback/second reads). Each read is then fuzzed
     **alone** while the others are absent, so an early throw cannot mask a later
     read.
   - **Per read it requires:** an ERR naming `<Name>=<value> … outside documented
     values`, and no PASS beyond the all-absent baseline. `UBR` is the one
     exemption: an informational build suffix that is never graded.
   - **Anti-vacuous:** 41 baseline lines, ≥ 39 reads discovered, and the HKCU AIE
     and WinRM `allow_unencrypted` second reads must be among them.
   - **RED proof, pre-fix commit:** at `af45c48` all three fuzz values FAIL
     (`raw/s3-wip/r4-gate-red.txt`). The earlier uniform-fuzz version of this gate
     was also RED there (`raw/s3-wip/r3-gate-red-at-af45c48.txt`), but the verify
     pass showed that version could mask later reads, so it was replaced.
   - **RED proof, mutations of the specific property (at `7ff27c2`):**
     - **M1:** the reviewer's counterexample, the HKCU AIE read unvalidated. 3/3
       RED on exactly that key.
     - **M2:** the PowerShellVersion domain reverted to "version-shaped". 3/3 RED.
     - **Restored:** 3/3 GREEN (`raw/s3-wip/r4-gate-red.txt`).
     - **Earlier mutation:** removing `Get-RegPolicy`'s domain check went RED
       (`raw/s3-wip/r3-gate-mutation.txt`).

Review-round tests failing at their pre-fix commit (cheapest valid RED):
`raw/s3-wip/round1-red-at-0f80c45.txt` (11 failed; the 2 passes — hostile-string
and PSSA — pin properties the base already had) and
`raw/s3-wip/r2-red-at-93ec61e.txt` (LDAP matrix, MAC, and exactly the two
out-of-domain LMCOMPAT cases), and `raw/s3-wip/r3-gate-red-at-af45c48.txt`
(`Get-RegPolicy` unit test + the gate).

## Phase 8 — benefit (same harness)

`docs/test-strategy/harness/m7_posture_coverage.py` (v2), M7 = posture checks
per OS with a KB test + remediation:

| | Baseline `7e62404` | Head `7ff27c2` | Target | Provenance |
|---|---|---|---|---|
| Linux | 0 | **43** | ≥ 30 | measured (`raw/s3-base-7e62404/m7-baseline-v2.txt`, `raw/s3-head/m7-after-v2.txt`) |
| Windows (host + AD) | 0 | **56** | ≥ 35 | measured |
