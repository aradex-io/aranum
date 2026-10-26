# TEST CARD — S4 `--local` access layer

- **Date:** 26 OCT 2026
- **Sprint:** S4 (`dev/local-access`)
- **Base SHA (baseline):** `41860c8` (S3 merge + its SHA-record commit = `main` tip)
- **Head:** six commits on `dev/local-access` (`8169716`…`e5b0a6b`)
- **Suite command:** `python3 -m pytest aranumtoolkit/tests -v`
- **Manifest:** per-test `<nodeid> STATUS` extracted from the `-v` log with a
  spacing-tolerant regex (`\s+STATUS\s+\[\s*\d+%\]`), rebased to `STATUS nodeid`,
  sorted. (The `41860c8` baseline log additionally carried an `-rA` summary block
  and `-rs` skip-summary lines; those are a logging-format difference, not test
  identities. The compare below is by nodeid and is apples-to-apples.)
- **Raw output:** `docs/test-strategy/raw/s4-base-41860c8/{pytest.log,manifest.txt,m8-baseline.txt}`
  (baseline), `docs/test-strategy/raw/s4-head/{pytest.log,manifest.txt,m8-after.txt}` (head).

## (a) No regression — per-test manifest diff

| | Baseline `41860c8` | Head |
|---|---|---|
| passed | 529 | 576 |
| failed | 0 | 0 |
| skipped | 5 | 5 (identical signatures) |
| subtests | 100 | 100 |

- **Baseline-passing nodeids that do not pass at head:** NONE (authoritative
  nodeid compare of `manifest.txt`: 0 regressions, 0 missing).
- **New test identities:** 47, all in `aranumtoolkit/tests/test_local_access.py`.
  `576 − 529 = +47` matches exactly; no baseline identity was renamed away.
- **Skip signatures identical:** 4× pywinrm not installed, 1× recce not importable.
- **Two false alarms chased to ground and dismissed** (recorded so the next
  reader does not re-chase them): `test_r2_protocol_transports` parametrized mail
  ids contain **spaces** (`…[enum-imap.sh-993-a1 CAPABILITY-a1 LOGIN-…]`) and
  truncate under a naive `\S+`; and `test_status_ok` / `TestHelp::test_root_help`
  print `PASSED  [` with **two** spaces (pytest right-aligns the percent column).
  All four PASS at base and head — verified by direct grep of both `-v` logs.

## (b) New behavior proven (specific assertions, real inputs)

`aranumtoolkit/tests/test_local_access.py`, 47 hermetic tests (no Windows host, no
live exec target — ADR-007 "what this does not validate"):

- **Target parsing:** `[user@]host[:port] [os=] [via=] [user=]` → exact `HostSpec`
  fields; `via=` set; explicit `user=` wins over `user@`; comments/blanks skipped;
  bad os / unknown pathway / unknown key / out-of-range port → `UsageError`;
  file round-trip preserves order + os.
- **OS inference:** product-first (`Microsoft Windows RPC` on :22 ⇒ windows),
  ssh ⇒ linux, winrm port ⇒ windows, **Samba on 445 ⇒ unknown** (product overrides
  the Windows-signal port), no-signal ⇒ unknown.
- **Credentials:** `<host|*> <user> <secret>` → key (existing file) / nthash
  (`nt:`) / password; `resolve_cred` prefers the host-matching row over defaults.
- **Compact probe:** wmiexec carries ≥1 check within 8000; smbexec ≥ the core
  within 7800; **psexec refuses** (`ProbeTooLarge`); unknown method ⇒ `ValueError`
  (not `ProbeTooLarge`); `eligible_blocks` excludes every `$Context`-using block;
  each carried block is embedded **verbatim** and `checks ∪ omitted` partitions the
  full host-check id list (nothing invented, nothing silently lost); `encode_command`
  emits the `powershell.exe -NoProfile -NonInteractive -EncodedCommand` prefix;
  `annotate_omitted` writes `POSTURE|<id>|NA|…` lines.
- **plan_host PLAN contract:** linux→`ssh|full|bulk-enum-linux.sh`,
  windows→`winrm|full|bulk-enum-windows.py`, exec wmiexec→`compact|compact-probe|fits=yes`,
  psexec→a `fits=no refuse` row **and** a `psexec:probe-too-large` skip row with no
  pathway chosen; no-user ⇒ `skip:no-credentials`.
- **resolve_allowed consent gates:** `auto` ⇒ `{ssh,winrm}` (+`local` on `--self`,
  +`exec` only with `--win-exec` **and** `--use-smb-admin`); `exec` without either
  ⇒ `UsageError`; rdp/vnc transport or `--desktop-ok` ⇒ `UsageError` (S5).
- **Exec transport contract:** smbexec command goes to **stdin** ending in `exit`
  and is NOT on argv; wmiexec/psexec take the command positional; nthash ⇒
  `-hashes` on argv; `classify_exec` OK on probe markers, AUTH_FAIL on
  logon-failure, HOST_TIMEOUT on timeout; `find_exec_tool` ⇒ None when the CLI is
  absent (dependency-absent degradation).
- **`--ad` threading:** `run_windows_engine` includes `--ad` in the engine argv iff
  `args.ad` (captured via a stubbed `run_bounded`).
- **argv partitioning:** `run --local` routes local-only flags to the access layer,
  auto-only flags to run, and shared creds + `--dry-run` to both; `--local` consumed.
- **Mixed-tree collect:** a tree with one `_aranum_bulk_root` + one service dir ⇒
  `collect().mode == "mixed"`.

Supporting end-to-end evidence (manual, pre-commit): `aranum local --self -report`
wrote a bulk-enum tree (`mode=bulk-enum`, posture localhost 25P/1F/10W/4I/1NA/2ERR,
11 findings); a real mixed tree (self-scan bulk root + synthetic `ssh/192.0.2.50`
service dir) collected `mode=mixed` with both host populations and `per_host` scoped
to the bulk host; `aranum run <scan> --local` partitions as above.

## (c) New GATES shown able to go RED

One new acceptance gate (the compact-probe **exec-ceiling refusal**). The ordinary
assertions in (b) are not gates.

1. **Exec-ceiling gate** — `build_probe` must **refuse** (`ProbeTooLarge`) when even
   the core (helpers + `whoami /priv` + first check) exceeds the method's ceiling,
   and must never truncate.
   - Tests: `TestExecCeilingGate.test_tiny_ceiling_forces_refusal` (RED direction),
     `…test_huge_ceiling_carries_all_eligible_checks_no_refusal` (non-vacuous: a
     lifted ceiling carries **every** eligible check and strictly more than the
     default), and `TestCompactProbe.test_psexec_refuses_core_over_ceiling`
     (the shipped psexec ceiling of 4000 < the 7146-char core).
   - **RED proof (deliberate mutation, disposable sibling copy):** the base SHA has
     no `build_probe`, so the pre-fix-commit route is unavailable; instead the
     core-ceiling guard (`if core_chars > ceiling: raise ProbeTooLarge`) was
     neutered to `if False:` in `aranumtoolkit/network/local-enum-MUTANT.py` (placed
     beside the real scripts so its engine sibling resolves). Observed:
     `build_probe("psexec")` returned a probe (1 check, 7146 chars) and
     `build_probe("wmiexec", ceiling=100)` returned instead of raising — so both
     gate tests would FAIL. The mutant was deleted; the real file passes the three
     gate tests GREEN (`python3 -m unittest … TestExecCeilingGate …` ⇒ OK).
   - The falsifier is the correct one for a required-refusal property: removing the
     refusal (wrong-but-present: a probe that fits-by-ignoring-the-ceiling) makes
     the gate pass only if it has teeth; it did not, so the gate has teeth.

## Post-review round (REVIEW-011 — Daybreak Blue, Phase-6 diff review)

The Phase-6 independent diff review returned CHANGES-REQUESTED with 10 findings,
all confirmed real against the code (2 with a code-corrected remedy, 1 sub-item
backlogged as **S4-BL-01**). Fixes applied to `local-enum.py`, `report-dashboard.py`,
`aranum.py`; dispositions in `docs/review/REVIEW-011-26OCT2026-s4-local-access-peer.md`.

- **(a) No regression.** Suite re-run post-fix: **588 passed / 5 skipped / 100
  subtests** (`docs/test-strategy/raw/s4-head-postreview/`). Per-nodeid compare
  against the S4-head manifest: **0 previously-passing nodeids regressed**, **12
  new PASSED additions** (= the 12 fix tests), skip signatures identical.
- **(b) New behavior per fix.** 12 tests pin each fix: probe `[+]`/`[-]`
  privilege lines survive `clean_exec_output` (#1); winrm-primary supersedes the
  exec row and keeps `pathways` honest, exec-sole still runs (#2); windows engine
  subprocess cap = `host_timeout×group` and 0⇒unbounded (#3); `run_bounded`
  returns bound output on the `ProcessLookupError` exit race (#10); self-scan
  `COLLECTOR_ERR` on non-zero rc (#4); windows self-scan honors `--windows-script`
  (#8); skipped-host `_meta` written (#5); exec custom-port warning (#6); mixed
  host SMB card resolves service-dir evidence not bulk files (#7);
  `_partition_local` routes `--opt=value` (#9).
- **(c) Teeth proven.** The 3 source files were reverted to committed HEAD
  (pre-fix) and the 12 tests re-run: **10 fix-pinning assertions failed** (one per
  fix), the 2 regression-guard cases (exec-sole-runs, zero-timeout-unbounded)
  passed as designed. Fixed source restored ⇒ all 12 GREEN. No new *gate* was
  added (ordinary assertions), so Phase-7c is **N/A — no new gate** for this round;
  the only S4 gate (exec-ceiling refusal) is unchanged and already proven above.
- **Benefit unchanged.** M8 re-measured post-fix = **6/9** (full 4/4, compact 2/3,
  desktop 0/2), identical to S4. The compact checks use `--transport exec` (winrm
  excluded) so #2's supersede never fires there; the real collectors exit 0 on a
  complete run so #4 never flips `local` to `COLLECTOR_ERR`. Raw:
  `docs/test-strategy/raw/s4-head-postreview/m8-after.txt`.

## (b/c) inconclusive handling

Unit assertions are deterministic. The pwsh-dependent probe/collector *runtime*
parity is not asserted here (pwsh 7.x ≠ PS 5.1 registry semantics); the probe's
non-drift from the collector is instead enforced structurally (verbatim-block +
partition assertions above), which needs no interpreter.
