# Phase R2 implementation report — endpoint, transport, and host detection

**Date:** 2026-09-14
**Branch:** `codex/aranum-r2-14sep2026`
**Scope:** S2-05 through S2-22 plus V-01 (19 findings)
**Implementation status:** all 19 findings implemented with offline regressions; no
live estate or Bambu device was probed.

## Finding ledger

| ID | Status | Implementation and evidence |
|---|---|---|
| S2-05 | Complete | `bulk-enum-windows.py` distinguishes explicit endpoint ports and passes a classified nondefault port to the OpenSSH transport. Regression covers port 2222. |
| S2-06 | Complete | `enum-ssh.sh` stores banners, ssh-audit, auth-method, nxc, and CVE evidence per port; user-qualified evidence uses a reversible hex encoding of the exact username bytes. Contradictory two-port evidence stays isolated, and `CORP\alice` cannot collide with `CORP_alice`. |
| S2-07 | Complete | `enum-ldap.sh` retains every discovered LDAP/GC endpoint and selects `ldap://` or implicit `ldaps://` for 389/636/3268/3269. Nxc and all LDAP evidence are port-qualified. |
| S2-08 | Complete | IMAP/POP exchange helpers preserve stdin through OpenSSL and credentials are tested on 993/995 as well as plaintext endpoints. Offline OpenSSL transcripts prove both paths. |
| S2-09 | Complete | POP3 success is decided by the status response corresponding to `PASS`, not an unrelated greeting, USER, STAT, or QUIT response. Positive and rejected-PASS transcripts are covered. |
| S2-10 | Complete | SMTP 465 and FTP 990 use implicit TLS; FTP URLs use `ftps://` and Nmap follows the exact discovered port instead of fixed port 21. Argument/stdin shims cover 465 and 990. |
| S2-11 | Complete | `nmap-parse.py` routes X11 only on compatible observed service identity; `ssl` and `unknown` on port 6000 are negative controls. |
| S2-12 | Complete | Added a conservative Bambu/BBL host correlation requiring explicit identity plus compatible protocol or identity evidence on another distinct endpoint, recorded as `confidence=likely`, `severity=low`. Signals are grouped by endpoint, so two regex matches or duplicate records from one endpoint count only once; common/unidentified ports never count as evidence. Its dispatcher only renders prior parser evidence and contains no live network primitive. Exact combined-product, duplicate-endpoint, and identity-plus-unidentified-tuple controls remain unclassified. |
| S2-13 | Complete | APT file enumeration no longer increments inside a lost pipeline subshell; writable `APT_CONFIG` increments the same counter. Independent, combined, and clean fixtures prove non-contradictory output. |
| S2-14 | Complete | All three Windows service paths parse quoted executables correctly; unquoted checks construct the loader's progressive `.exe` candidates and test candidate parents. PowerShell fixtures cover both shapes. |
| S2-15 | Complete | `Invoke-PrivEscEnum.ps1` now intentionally uses a regex credential pattern instead of `-SimpleMatch` with regex syntax. |
| S2-16 | Complete | SYSVOL construction interpolates a joined DNS/NetBIOS domain and explicitly skips the branch when no domain is available. |
| S2-17 | Complete | ADCS ESC1 and ESC2 now require an effective low-privilege enrollment allow; administrator-only and applicable-deny fixtures are negative. |
| S2-18 | Complete | Windows guidance now claims local ADSI coverage only for ESC1, ESC2, and ESC4 and identifies Certipy as the broader follow-up. |
| S2-19 | Complete | All seven OT dispatchers use one shared bounded worker scheduler. `OT_MAX_PARALLEL` enforces the ceiling and a locked global 500 ms start gate uses state shared by every protocol dispatcher process. Cross-process regression proves the first target in a new protocol group cannot reset/bypass the floor. If `flock` is unavailable, the scheduler warns and forces one worker rather than permitting concurrent fallback sleeps; a real PATH-without-flock regression executes all four targets and measures every start interval at 500 ms or greater. |
| S2-20 | Complete | SSH keys are annotated and filtered for actual noninteractive probeability before `--max-per-user` is consumed; invalid and encrypted/unlocked originals stay inventory-only. |
| S2-21 | Complete | `ssh-key-triage` emits versioned `aranum.authorized-ssh-pair/v1` JSONL with key/user/host/port. `bulk-enum-linux.sh --authorized-pairs` validates and consumes every row directly. Artifact directories, `.done` resume markers, metadata, and summary rows use a SHA-256 identity over the complete key/user/host/port tuple. Metadata is atomically written by Python's JSON encoder, including backslashes, quotes, and control-character escaping. `report.py` resolves opaque pair directories through validated canonical user/host/port/key metadata and emits partial/error state plus rc=1 for malformed metadata. The real end-to-end regression covers IPv6, `CORP\alice`, quoted/backslashed key paths, report identity, and duplicate-row de-duplication. |
| S2-22 | Complete | The SSH key probe executor uses one thread-safe global start-rate limiter; a fake clock proves starts at 0.0, 0.5, 1.0, and 1.5 seconds under one timeline. |
| V-01 | Complete | Linux bulk, key-triage, SSH triage auth probe, and Windows OpenSSH builders pass bare IPv6 destinations. Brackets remain only in target-file/URL forms that require them. |

## Files changed

- Contract and operator docs: `README.md`, `CHANGELOG.md`,
  `aranumtoolkit/docs/ADR-006-28JUL2026-bulk-enum-overhaul.md`,
  `wiki/bambu.md`, `wiki/windows.md`, `standalones/ot/README.md`.
- SSH/bulk: `aranumtoolkit/network/bulk-enum-linux.sh`,
  `bulk-enum-windows.py`, `enum-ssh.sh`, `ssh-key-triage.py`, `ssh-triage.sh`.
- Protocol/correlation: `aranumtoolkit/network/enum-bambu.sh`, `enum-ftp.sh`,
  `enum-imap.sh`, `enum-ldap.sh`, `enum-pop3.sh`, `enum-smtp.sh`,
  `nmap-parse.py`, `report.py`, `service-metadata.json`.
- Host predicates: `standalones/linux/apt-source-check.sh`,
  `standalones/windows/Get-ADCSMisconfig.ps1`, `Get-ServiceMisconfig.ps1`,
  `Get-UnquotedServices.ps1`, `Invoke-PrivEscEnum.ps1`.
- OT scheduler: `standalones/ot/_lib.sh`, `ot-enum.sh`, and all seven `enum-{bacnet,dnp3,enip,iec104,modbus,opcua,s7}.sh` dispatchers.
- Tests: `aranumtoolkit/tests/test_bulk_enum_linux_auth.py`,
  `test_bulk_enum_report.py`, `test_bulk_enum_windows_transports.py`, `test_nmap_parse.py`,
  `test_ssh_key_triage.py`, plus new `test_r2_protocol_transports.py` and
  `test_r2_host_predicates.py`.

## Verification

### REQUEST_CHANGES correction evidence

- S2-12 independent-evidence correction:
  `python3 -m pytest aranumtoolkit/tests/test_nmap_parse.py::TestBoundedBambuCorrelation -q`
  — **6 passed**. The exact lone `990/ftps` record whose product is
  `Bambu Lab BBL-P003 FTP Server` remains unclassified, as do duplicate records
  from one endpoint and identity plus unidentified characteristic ports. Valid
  positives require compatible protocol or identity evidence on another
  distinct endpoint.
- S2-19 no-`flock` release correction:
  `python3 -m pytest aranumtoolkit/tests/test_r2_host_predicates.py::test_ot_scheduler_without_flock_forces_serial_and_preserves_start_floor -q`
  — **1 passed in 1.69s**. Four callbacks ran with a PATH containing the
  scheduler dependencies but no `flock`; none were skipped and every monotonic
  start interval was at least 500,000,000 ns.
- Complete OT/host-predicate surface:
  `PYENV_VERSION=vr shellcheck -S warning -e SC1091,SC2046 standalones/ot/_lib.sh standalones/ot/ot-enum.sh standalones/ot/enum-bacnet.sh standalones/ot/enum-dnp3.sh standalones/ot/enum-enip.sh standalones/ot/enum-iec104.sh standalones/ot/enum-modbus.sh standalones/ot/enum-opcua.sh standalones/ot/enum-s7.sh && python3 -m pytest aranumtoolkit/tests/test_r2_host_predicates.py -q && git diff --check`
  — **ShellCheck and diff check passed; 11 tests passed in 3.33s**.

- Consolidated R2 regression surface:
  `python3 -m pytest aranumtoolkit/tests/test_ssh_key_triage.py aranumtoolkit/tests/test_bulk_enum_linux_auth.py aranumtoolkit/tests/test_bulk_enum_windows_transports.py aranumtoolkit/tests/test_nmap_parse.py aranumtoolkit/tests/test_bulk_enum_report.py aranumtoolkit/tests/test_structured_findings.py aranumtoolkit/tests/test_r2_protocol_transports.py aranumtoolkit/tests/test_r2_host_predicates.py -q`
  — **143 passed in 13.19s** after the S2-12 independent-evidence correction.

- S2-21 end-to-end re-verification:
  `python3 -m pytest aranumtoolkit/tests/test_bulk_enum_linux_auth.py::test_authorized_pairs_artifacts_resume_and_summary_are_identity_safe aranumtoolkit/tests/test_bulk_enum_report.py::TestCLIBulkMode::test_malformed_pair_metadata_is_reported_as_partial -q`
  — **2 passed in 2.50s**. This executes the real JSONL consumer, SSH shim,
  pair artifact/metadata writer, summary, and `report.py` output path.
- S2-21 focused reporting surface:
  `PYENV_VERSION=vr shellcheck -S warning -e SC1091,SC2046 aranumtoolkit/network/bulk-enum-linux.sh && python3 -m pytest aranumtoolkit/tests/test_bulk_enum_linux_auth.py aranumtoolkit/tests/test_bulk_enum_report.py aranumtoolkit/tests/test_structured_findings.py -q && git diff --check`
  — **ShellCheck and diff check passed; 32 tests passed in 7.26s**.

- Verifier-specific adversarial cases:
  `python3 -m pytest aranumtoolkit/tests/test_bulk_enum_linux_auth.py::test_authorized_pairs_artifacts_resume_and_summary_are_identity_safe aranumtoolkit/tests/test_r2_protocol_transports.py::test_ssh_user_evidence_tag_is_reversible_and_noncolliding aranumtoolkit/tests/test_r2_host_predicates.py::test_ot_rate_gate_persists_across_dispatcher_processes -q`
  — **3 passed in 0.60s**.
- Corrected affected surface plus changed-file ShellCheck:
  `PYENV_VERSION=vr shellcheck -S warning -e SC1091,SC2046 aranumtoolkit/network/bulk-enum-linux.sh aranumtoolkit/network/enum-ssh.sh standalones/ot/_lib.sh standalones/ot/ot-enum.sh && python3 -m pytest aranumtoolkit/tests/test_bulk_enum_linux_auth.py aranumtoolkit/tests/test_r2_protocol_transports.py aranumtoolkit/tests/test_r2_host_predicates.py -q`
  — **ShellCheck passed; 31 tests passed in 5.56s**. The command was run after
  adding exact authorized-pair row de-duplication; `bash -n` and
  `git diff --check` also passed in the same final gate.

- Focused pre-change-compatible regression set:
  `python3 -m pytest aranumtoolkit/tests/test_ssh_key_triage.py aranumtoolkit/tests/test_bulk_enum_linux_auth.py aranumtoolkit/tests/test_bulk_enum_windows_transports.py aranumtoolkit/tests/test_nmap_parse.py -q`
  — **99 passed in 4.41s**.
- R2 protocol/host predicate set after final additions:
  `python3 -m pytest aranumtoolkit/tests/test_r2_protocol_transports.py aranumtoolkit/tests/test_r2_host_predicates.py -q`
  — **17 passed in 2.40s**.
- Full unittest discovery:
  `python3 -m unittest discover -s aranumtoolkit/tests -p 'test_*.py' -v`
  — **288 tests passed, 5 skipped in 22.40s** after both release corrections.
- Full pytest discovery:
  `python3 -m pytest aranumtoolkit/tests/ -q`
  — **340 passed, 5 skipped, 68 subtests passed in 39.66s** after the S2-12
  independent-evidence and S2-19 no-`flock` corrections.
- Modified shell files:
  `PYENV_VERSION=vr shellcheck -S warning -e SC1091,SC2046 <all modified .sh>`
  — **pass, no diagnostics**.
- Bash/Python/JSON/PowerShell parsers: all modified Bash files passed `bash -n`,
  Python files passed `py_compile`, service metadata passed `json.tool`, and all
  four modified PowerShell files passed `System.Management.Automation.Language.Parser`.
- `python3 aranumtoolkit/tests/data_audit.py && git diff --check` — **pass**.

`bash aranumtoolkit/tests/smoke.sh` was rerun sequentially after both release corrections
with no competing FP/TP harness process present when the fixed local port bases
`19000/19010` were acquired: **375 passed, 0 failed, 1 skipped**. The skip is the
expected non-failing dirty-worktree notice for the uncommitted remediation, and
the final harness result was `no FPs, TP markers intact`.

Repository-wide `PYENV_VERSION=vr make lint` returned **rc=2** because ShellCheck
still reports six pre-existing warnings in unrelated files:
`standalones/linux/container-detect.sh` (SC2221/SC2222),
`standalones/linux/cron-enum.sh` (SC2010),
`standalones/redis/redis-rce-lua.sh` (two SC2034), and
`standalones/tomcat/tomcat-war-deploy.sh` (SC2206). The two warnings initially
reported in the R2 Linux bulk edit were corrected; the changed-file lint is clean.

## Limits and blockers

- No implementation blocker remains.
- No enterprise/live target was scanned. Mail/LDAP/FTP/SSH behaviors were
  exercised through local command/transcript shims only.
- No Bambu device was contacted. Correlation fixtures use established bounded
  signals and the dispatcher is evidence-only.
- PowerShell logic and ACL predicates were parser/fixture tested on Linux. Final
  environmental confidence for actual service ACL and ADCS inheritance/effective
  rights still requires a disposable domain-joined Windows lab with privileged
  and low-privileged controls; this is a validation limit, not unimplemented R2 work.
