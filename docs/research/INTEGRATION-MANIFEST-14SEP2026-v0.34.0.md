# Integration manifest — aranum v0.34.0 candidate — 14SEP2026

## Purpose

This manifest records the integration of all three comprehensive-quality remediation components onto a clean branch from the current remote default branch. It is a pre-release integration record: the version bump and release tag are intentionally deferred until the integrated branch passes review and remote CI.

## Integration base and components

- Base: `origin/main` at `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`).
- R1 source: `8e4aa2dc1432c890d068ec29ca91e436657b9625`; integrated commit: `553a0fa` — `fix(core): make orchestration and reporting trustworthy`.
- R2 source: `08a4ff16ab80c6927d3200efa4fe7a10fc745a21`; integrated commit: `2ad0807` — `fix(network): preserve endpoint and protocol fidelity`.
- R3 source: `fdc125f25a4a2eef9b5eeba8c6d6c701d317a16c`; integrated commit: `335ac7a` — `fix(specialists): correct verdict and lifecycle semantics`.
- Integration branch: `codex/aranum-v0.34.0`.

The source commits were cherry-picked in R1, R2, R3 order. Component commit subjects and ordering are retained.

## Conflict resolutions

### R2 over R1

- `CHANGELOG.md`: retained the complete R1 and R2 entries together under `[Unreleased]`; no release block or version was created.
- `aranumtoolkit/network/bulk-enum-linux.sh`: combined R1 endpoint manifests, collision-safe output directories, bounded dispatch, conservative resume migration, stale-marker invalidation, and fatal systemic dispatch handling with R2 authorized-pair JSONL validation, per-row key identity, safe JSON metadata encoding, and bare OpenSSH IPv6 destinations. Authorized pairs keep their full key/user/host/port artifact identity through normalization and dispatch.
- `aranumtoolkit/network/enum-ftp.sh`: retained R1 phase-constrained execution and exact-port NXC grouping while adding R2 implicit FTPS handling and per-endpoint Nmap execution. Queue tasks retain the canonical `ftp.txt` evidence name; unconstrained multi-endpoint runs use port-qualified evidence to prevent collisions.
- `aranumtoolkit/network/report.py`: retained R1 finding finalization, protocol-aware IDs, structural attribution, and evidence deduplication while adding R2 canonical bulk metadata validation, partial-report diagnostics, and auth-pair identity fields. Deduplication and finding IDs include user/key/artifact identity so distinct authorized pairs cannot collapse.
- `aranumtoolkit/tests/test_r1_remediation.py`: made assertions accept R2's port-token formatting and user-qualified key-only evidence names without weakening the tested R1 behavior.

### R3 over R1 and R2

- `CHANGELOG.md`: retained all R1 and R2 entries and incorporated all R3 Fixed, Changed, Added, and test coverage descriptions under `[Unreleased]`.
- `README.md` and `aranumtoolkit/tests/smoke.sh` merged automatically with all component changes retained.
- No R3 production file required a manual conflict choice.

## Verification

Conflict-focused and component integration checks:

- `python3 -m pytest -q aranumtoolkit/tests/test_bulk_enum_linux_auth.py aranumtoolkit/tests/test_bulk_enum_report.py aranumtoolkit/tests/test_r2_protocol_transports.py aranumtoolkit/tests/test_r1_remediation.py` — 59 passed.
- `python3 -m pytest -q aranumtoolkit/tests/test_specialist_semantics_r3.py aranumtoolkit/tests/test_gql_internals.py` — 73 passed; 32 subtests passed.
- `python3 -m pytest -q` — 416 passed, 5 skipped; 100 subtests passed.
- `make test` — passed:
  - ShellCheck was unavailable; the designed fallback parsed every tracked shell file with `bash -n`.
  - unittest: 364 passed, 5 skipped.
  - pytest: 416 passed, 5 skipped; 100 subtests passed.
  - smoke: 380 passed, 0 failed, 1 skipped.
  - data audit: all seven manifest entries passed, including the 78-file embedded CVE/version family.
- Dedicated tracked-file syntax passes:
  - every `*.sh`: `bash -n`;
  - every `*.py`: `python3 -m py_compile`;
  - every `*.json`: `python3 -m json.tool`.
- `git diff --check origin/main...HEAD` — passed.
- Copied review documents were SHA-256 checked byte-for-byte against the primary checkout.

## Release state and pending bump

- `VERSION` remains `0.33.0`.
- The newest released changelog block remains `[v0.33.0]`.
- All combined remediation entries remain under `[Unreleased]`.
- No release tag has been created.

After this integration branch is reviewed and remote CI passes, create a dedicated release commit that:

1. changes `VERSION` to `0.34.0`;
2. moves the combined `[Unreleased]` entries into `[v0.34.0] — 2026-09-14`;
3. leaves a fresh empty `[Unreleased]` section;
4. reruns the release/version checks and full test gate;
5. tags the resulting commit `v0.34.0` and publishes only after verifying the tag target.

## Full changed-file inventory

Status is relative to `origin/main` at the integration base. `A` means added and `M` means modified.

- `M` `.github/workflows/ci.yml`
- `M` `aranum.py`
- `A` `aranumtoolkit/data-sources.json`
- `M` `aranumtoolkit/docs/ADR-002-20MAY2026-bulk-enum-design.md`
- `M` `aranumtoolkit/docs/ADR-006-28JUL2026-bulk-enum-overhaul.md`
- `M` `aranumtoolkit/docs/DATA-SOURCES.md`
- `M` `aranumtoolkit/docs/SCHEMA.md`
- `M` `aranumtoolkit/interop/aranum_to_recce.py`
- `M` `aranumtoolkit/interop/README.md`
- `M` `aranumtoolkit/network/_lib.sh`
- `M` `aranumtoolkit/network/auto-enum.sh`
- `M` `aranumtoolkit/network/autoenum-diff.sh`
- `M` `aranumtoolkit/network/bulk-enum-linux.sh`
- `M` `aranumtoolkit/network/bulk-enum-windows.py`
- `A` `aranumtoolkit/network/enum-bambu.sh`
- `M` `aranumtoolkit/network/enum-ftp.sh`
- `M` `aranumtoolkit/network/enum-imap.sh`
- `M` `aranumtoolkit/network/enum-ldap.sh`
- `M` `aranumtoolkit/network/enum-pop3.sh`
- `M` `aranumtoolkit/network/enum-smtp.sh`
- `M` `aranumtoolkit/network/enum-ssh.sh`
- `M` `aranumtoolkit/network/iterative-enum.sh`
- `M` `aranumtoolkit/network/merge-results.py`
- `M` `aranumtoolkit/network/nmap-parse.py`
- `M` `aranumtoolkit/network/plan.py`
- `M` `aranumtoolkit/network/report-dashboard.py`
- `M` `aranumtoolkit/network/report.py`
- `M` `aranumtoolkit/network/service-metadata.json`
- `M` `aranumtoolkit/network/ssh-key-triage.py`
- `M` `aranumtoolkit/network/ssh-triage.sh`
- `M` `aranumtoolkit/tests/data_audit.py`
- `M` `aranumtoolkit/tests/smoke.sh`
- `M` `aranumtoolkit/tests/test_bulk_enum_linux_auth.py`
- `M` `aranumtoolkit/tests/test_bulk_enum_report.py`
- `M` `aranumtoolkit/tests/test_bulk_enum_windows_transports.py`
- `M` `aranumtoolkit/tests/test_gql_internals.py`
- `M` `aranumtoolkit/tests/test_interop_recce.py`
- `M` `aranumtoolkit/tests/test_merge_results.py`
- `M` `aranumtoolkit/tests/test_nmap_parse.py`
- `M` `aranumtoolkit/tests/test_phase1_hardening.py`
- `M` `aranumtoolkit/tests/test_planner.py`
- `A` `aranumtoolkit/tests/test_quality_gate_r1.py`
- `A` `aranumtoolkit/tests/test_r1_remediation.py`
- `A` `aranumtoolkit/tests/test_r2_host_predicates.py`
- `A` `aranumtoolkit/tests/test_r2_protocol_transports.py`
- `A` `aranumtoolkit/tests/test_specialist_semantics_r3.py`
- `M` `aranumtoolkit/tests/test_ssh_key_triage.py`
- `M` `CHANGELOG.md`
- `M` `deps-check.sh`
- `A` `docs/plans/REMEDIATION-SPRINT-PLAN-13SEP2026-aranum-quality-findings.md`
- `A` `docs/plans/REVIEW-SPRINT-PLAN-13SEP2026-aranum-comprehensive-quality.md`
- `A` `docs/research/IMPLEMENTATION-R1-14SEP2026-aranum-quality-remediation.md`
- `A` `docs/research/IMPLEMENTATION-R2-14SEP2026-endpoint-transport-host-detection.md`
- `A` `docs/research/IMPLEMENTATION-R3-14SEP2026-specialist-semantics-lifecycle.md`
- `A` `docs/research/INTEGRATION-MANIFEST-14SEP2026-v0.34.0.md`
- `A` `docs/research/REVIEW-SPRINT-1-13SEP2026-orchestration-data-reporting.md`
- `A` `docs/research/REVIEW-SPRINT-2-13SEP2026-network-host-enumeration.md`
- `A` `docs/research/REVIEW-SPRINT-3-13SEP2026-specialist-tests-product-gaps.md`
- `A` `docs/research/REVIEW-VALIDATION-13SEP2026-independent-findings-gate.md`
- `M` `Makefile`
- `M` `README.md`
- `M` `standalones/activemq/_activemq_lib.sh`
- `M` `standalones/activemq/activemq-cve-2023-46604.py`
- `M` `standalones/activemq/activemq-queues.sh`
- `M` `standalones/activemq/activemq-quickwin.sh`
- `A` `standalones/activemq/jolokia_inventory.py`
- `M` `standalones/activemq/README.md`
- `M` `standalones/graphql/gql.py`
- `M` `standalones/graphql/README.md`
- `M` `standalones/jabber/jabber-user-enum.py`
- `M` `standalones/jabber/openfire-cve-2023-32315.py`
- `M` `standalones/jabber/README.md`
- `M` `standalones/linux/apt-source-check.sh`
- `M` `standalones/ot/_lib.sh`
- `M` `standalones/ot/enum-bacnet.sh`
- `M` `standalones/ot/enum-dnp3.sh`
- `M` `standalones/ot/enum-enip.sh`
- `M` `standalones/ot/enum-iec104.sh`
- `M` `standalones/ot/enum-modbus.sh`
- `M` `standalones/ot/enum-opcua.sh`
- `M` `standalones/ot/enum-s7.sh`
- `M` `standalones/ot/ot-enum.sh`
- `M` `standalones/ot/README.md`
- `M` `standalones/redis/_redis_lib.sh`
- `M` `standalones/redis/module/Makefile`
- `M` `standalones/redis/module/README.md`
- `A` `standalones/redis/module/SOURCE.json`
- `A` `standalones/redis/module/verify_source.py`
- `M` `standalones/redis/README.md`
- `M` `standalones/redis/redis-lateral.sh`
- `M` `standalones/redis/redis-quickwin.sh`
- `M` `standalones/redis/redis-rce-lua.sh`
- `M` `standalones/redis/redis-rce-module.sh`
- `M` `standalones/redis/redis-rce-ssh.sh`
- `M` `standalones/smtp/_smtp_lib.sh`
- `M` `standalones/smtp/README.md`
- `M` `standalones/smtp/smtp-phish-send.sh`
- `M` `standalones/smtp/smtp-quickwin.sh`
- `M` `standalones/smtp/smtp-relay-test.sh`
- `M` `standalones/smtp/spf-dmarc-check.sh`
- `M` `standalones/windows/Get-ADCSMisconfig.ps1`
- `M` `standalones/windows/Get-ServiceMisconfig.ps1`
- `M` `standalones/windows/Get-UnquotedServices.ps1`
- `M` `standalones/windows/Invoke-PrivEscEnum.ps1`
- `A` `wiki/bambu.md`
- `M` `wiki/windows.md`
