# Phase R3 implementation report — specialist semantics and lifecycle

Date: 2026-09-14
Branch: `codex/aranum-r3-14sep2026`
Worktree: `/home/jay/Documents/cyber/dev/.aranum-worktrees/14sep2026/r3`

## Scope and status

All 23 binding Phase R3 findings, S3-04 through S3-26, are implemented. The
work used deterministic local fixtures only: it performed no target scan, no
live exploit, and no live target mutation. The two Openfire preflight failures
remain distinct: omitted `--plugin-jar` produces `PLUGIN_ARGUMENT_OMITTED`,
while a supplied nonexistent or unreadable path produces `PLUGIN_UNREADABLE`.
Both return nonzero before confirmation or network access and report
`mutation_calls: 0`.

## Finding-by-finding implementation

| ID | Status | Implementation and evidence |
|---|---|---|
| S3-04 | Complete | SMTP parsing associates the final multiline reply with its exact command; the reject-all RCPT fixture cannot inherit an earlier EHLO/MAIL `250`. |
| S3-05 | Complete | Relay case 18 is normal external-to-local delivery, case 19 is destination-indeterminate, and case 16 is an accepted null-recipient protocol anomaly with no external destination. Only unauthenticated delivery to an actual external destination becomes a relay finding. |
| S3-06 | Complete | The interactive sender gates EHLO, MAIL, RCPT, DATA, and final body acceptance independently; RCPT/DATA/final rejection returns a distinct nonzero status. |
| S3-07 | Complete | SPF/DMARC parsing uses option-safe matches, joins quoted TXT fragments, and initializes policy state; SPF `-all` plus absent DMARC is stable. Any failed `dig` makes the overall result `INDETERMINATE` with status 2 and can never become “wide open.” |
| S3-08 | Complete | Redis module capability uses server policy and current-user ACL evidence (`ACL DRYRUN` where available); `MODULE LIST` alone cannot imply load permission, and `enable-module-command=local` is denied for the tool's remote TCP connection even if ACL dry-run permits it. |
| S3-09 | Complete | Redis mutation snapshots persistence, role/upstream, `masterauth`, and `masteruser`, including empty credential values. Shared command status is preserved; module and SSH workflows refuse incomplete snapshots. Module and SSH-key `SET`/`CONFIG SET`/`SAVE`, replication transitions, load, and unload require status zero plus exact trimmed `OK`; SSH key length and staged configuration are read back. Any unproved cleanup state returns status 77 even when the main path already failed. Adversarial fixtures reject nonzero-with-`OK`, `OK-but-not-applied`, `OK-but-not-saved`, `OK-but-not-restored`, and `OK-but-still-loaded`. |
| S3-10 | Complete | Documentation now promises a local offline build from vendored inputs rather than an absent binary. `SOURCE.json` pins paths, provenance, and hashes; `verify_source.py` gates bundled builds before target access; the default/runtime Makefile path cannot fetch a missing input. |
| S3-11 | Complete | An OpenWire signature is critical only with parsed, affected semantic-version evidence; patched versions are low and absent/invalid versions remain medium/indeterminate. |
| S3-12 | Complete | XML and callback listeners bind before payload delivery; callback bind failure is fatal, and all listeners close on every send outcome. |
| S3-13 | Complete | Jolokia discovery searches actual broker objects, structurally parses quoted object names, preserves whitespace, URL-encodes exact object names, hashes artifact slugs, and counts empty results as zero. |
| S3-14 | Complete | GraphQL response status is computed recursively before rendering, so raw and batched transport, HTTP, malformed/empty-body, and per-member GraphQL errors remain nonzero, including partial-data errors. |
| S3-15 | Complete | Loop classification uses field membership rather than truthiness; false, zero, empty string/list, and null are distinguished. Signatures use value-insensitive JSON shapes. |
| S3-16 | Complete | Read-only GET is informational only when its response is conclusive. A critical CSRF result requires an operator-supplied mutation, cookie context, attacker Origin, no PAT/bearer/job/custom CSRF-token defense, and a non-null expected top-level result field. Authentication and custom CSRF header names are matched case-insensitively, including custom `--header` spelling. Transport failure, uncertain HTTP, malformed bodies, GraphQL errors, and absent/null proof fields are indeterminate/nonzero. |
| S3-17 | Complete | Alias tests clone the selected operation, arguments, variables, and selection; randomized repeated samples report median/variance and only a follow-up timing signal, never proof of normalization or DoS. |
| S3-18 | Complete | The GraphQL README now documents the accepted `gql.py ls` command rather than passing an invalid `--no-schema` option. |
| S3-19 | Complete | Generic SASL `not-authorized` is neutral; only repeatable differentiation from randomized high-entropy controls produces `LIKELY_EXISTS`. |
| S3-20 | Complete | URL, plugin argument/readability/JAR metadata, proof marker, and atomic recovery-log destination are checked locally before confirmation/network access. Directories, symlinks, missing/unwritable parents, and unwritable destinations fail locally; omitted and unreadable-plugin reasons remain separate and zero-mutation. |
| S3-21 | Complete | Admin creation is independently verified and recovery state is written atomically after each mutation response. Upload failure and proof failure are nonzero; only exact proof-marker retrieval reaches `full_chain_verified`. |
| S3-22 | Complete | Shared Redis argv construction and every specialist caller accept named ACL username plus password while preserving legacy password-only AUTH. |
| S3-23 | Complete | `test_specialist_semantics_r3.py` adds deterministic verdict/lifecycle fixtures across all specialist families plus exact adversarial reproductions for failed DNS, Redis local policy/empty state/status, runtime no-fetch, typed derivations, token-aware CSRF ambiguity, Openfire log preflight, and plugin-inventory cleanup proof. |
| S3-24 | Complete | `data-sources.json` replaces the two-path allowlist with seven manifest families carrying source, owner, refresh date, freshness policy, and checksum or typed derivation. The audit validates JSON structure, every checksummed source-manifest input, and actual dynamically discovered CVE/version-rule files. |
| S3-25 | Complete | Root documentation describes the shipped credential sweeper as HTTP(S) administrative-portal coverage and directs native authentication to protocol dispatchers. |
| S3-26 | Complete | Cleanup legitimately authenticates, discovers target-provided uninstall/delete actions, and proves plugin absence through a recognized authenticated plugin inventory before deleting the created admin. Marker absence plus failed login is explicitly insufficient; verified prior inventory evidence supports idempotent reruns. |

## Files changed

- Release/product docs: `CHANGELOG.md`, `README.md`, and this dated report.
- Assurance/data: `aranumtoolkit/data-sources.json`,
  `aranumtoolkit/docs/DATA-SOURCES.md`, `aranumtoolkit/tests/data_audit.py`,
  `aranumtoolkit/tests/smoke.sh`, `aranumtoolkit/tests/test_gql_internals.py`,
  `aranumtoolkit/tests/test_specialist_semantics_r3.py`.
- SMTP: `standalones/smtp/README.md`, `_smtp_lib.sh`,
  `smtp-phish-send.sh`, `smtp-quickwin.sh`, `smtp-relay-test.sh`,
  `spf-dmarc-check.sh`.
- Redis: `standalones/redis/README.md`, `_redis_lib.sh`,
  `redis-lateral.sh`, `redis-quickwin.sh`, `redis-rce-lua.sh`,
  `redis-rce-module.sh`, `redis-rce-ssh.sh`, `module/Makefile`,
  `module/README.md`, `module/SOURCE.json`, `module/verify_source.py`.
- ActiveMQ: `standalones/activemq/README.md`, `_activemq_lib.sh`,
  `activemq-cve-2023-46604.py`, `activemq-queues.sh`,
  `activemq-quickwin.sh`, `jolokia_inventory.py`.
- GraphQL: `standalones/graphql/README.md`, `gql.py`.
- Jabber/Openfire: `standalones/jabber/README.md`,
  `jabber-user-enum.py`, `openfire-cve-2023-32315.py`.

## Verification evidence

- `python3 -m pytest aranumtoolkit/tests/test_specialist_semantics_r3.py -q`
  — PASS after final gate fixes: 44 tests and 32 subtests in 12.22 seconds.
- `python3 -m pytest aranumtoolkit/tests/test_gql_cli.py aranumtoolkit/tests/test_gql_hardening.py aranumtoolkit/tests/test_gql_internals.py -q`
  — PASS after release-blocker fixes: 49 tests and 10 subtests in 2.42 seconds.
- `python3 -m pytest aranumtoolkit/tests/ -q`
  — PASS after final gate fixes: 349 passed, 5 skipped, 100 subtests in
  41.49 seconds.
- `python3 aranumtoolkit/tests/data_audit.py`
  — PASS: all 7 manifest entries; dynamic rule inventory resolved 78 files.
- `env PATH=/usr/bin:/bin make lint`
  — PASS: ShellCheck is unavailable on the system path, so the documented
  fallback parsed every tracked shell script successfully with `bash -n`.
- `make lint`
  — NONZERO (123): the branch inherited the independently assigned S3-02
  pyenv `shellcheck` shim failure (`command not found`). The direct system-path
  lint above passes and no R3 shell syntax failure remains.
- `git diff --check` — PASS.
- Direct Openfire preflight CLI evidence — PASS: omitted plugin returned 64
  with `PLUGIN_ARGUMENT_OMITTED` and `mutation_calls: 0`; supplied nonexistent
  path returned 66 with `PLUGIN_UNREADABLE` and `mutation_calls: 0`.
- `python3 standalones/redis/module/verify_source.py` — PASS: both vendored
  inputs match their structural provenance entries and SHA-256 values.
- `unshare -Urn bash -c 'ip link set lo up && exec bash aranumtoolkit/tests/smoke.sh'`
  — PASS: 375 passed, 0 failed, 1 skipped; FP harness reported no false
  positives and intact true-positive markers. The isolated network namespace
  prevents port collisions and any external target access.

The 375/0/1 smoke result predates the final S3-05/S3-09/S3-14/S3-16 release-blocker
edits and is retained as earlier R3 regression evidence, not as proof of those
edits. A post-fix isolated smoke attempt was discarded without a final summary;
the post-fix evidence for the binding blockers is the focused adversarial suite,
the legacy GraphQL suite, the complete pytest suite, syntax checks, and
`git diff --check` above.

An earlier host-network smoke run was invalidated because simultaneous
worktrees shared the fixed FP-harness ports. It is not used as evidence; the
complete isolated-network result above is the final smoke evidence.

## Blockers

No R3 implementation item is blocked. The default `make lint` launcher issue is
owned by S3-02 outside this worktree; its underlying lint command passes with
the system tool path.
