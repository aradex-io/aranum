# Aranum comprehensive quality review — Sprint 3

**Date:** 13 September 2026
**Reviewed baseline:** `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
**Sprint focus:** specialist tools; build, test, CI, dependency, and release systems; relevant product documentation and offline-data governance
**Explicit exclusion:** security of aranum itself

## Outcome

This sprint found **21 concrete defects** and **5 evidence-backed feature/coverage gaps**. The highest-impact cluster is incorrect positive/negative evidence: several SMTP, Redis, ActiveMQ, GraphQL, and Jabber helpers can promote ordinary or indeterminate behavior to a high-confidence finding, while the build and CI paths do not consistently exercise the tests intended to prevent those regressions.

Severity totals across both sections: **16 High, 8 Medium, 2 Low**.

## Coverage and method

The review read the implementation, tests, configuration, data metadata, and operator documentation in these areas:

- `standalones/{activemq,creds,graphql,jabber,redis,smtp,tomcat}/`
- `.github/workflows/ci.yml`, `Makefile`, `deps-check.sh`, `VERSION`, `requirements-optional.txt`, release/data documentation
- specialist-facing test modules and fixtures under `aranumtoolkit/tests/`, including the smoke and false-positive harnesses
- `README.md`, specialist READMEs, `CHANGELOG.md`, and `aranumtoolkit/docs/DATA-SOURCES.md`

Safe static and local protocol-mock checks were used. No product code or remote target was changed. Redis server behavior could not be reproduced locally because `redis-server` and `redis-cli` are absent; the Redis findings below therefore identify their static control-flow evidence explicitly.

### Commands and results

| Check | Result |
|---|---|
| `python3 -m py_compile` over all Sprint 3 Python tools | pass |
| `bash -n` over all Sprint 3 shell tools | pass |
| `gcc -O2 -Wall -Wextra -fPIC -std=c99 -fsyntax-only standalones/redis/module/system.c` | pass |
| `python3 -m json.tool` over specialist catalogs and service metadata | pass |
| targeted creds/GraphQL unit modules | **64 passed** |
| `python3 -m unittest discover -s aranumtoolkit/tests -p 'test_*.py' -v` | **278 tests passed, 5 skipped** |
| `python3 -m pytest aranumtoolkit/tests/ -q` | **304 passed, 5 skipped, 68 subtests passed** (309 collected) |
| `make smoke` | **372 passed, 0 failed, 1 skipped**; existing FP harness reported no FPs and intact TP markers |
| `make lint` | **exit 2**: a non-functional pyenv `shellcheck` shim is treated as installed; `xargs` exits 123 |
| `bash deps-check.sh` | **exit 0** despite two required-tool failures and four pyenv shims whose version command says `command not found` |
| `make data-audit` | exit 0; only two datasets were inspected |
| SMTP reject-all mock against `smtp-quickwin.sh` | tool emitted **CRITICAL** although every `RCPT TO` returned 550 |
| local-delivery-only SMTP mock against `smtp-relay-test.sh` | ordinary external-to-local recipient acceptance was labelled `RELAY OPEN` |
| SMTP reject mock against `smtp-phish-send.sh --send` | tool printed `Message accepted` and exited 0 after `RCPT 550` and `DATA 554` |
| fake-`dig` SPF hardfail/no-DMARC fixture | grep printed its usage instead of recognizing `-all`, then the script failed with `policy: unbound variable` |
| `gql.py --raw-response raw` against a refused port | printed a connection-error JSON object and exited **0** |
| documented `gql.py ls --no-schema` | argparse rejected the option, exit **2** |
| `git ls-files standalones/redis/module` plus file check | documentation claims `system.so` is checked in; it is neither tracked nor present |

## Concrete defects

### S3-01 — Dependency preflight reports success for a non-runnable environment

- **Category:** dependency detection / exit-status logic
- **Severity:** High
- **Location:** `deps-check.sh:10-23`, `deps-check.sh:47-55`, `deps-check.sh:257-269`
- **Background/details:** `check()` equates `command -v` with a working executable, prints the first line of a failed `--version` invocation as a success, and never accumulates required failures. In addition, the `dig` row passes `bind-utils-or-dig` as the executable name, so it does not actually test `dig`. The script falls off the end with status 0.
- **Effectiveness impact:** Operators can begin an offline or large-network run after a successful preflight even though required tooling cannot run, causing missing coverage and late failures that look like target behavior.
- **Evidence/reproduction:** `bash deps-check.sh` returned 0 while flagging `dig` and `ldapsearch` as required-but-missing. It printed `[+]` for `GetUserSPNs.py`, `GetNPUsers.py`, `mssqlclient.py`, and `shellcheck`, immediately followed by pyenv's `command not found` text.
- **Proposed remediation:** Probe the actual executable, run a cheap executable-specific version/help check, treat 126/127 as absent, accumulate required failures, print a final summary, and return nonzero when any required dependency is unusable. Separate package-install hints from the executable argument.

### S3-02 — Lint fallback is bypassed by a broken PATH shim

- **Category:** build reliability / degraded-mode logic
- **Severity:** High
- **Location:** `Makefile:52-70`
- **Background/details:** The advertised offline fallback is selected only when `command -v shellcheck` fails. A pyenv shim satisfies that predicate even when no shellcheck version is installed; the Makefile then invokes the broken shim through `xargs` and never reaches `bash -n`.
- **Effectiveness impact:** `make test` aborts before tests on a common version-manager PATH configuration, defeating both the full quality gate and its documented offline behavior.
- **Evidence/reproduction:** `command -v shellcheck` returned `/home/jay/.pyenv/shims/shellcheck`; `shellcheck --version` returned 127; `make lint` exited 2 after `xargs` returned 123.
- **Proposed remediation:** Validate `shellcheck --version` (or a no-input invocation) before selecting it. If execution returns 126/127, issue the degraded warning and run the existing syntax sweep. Add a regression test with a deliberately broken shim first on PATH.

### S3-03 — GitHub CI omits the pytest portion of the declared full suite

- **Category:** CI/test integration gap
- **Severity:** High
- **Location:** `.github/workflows/ci.yml:3-5`, `.github/workflows/ci.yml:47-69`, `Makefile:38-39`, `Makefile:76-87`
- **Background/details:** The workflow says it mirrors `make test`, but invokes only `make lint`, `make unittest`, and `make smoke`. `make test` also depends on `pytest`, specifically described as covering suites unittest discovery cannot collect. CI neither invokes that target nor explicitly installs pytest.
- **Effectiveness impact:** A green pull request can ship regressions in pytest-only bulk-enum, SSH triage, and thick-client behavior; the local and CI meanings of “full test” differ.
- **Evidence/reproduction:** Unittest discovery ran 278 tests; pytest collected 309. Full pytest passed locally, demonstrating 31 collected cases outside the unittest count. Workflow lines 60-69 contain no pytest step.
- **Proposed remediation:** Install a pinned/supported pytest in CI and run `make pytest` on every supported Python, or run `make test` once plus interpreter-specific unit/pytest jobs. Update the workflow comment only after the executable paths match.

### S3-04 — SMTP quickwin derives relay verdicts from unrelated 250 replies

- **Category:** protocol-state logic / false positive
- **Severity:** High
- **Location:** `standalones/smtp/smtp-quickwin.sh:52-70`, `standalones/smtp/smtp-quickwin.sh:86-96`
- **Background/details:** Both probes scan an entire multi-command transcript for a matching `250`, rather than associating a reply with the `RCPT TO` command. EHLO or MAIL acceptance can therefore satisfy the test. The “internal relay” also defaults the internal domain to the target host and interprets acceptance of local delivery as a critical relay primitive.
- **Effectiveness impact:** Normal SMTP servers can be elevated to CRITICAL, flooding a large-network review with misleading remediation work and obscuring real open relays.
- **Evidence/reproduction:** A local mock returned 250 to EHLO/MAIL and 550 to every RCPT. The tool wrote `relay_open=0 internal_ok=1` and `CRITICAL internal-domain relay accepted unauth`.
- **Proposed remediation:** Implement a small SMTP response state machine, require the relevant RCPT reply (and preferably successful DATA completion) for a relay verdict, accept an explicit internal-domain value, and distinguish expected local delivery from third-party relay acceptance.

### S3-05 — SMTP relay matrix reverses normal inbound and unauthenticated outbound semantics

- **Category:** assessment logic / documentation error
- **Severity:** High
- **Location:** `standalones/smtp/smtp-relay-test.sh:71-73`, `standalones/smtp/smtp-relay-test.sh:83-105`, `standalones/smtp/README.md:104-108`
- **Background/details:** Every 250/251 RCPT is unconditionally labelled `RELAY OPEN`. Case 18 (external sender to a recipient in the server's own domain) is ordinary inbound delivery, not third-party relaying. Conversely, the README says a well-configured server should accept case 17 (local-looking sender to an external recipient) without accounting for authentication or a trusted source IP.
- **Effectiveness impact:** The matrix reports the defining normal behavior of an inbound MTA as a critical fault and teaches operators the inverse remediation expectation.
- **Evidence/reproduction:** A mock that accepted only `@corp.local` recipients rejected case 17 and accepted case 18; the tool flagged case 18 as `RELAY OPEN` and counted it among seven accepted variants.
- **Proposed remediation:** Classify by destination relay boundary: external-to-local is expected, while acceptance to a non-local destination without authentication/trusted-network authorization is the relay signal. Make expected outcomes domain-aware and document authenticated-versus-unauthenticated cases.

### S3-06 — SMTP sender reports success after rejected recipient and DATA commands

- **Category:** protocol-state logic / exit-status correctness
- **Severity:** High
- **Location:** `standalones/smtp/smtp-phish-send.sh:137-151`
- **Background/details:** The sender pipelines the complete dialog, then declares success if any response line matches a generic `250 ... ok/queued/accepted`. It does not require RCPT success, a 354 DATA challenge, or a final queued response, and the failure branch does not return nonzero.
- **Effectiveness impact:** Operators can believe an authorized delivery test worked when no message was accepted, invalidating downstream phishing-control conclusions.
- **Evidence/reproduction:** A mock returned 250 to EHLO and MAIL, 550 to RCPT, and 554 to DATA. The script printed `[+] Message accepted` and exited 0.
- **Proposed remediation:** Parse and gate each SMTP stage, send message content only after 354, require a 2xx final result after the terminating dot, and return distinct nonzero statuses for recipient, DATA, and final-delivery rejection. Reuse `swaks` where available but keep a correct fallback.

### S3-07 — SPF/DMARC checker misparses hardfail and crashes on a common record combination

- **Category:** shell parsing / uninitialized state
- **Severity:** High
- **Location:** `standalones/smtp/spf-dmarc-check.sh:16-35`, `standalones/smtp/spf-dmarc-check.sh:39-60`, `standalones/smtp/spf-dmarc-check.sh:81-90`
- **Background/details:** `grep -q '-all'` treats the leading hyphen as options rather than a pattern. Separately, `policy` is assigned only when DMARC exists but is dereferenced in the final verdict under `set -u` when SPF exists and DMARC does not.
- **Effectiveness impact:** A valid SPF hardfail is not recognized, and domains with SPF but no DMARC terminate before producing a usable posture verdict.
- **Evidence/reproduction:** With a fake `dig` returning `v=spf1 -all` and no DMARC, the script emitted `grep: invalid option -- 'p'` and then `policy: unbound variable`.
- **Proposed remediation:** Use `grep -q -- '-all'`, initialize all record-derived fields before branches, make verdict branches depend explicitly on record presence, and add table-driven fixtures for absent/present SPF and DMARC combinations.

### S3-08 — Redis quickwin equates `MODULE LIST` access with `MODULE LOAD` capability

- **Category:** capability inference / false positive
- **Severity:** High
- **Location:** `standalones/redis/redis-quickwin.sh:88-106`, `standalones/redis/module/README.md:35-37`
- **Background/details:** Redis major version 4+ initializes `module_capable=1`; the detector clears it only when `MODULE LIST` itself returns an error. Redis 7 can permit listing while `enable-module-command no` blocks load/unload. The README nevertheless claims this setting is probed and the tier is downgraded.
- **Effectiveness impact:** Unauthenticated Redis services can be labelled CRITICAL with a specific RCE path that the configured server rejects.
- **Evidence/reproduction:** Static control flow contains no `CONFIG GET enable-module-command`, ACL command check, or safe load-capability distinction; only the `MODULE LIST` result controls lines 97-101. Local runtime reproduction was unavailable because Redis tooling is not installed.
- **Proposed remediation:** Query `CONFIG GET enable-module-command` when permitted, separately inspect ACL permission for the current identity, and describe unknown/hidden configuration as indeterminate rather than load-capable. Add Redis 7 fixtures/containers for enabled, disabled, and ACL-denied states.

### S3-09 — Redis module cleanup permanently detaches pre-existing replicas

- **Category:** target-state restoration / logic error
- **Severity:** High
- **Location:** `standalones/redis/redis-rce-module.sh:119-140`, `standalones/redis/redis-rce-module.sh:193-217`, `standalones/redis/_redis_lib.sh:104-115`
- **Background/details:** The cleanup trap always issues `REPLICAOF NO ONE`, including error exits. The saved configuration contains only `dir`, `dbfilename`, and `appendonly`; it does not capture the original replication role/upstream or `masterauth`, although the exploit changes both replication and potentially `masterauth`.
- **Effectiveness impact:** An engagement helper can promote an existing replica and leave replication/auth topology changed after either success or failure, undermining service integrity and cleanup confidence.
- **Evidence/reproduction:** Static trace: save at lines 104-109 omits replication state; line 197 changes `masterauth`; line 201 redirects replication; trap line 135 always detaches and never restores the previous upstream.
- **Proposed remediation:** Snapshot `INFO replication`, upstream host/port, relevant auth/config values, and whether each value was readable before mutation. Track which steps changed state and restore the exact original role/config in reverse order; abort before mutation if reliable restoration is impossible.

### S3-10 — Redis’s promised checked-in offline module binary is absent

- **Category:** packaging / offline readiness
- **Severity:** Medium
- **Location:** `standalones/redis/module/README.md:9-19`, `standalones/redis/module/Makefile:1-22`, `standalones/redis/redis-rce-module.sh:106-115`, `.gitignore:1-5`, `.gitignore:33-35`
- **Background/details:** Documentation and Makefile comments say `system.so` is checked in and the default build is offline/no-op. The repository tracks only the Makefile, README, header, and C source, while `.gitignore` explicitly excludes the claimed artifact. The runtime silently attempts a local compiler build when the binary is missing.
- **Effectiveness impact:** On an air-gapped assessment host without a compiler/toolchain, a documented ready-to-use path fails only after the operator reaches it.
- **Evidence/reproduction:** `git ls-files standalones/redis/module` contained no `system.so`; the file was also absent from the working tree.
- **Proposed remediation:** Either distribute a versioned/checksummed build artifact through the release process (with explicit architecture constraints) or remove the checked-in claim and make compiler/architecture preflight explicit in `deps-check.sh` and dry-run output.

### S3-11 — Any ActiveMQ OpenWire signature is reported CRITICAL without version evidence

- **Category:** version classification / false positive
- **Severity:** High
- **Location:** `standalones/activemq/activemq-quickwin.sh:50-61`, `standalones/activemq/README.md:41-49`
- **Background/details:** The documentation defines CRITICAL as OpenWire plus a vulnerable version. The implementation sets CRITICAL as soon as banner bytes contain `ActiveMQ` or `MagicID`; its reason merely says “if version” is vulnerable and never obtains or evaluates that version on the OpenWire path.
- **Effectiveness impact:** Patched ActiveMQ brokers are promoted directly to an unauthenticated-RCE queue, overstating exposure across any estate that uses port 61616.
- **Evidence/reproduction:** The OpenWire branch has no call to `broker_version` or version-range comparator before assigning `tier="CRITICAL"` at line 56.
- **Proposed remediation:** Emit a detection/candidate tier until a version is obtained and falls in a vulnerable range; preserve “unknown due to backport/version hiding” distinctly from confirmed. Add boundary tests for every maintained ActiveMQ branch.

### S3-12 — ActiveMQ proof listener starts after the payload that may trigger it

- **Category:** event ordering / missed evidence
- **Severity:** Medium
- **Location:** `standalones/activemq/activemq-cve-2023-46604.py:188-219`
- **Background/details:** The XML server is started before the OpenWire send, but the optional callback listener is not bound until after the payload is sent and the broker response wait finishes. A fast command callback therefore reaches a closed port and is lost.
- **Effectiveness impact:** A successful command can be downgraded from CONFIRMED to PROGRESSED/SENT, wasting retest time and weakening evidence quality.
- **Evidence/reproduction:** Static event order is payload send at lines 196-212 followed by `serve_callback()` at lines 214-219.
- **Proposed remediation:** Validate/bind both required listeners before sending any payload, then send and hold; close both listeners in `finally` on all error paths. Unit-test ordering with fake listener and socket factories.

### S3-13 — ActiveMQ queue enumeration assumes broker name `localhost` and whitespace-safe destinations

- **Category:** Jolokia object discovery / parsing
- **Severity:** Medium
- **Location:** `standalones/activemq/activemq-queues.sh:42-70`, `standalones/activemq/activemq-queues.sh:76-85`
- **Background/details:** Broker discovery first reads only `brokerName=localhost`, then falls back to the same literal if parsing fails. Queue names are scraped from JSON with grep, expanded with `for q in $QUEUES`, and inserted unescaped into Jolokia URLs. Empty output is also counted as one line by `echo "$QUEUES" | wc -l`.
- **Effectiveness impact:** Custom broker names and destinations containing spaces/JMX-special or URL-special characters are missed or queried incorrectly, producing incomplete queue intelligence and misleading counts.
- **Evidence/reproduction:** Static data flow at lines 44-49 fixes the initial object name; lines 56-57 and 70 split queue names on shell whitespace; lines 78/84 interpolate raw names into URLs.
- **Proposed remediation:** Search `brokerName=*`, parse Jolokia JSON with a real JSON parser, retain destinations as an array, apply Jolokia object-name escaping plus URL encoding, and count zero records correctly. Add fixture responses with custom broker and complex queue names.

### S3-14 — GraphQL raw-output mode converts request failures into success exits

- **Category:** CLI exit-status contract
- **Severity:** High
- **Location:** `standalones/graphql/gql.py:448-465`
- **Background/details:** `print_response()` returns 0 immediately after printing raw JSON, before testing `_error`, GraphQL errors, or HTTP failure status.
- **Effectiveness impact:** Automation using `--raw-response` cannot distinguish a completed probe from transport/GraphQL failure and may store or aggregate failed requests as successful evidence.
- **Evidence/reproduction:** `python3 .../gql.py --url http://127.0.0.1:1/graphql --raw-response raw --query 'query { __typename }'` printed `{"_error":"connection failed..."}` and returned 0.
- **Proposed remediation:** Determine the result status before formatting; raw mode should suppress decoration, not alter success semantics. Test transport errors, non-2xx, GraphQL `errors`, and partial-data responses in both formatted and raw modes.

### S3-15 — GraphQL loop marks legitimate false/zero/empty field values as no data

- **Category:** response classification / false negative
- **Severity:** Medium
- **Location:** `standalones/graphql/gql.py:707-725`
- **Background/details:** `has_data = bool(body.get("data") and any(body["data"].values()))` requires at least one truthy top-level value. Valid responses such as `{"data":{"enabled":false}}`, count 0, empty lists, or empty strings are classified as no-data.
- **Effectiveness impact:** Authorization/data-presence sweeps can hide real accessible fields and make differential results look equivalent.
- **Evidence/reproduction:** Direct evaluation of the line’s predicate is false for valid GraphQL scalar/container results; the flag at line 720 is therefore never set for them.
- **Proposed remediation:** Track response structure separately from value truthiness: data member present, operation field present, null versus non-null, errors, and a stable serialized digest/size. Add false, zero, empty-list, null, and partial-error fixtures.

### S3-16 — GraphQL CSRF probe labels standards-compliant GET queries CRITICAL

- **Category:** assessment methodology / false positive
- **Severity:** High
- **Location:** `standalones/graphql/gql.py:952-980`
- **Background/details:** The probe sends only the read-only query `{__typename}`. Success causes a CRITICAL verdict claiming arbitrary reads or mutations, even though GraphQL-over-HTTP supports GET for query operations and mutation-over-GET is the behavior that must be rejected. It also does not establish cookie authentication, browser credential inclusion/SameSite conditions, or absence of an application CSRF defense.
- **Effectiveness impact:** Ordinary GraphQL endpoints are reported as critical CSRF vulnerabilities without demonstrating an authenticated state change.
- **Evidence/reproduction:** Lines 957-975 explicitly use only `__typename`; the comment concedes no mutation is attempted, yet lines 969-972 issue a critical arbitrary-query/mutation claim.
- **Proposed remediation:** Treat anonymous read-only GET support as informational. For a CSRF conclusion, require an operator-supplied benign mutation and authenticated browser-equivalent cookie context, verify it is accepted over GET without the expected origin/token defense, and clearly separate preconditions from confirmation.

### S3-17 — GraphQL alias-DoS check ignores the selected operation

- **Category:** feature wiring / invalid inference
- **Severity:** Medium
- **Location:** `standalones/graphql/gql.py:602-625`, `standalones/graphql/gql.py:983-1005`
- **Background/details:** The CLI passes the selected operation and schema object into `_alias_dos_check`, but the helper ignores both and repeatedly aliases root `__typename`. A single latency ratio over 2.5 is then described as missing alias normalization; a quiet result is described as proof the server normalizes aliased fields.
- **Effectiveness impact:** The feature does not exercise resolver amplification for the requested operation and can turn network jitter or trivial parser work into unsupported DoS conclusions.
- **Evidence/reproduction:** Every generated document at lines 995-997 contains only `aN: __typename`; neither `operation` nor `op` contributes to the request.
- **Proposed remediation:** Build aliases of the explicitly selected safe operation/field with valid arguments and selection, take multiple randomized baseline/probe samples, report confidence/variance, and avoid universal “normalizes” claims. Add a deterministic mock with configurable latency.

### S3-18 — Documented GraphQL catalog command is not accepted by the parser

- **Category:** documentation/CLI drift
- **Severity:** Low
- **Location:** `standalones/graphql/README.md:176-182`, `standalones/graphql/gql.py:1037-1040`, `standalones/graphql/gql.py:1046-1053`
- **Background/details:** The README tells operators to use `gql.py ls --no-schema`, but `--no-schema` belongs only to `call`, not `ls`.
- **Effectiveness impact:** The recommended workflow for introspection-disabled targets stops at argument parsing, making the bundled catalog harder to discover exactly when it is needed.
- **Evidence/reproduction:** The documented command returned argparse error `unrecognized arguments: --no-schema` with exit 2.
- **Proposed remediation:** Either add `--no-schema` to `ls` with explicit catalog-only semantics or document plain `ls` and state its schema/cache fallback behavior. Add executable documentation examples to CLI tests.

### S3-19 — Jabber enumerator presents generic SASL rejection as user existence

- **Category:** authentication-response inference / false positive
- **Severity:** High
- **Location:** `standalones/jabber/jabber-user-enum.py:14-29`, `standalones/jabber/jabber-user-enum.py:159-190`, `standalones/jabber/jabber-user-enum.py:297-325`
- **Background/details:** `<not-authorized/>` maps directly to `USER_EXISTS`, although the tool's own module documentation says hardened servers return that response for every username and will therefore mark every candidate as existing. The per-user UI still uses a green `+` and the JSON verdict remains categorical.
- **Effectiveness impact:** Large username lists can become entirely false-positive identity inventories, misdirecting credential validation and social-engineering defenses.
- **Evidence/reproduction:** The caveat at lines 26-29 exactly predicts the map at line 161; no nonexistent control users or statistical timing threshold are used before assigning the verdict.
- **Proposed remediation:** Rename the raw result to a neutral SASL condition, test randomized known-nonexistent controls, and issue `LIKELY_EXISTS` only when a repeatable differential exceeds a defined confidence threshold. Otherwise return `INDISTINGUISHABLE`; reflect confidence in terminal and JSON output.

### S3-20 — Openfire exploit preflights its required artifact after modifying the target

- **Category:** mutation ordering / recoverability
- **Severity:** High
- **Location:** `standalones/jabber/openfire-cve-2023-32315.py:164-225`, `standalones/jabber/openfire-cve-2023-32315.py:309-316`
- **Background/details:** `--plugin-jar` is described as required but argparse does not enforce it, and readability is not checked. The tool first attempts admin creation and only then discovers a missing argument; a nonexistent path raises an uncaught `FileNotFoundError` before any partial cleanup log is written.
- **Effectiveness impact:** A local input error can leave an added administrator on the assessed server with no reliable recovery record.
- **Evidence/reproduction:** Target mutation is requested at lines 180-204. Missing-value handling begins at 216; file reading at 225 is unguarded; parser line 313 lacks `required=True`.
- **Proposed remediation:** Validate every local prerequisite (argument, readable JAR, log destination, URL shape) before confirmation or network mutation. Write an atomic partial recovery log immediately after any confirmed target-side change, and use `try/finally` to preserve state/recovery evidence on later failure.

### S3-21 — Openfire upload failure is logged and returned as a successful full chain

- **Category:** verification / exit-status correctness
- **Severity:** High
- **Location:** `standalones/jabber/openfire-cve-2023-32315.py:237-250`
- **Background/details:** HTTP 200/302 is assumed to mean the plugin is installed, but no plugin or webshell verification is performed. Any other status prints a warning yet still writes `step="full_chain"` and returns 0. The derived webshell path is based on the CLI name, not verified plugin metadata/context.
- **Effectiveness impact:** The tool can report successful exploitation and record misleading cleanup state when only admin creation succeeded or upload was rejected.
- **Evidence/reproduction:** Both branches converge on `_write_log(... step="full_chain")` and `return 0` at lines 248-250; the supposed success path itself says to verify manually.
- **Proposed remediation:** Record each step independently, verify plugin installation and a benign endpoint response, use the actual deployed context, and return nonzero/partial status when upload or verification fails. Preserve the admin recovery log even for partial success.

## Evidence-backed feature and coverage gaps

### S3-22 — Redis specialist tools cannot authenticate as named ACL users

- **Category:** protocol feature gap
- **Severity:** Medium
- **Location:** `standalones/redis/_redis_lib.sh:24-43`, `standalones/redis/_redis_lib.sh:52-75`, `standalones/redis/_redis_lib.sh:79-101`
- **Background/details:** All authentication paths accept only a password and invoke `redis-cli -a`; there is no `--user`/`--username` plumbing for Redis 6+ ACL identities.
- **Effectiveness impact:** Valid least-privilege assessment credentials for named users are reported as wrong or unusable, preventing capability review of modern enterprise Redis deployments.
- **Evidence/reproduction:** The shared library constructs only `-a "$PASS"`; all callers inherit that limitation. No Redis specialist CLI exposes a username option.
- **Proposed remediation:** Add a shared optional username, invoke `redis-cli --user USER --pass PASS` (or URI equivalent without exposing credentials), distinguish WRONGPASS from missing ACL permission, and test default-user plus named-user fixtures.

### S3-23 — Specialist smoke coverage checks gates/help, not verdict semantics

- **Category:** regression-test coverage gap
- **Severity:** High
- **Location:** `aranumtoolkit/tests/smoke.sh:45-65`, `aranumtoolkit/tests/smoke.sh:170-239`, `aranumtoolkit/tests/smoke.sh:349-370`, `aranumtoolkit/tests/smoke.sh:569-590`
- **Background/details:** GraphQL and a few Jabber paths have focused unit coverage, but the broader specialist smoke checks primarily test `--help`, closed ports, confirmation gates, and dry-run strings. There are no stateful protocol fixtures asserting SMTP command/reply association, Redis module/config conclusions, ActiveMQ version/object-name behavior, or Openfire partial-step logs.
- **Effectiveness impact:** The false verdicts in S3-04 through S3-21 can pass the current suite; a green build offers limited evidence that specialist conclusions are correct.
- **Evidence/reproduction:** Repository test search found no semantic tests for the SMTP relay/sender/SPF tools, Redis quickwin/restoration, ActiveMQ quickwin/queues, or Openfire success/partial-failure flow. Existing smoke lines 585-590 assert only that mutating helpers dry-run without their gate.
- **Proposed remediation:** Add deterministic local mock servers/fixture responses and test exit code, tier, evidence file, and cleanup-state contracts. Promote false-positive/true-positive cases into the existing FP harness and run them in CI across supported Python/Bash environments.

### S3-24 — Data freshness gate covers only two of the documented/embedded data sources

- **Category:** data-governance coverage gap
- **Severity:** Medium
- **Location:** `aranumtoolkit/tests/data_audit.py:14-42`, `aranumtoolkit/docs/DATA-SOURCES.md:1-19`, `Makefile:20-24`
- **Background/details:** Documentation says each embedded dataset carries source/updated metadata and that `make data-audit` warns when any is stale. The audit has a hard-coded list of only default credentials and the GTFOBins subset. Service metadata is “tracked via git,” and embedded CVE/version rules have no machine-audited refresh stamp.
- **Effectiveness impact:** A successful audit can create false confidence while classification metadata and version-range intelligence age silently.
- **Evidence/reproduction:** `make data-audit` returned 0 and printed exactly two checked paths; `CHECKS` contains exactly two entries.
- **Proposed remediation:** Maintain one machine-readable data registry with source, refreshed date, owner, and maximum age; validate every declared embedded dataset/rule family and fail on missing metadata as well as stale dates. Keep “git tracked” distinct from “reviewed current.”

### S3-25 — Top-level documentation advertises native protocols the credential sweeper intentionally lacks

- **Category:** product-positioning/feature gap
- **Severity:** Low
- **Location:** `README.md:86-92`, `standalones/creds/default-creds-sweep.py:1-16`, `standalones/creds/README.md:73-78`
- **Background/details:** The root README calls the helper a multi-protocol sweep for SSH, MSSQL, MySQL, Redis, and Mongo. The implementation is an HTTP(S) admin-portal sweeper, and its own README explicitly says native service authentication is out of scope and delegated elsewhere.
- **Effectiveness impact:** Operators may expect credential coverage that never occurs, leaving unaudited services while the run appears feature-complete.
- **Evidence/reproduction:** The Python tool uses only urllib HTTP behavior; the specialist README says “HTTP-only by design,” directly contradicting the root table.
- **Proposed remediation:** Correct the root description to “HTTP(S) administrative portal default credentials” and link the native-protocol dispatchers, or implement an explicit orchestrated multi-protocol facade with per-protocol rate/lockout controls.

### S3-26 — Openfire’s advertised cleanup subcommand is only a non-operational scaffold

- **Category:** lifecycle/recovery feature gap
- **Severity:** Medium
- **Location:** `standalones/jabber/openfire-cve-2023-32315.py:268-295`, `standalones/jabber/README.md:105-122`
- **Background/details:** The CLI exposes `cleanup` as the reverse of an exploit run, but it reads and prints the log, performs no HTTP requests, and always returns 78. The README supplies only an interactive manual procedure.
- **Effectiveness impact:** Aranum automates target modification but cannot automate or verify reversal, which is a material completeness gap for repeatable enterprise assessment workflows.
- **Evidence/reproduction:** `cmd_cleanup()` has no network call or state-change operation; its only terminal action is `return 78`.
- **Proposed remediation:** Implement and lab-test authenticated plugin uninstall and user deletion for supported Openfire versions, make actions idempotent, verify absence afterward, and retain the manual fallback for unsupported versions. Until then, label the CLI subcommand `cleanup-plan` rather than implying execution.

## Remediation priority suggestion

1. Fix evidence integrity first: S3-04 through S3-09, S3-11, S3-14, S3-16, S3-19, and S3-21.
2. Make recovery and local gating trustworthy: S3-01 through S3-03, S3-20, S3-23, and S3-26.
3. Close completeness/operability gaps: S3-10, S3-12, S3-13, S3-15, S3-17, S3-18, and S3-22 through S3-25.

The separate validation agent should reproduce the protocol-mock cases and challenge all severity labels before these candidates enter the remediation sprint.
