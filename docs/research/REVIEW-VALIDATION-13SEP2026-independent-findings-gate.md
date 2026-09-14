# Aranum comprehensive review — independent findings gate

Date: 13 September 2026
Validated baseline: `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
Scope: functional correctness, network/host assessment effectiveness, reporting, product coverage, tests, dependencies, release quality, and operator-facing gaps
Explicit exclusion: security of aranum itself

## Gate method

This is an independent source-and-behavior gate over the 71 candidates produced by the three review sprints. A sprint author's conclusion was not treated as evidence. Each item was traced through the current production path and checked with a safe local fixture, command shim, import-level probe, or an exact source predicate where the affected runtime was unavailable. No product source was changed and no live target was scanned.

Decision meanings:

- `APPROVE`: the candidate is accurate enough to enter remediation unchanged.
- `APPROVE-WITH-REVISION`: a real issue exists, but the final category, severity, anchor, or claim below replaces the sprint wording.
- `MERGE`: the behavior is valid but duplicates another accepted finding; only the named canonical finding enters remediation.
- `REJECT`: the claimed behavior was not supported, was out of scope, or was already correct at this baseline.

## Gate outcome

All 71 sprint candidates were adjudicated: 66 `APPROVE`, 5 `APPROVE-WITH-REVISION`, 0 `MERGE`, and 0 `REJECT`. The gate also discovered and approved one adjacent in-scope defect, V-01. The resulting remediation input is 72 distinct findings: 38 High, 30 Medium, and 4 Low.

| Source | Candidates | Approve | Revise | Merge | Reject | Final H / M / L |
|---|---:|---:|---:|---:|---:|---:|
| Sprint 1 | 23 | 23 | 0 | 0 | 0 | 11 / 12 / 0 |
| Sprint 2 | 22 | 19 | 3 | 0 | 0 | 11 / 9 / 2 |
| Sprint 3 | 26 | 24 | 2 | 0 | 0 | 15 / 9 / 2 |
| Sprint-candidate total | 71 | 66 | 5 | 0 | 0 | 37 / 30 / 4 |
| Validator-originated V-01 | 1 | 1 | 0 | 0 | 0 | 1 / 0 / 0 |
| Distinct remediation total | 72 | 67 | 5 | 0 | 0 | 38 / 30 / 4 |

Exact non-default decision sets: `APPROVE-WITH-REVISION = {S2-05, S2-12, S2-13, S3-02, S3-20}`; `MERGE = {}`; `REJECT = {}`. Every other S1/S2/S3 candidate is `APPROVE`, and validator-originated V-01 is also `APPROVE`.

The tables below are the definitive finding list. Only rows marked `APPROVE` or `APPROVE-WITH-REVISION` are eligible for the remediation plan; `MERGE` rows contribute no additional work item and `REJECT` rows must not be implemented as defects.

## Sprint 1 gate — orchestration, data flow, and reporting

All 23 Sprint 1 candidates are approved. The validator independently reproduced each issue.

| ID | Decision | Final category / severity | Definitive anchor | Independent rationale and result |
|---|---|---|---|---|
| S1-01 | APPROVE | False negative / report data integrity — High | `aranumtoolkit/network/report.py:458-480,483-495,900-901` | A new one-rule list reused a cached list ID at iteration 7; `_classify("BETA_ONLY")` returned `None` while direct matching returned `critical`. The full pytest run also failed this invariant once. |
| S1-02 | APPROVE | Failure semantics / automation correctness — High | `aranumtoolkit/network/auto-enum.sh:502-511,548-561`; `aranum.py:634-648` | A copied dispatcher returning 7 produced `.rc=7`, `FAIL=1`, and overall process status 0. |
| S1-03 | APPROVE | Run-state accounting / resume correctness — Medium | `aranumtoolkit/network/auto-enum.sh:413-418,510-535` | In parallel resume mode, `.done` plus stale `.rc=9` printed `SKIPPED` and then `OK=0 FAIL=1 SKIP=0`; the skip counter was lost with the subshell. |
| S1-04 | APPROVE | Protocol identity / queue data loss — High | `aranumtoolkit/network/plan.py:293-301,383-420` | Same-host port 53 TCP and UDP produced four pre-dedup tasks but only the two TCP phase tasks survived; protocol is absent from `task_id`. |
| S1-05 | APPROVE | Distributed execution / queue partitioning — Medium | `aranumtoolkit/network/plan.py:402-420` | Duplicate DNS inventory records placed the same two task IDs in shard 1/2 and shard 2/2 because selection precedes deduplication. |
| S1-06 | APPROVE | Planning/execution contract / false completion — High | `aranumtoolkit/network/auto-enum.sh:286-305,423-500`; `aranumtoolkit/network/plan.py:342-400` | With phase 1 above and phase 2 below the priority threshold, one dispatcher invocation ran and writeback marked both phase IDs `done`. Phase, protocol, task ID, risk, and priority do not reach the dispatcher. |
| S1-07 | APPROVE | Input validation / fail-open orchestration — High | `aranumtoolkit/network/auto-enum.sh:286-306,542-561` | `{broken json` raised `JSONDecodeError`, but the shell ran an empty service set, printed `OK=0 FAIL=0`, and returned 0. |
| S1-08 | APPROVE | CLI argument propagation — Medium | `aranum.py:65-81,587-629`; `aranumtoolkit/network/auto-enum.sh:151` | `_prepare_run_args(['--service-parallel','4','scan.xml','--dry-run'])` produced `['-i','4','--service-parallel','scan.xml','--dry-run']`. |
| S1-09 | APPROVE | Inventory coverage / misleading summary — Medium | `aranumtoolkit/network/nmap-parse.py:244-280,458-479`; consumers `auto-enum.sh:273-283`, `plan.py:423-426` | XML containing two up hosts, one with no open port, emitted one service entry and reported one host. |
| S1-10 | APPROVE | Iterative evidence mining / feature disconnect — Medium | `aranumtoolkit/network/iterative-enum.sh:117-126,359-365` | A canonical raw inventory with an SMB target plus `raw/smb/prior.txt` containing `user: alice` completed with status 0 and generated an empty `inputs/smb/users.txt`. |
| S1-11 | APPROVE | Triage prioritization / metadata semantics — High | `service-metadata.json:15-17`; `report.py:211-229`; `report-dashboard.py:265-282` | A critical Redis finding was emitted with `confidence=medium`, `priority=P3`, and only the generic action because global defaults suppress severity-derived values. |
| S1-12 | APPROVE | Configuration override / contract drift — Medium | `aranumtoolkit/network/report.py:88-125` | An out-dir Redis title override was ignored; the existing repository file always returns first despite the documented local override path. |
| S1-13 | APPROVE | Rule precedence / feature contract — Medium | `aranumtoolkit/network/report.py:28-29,483-517,1200` | A custom `OpenSSH -> high` rule was loaded but the built-in earlier rule classified the line `low`. The module-level override promise and CLI's additions wording are inconsistent. |
| S1-14 | APPROVE | Reporting semantics / coverage gap — Medium | `aranumtoolkit/network/report.py:981-1009` | A completed SSH evidence directory with no matched issue produced zero findings and summary `hosts=[]`, `services=[]`; assessed-clean and unassessed are indistinguishable. |
| S1-15 | APPROVE | Deduplication / false-positive inflation — Medium | `aranumtoolkit/network/report.py:814-882`; `report-dashboard.py:392-436` | The same SMB-signing line in host evidence and `_dispatcher.log` yielded two medium findings, one endpoint-attributed and one dispatcher-attributed. |
| S1-16 | APPROVE | Change detection / silent false negative — High | `aranumtoolkit/network/autoenum-diff.sh:46-56,77-110` | Port 80 to 443 with otherwise equal fields returned 0; a change only after character 120 also returned 0. Port and complete evidence text are absent from identity. |
| S1-17 | APPROVE | Schema contract / consumer compatibility — High | `aranumtoolkit/network/merge-results.py:183-192`; `aranumtoolkit/docs/SCHEMA.md:3-24` | A valid v2 source merged with status 0, but the top-level `schema_version` was absent. |
| S1-18 | APPROVE | Output metadata accuracy — Medium | `aranumtoolkit/network/merge-results.py:183-192` | A redacted source and `<TARGET-1>` host were preserved while the merged artifact hard-coded `redacted=false`. |
| S1-19 | APPROVE | Evidence provenance / partial failure — Medium | `aranumtoolkit/network/merge-results.py:137-154` | With `copy2` forced to raise `OSError`, the finding referenced `evidence/src00-src/e.txt`; that path did not exist, although a warning was added. |
| S1-20 | APPROVE | Interop discovery / coverage loss — High | `aranumtoolkit/interop/aranum_to_recce.py:248-288`; `auto-enum.sh:267-270` | A standard session resolved `raw/` but not `raw/inventory.json`; an input `.gnmap` was also ignored because discovery searches only `.xml`. |
| S1-21 | APPROVE | Protocol mapping / interop corruption — High | `aranumtoolkit/interop/aranum_to_recce.py:213-244,376-399`; `report.py:202-231` | Inventory `161/udp` plus one SNMP finding created both `161/udp` and fabricated `161/tcp`; the vulnerability was attached as TCP. |
| S1-22 | APPROVE | Coverage-state correctness / false completion — High | `aranumtoolkit/interop/aranum_to_recce.py:319-340,416-421` | The same Recce fixture marked the unrelated inventory-only SSH port and both SNMP ports `vuln_scanned=True`, and the host `enumerated=True`, without consuming execution state. |
| S1-23 | APPROVE | IPv6 reporting / host attribution — Medium | `aranumtoolkit/network/report-dashboard.py:392-436` | A known target `[2001:db8::1]:6379` and dispatcher critical line for that endpoint remained under host `(dispatcher)` because re-attribution is IPv4-only. |

## Sprint 2 gate — network and host enumeration

Sprint 2 has 19 approvals and 3 approvals with revision. No candidate was merged or rejected. S2-05 retains its real nondefault-port failure but drops the incorrect IPv6 claim. S2-12 is narrowed and lowered to Low. S2-13 adds the second counter path omitted by the candidate.

| ID | Decision | Final category / severity | Definitive anchor | Independent rationale and result |
|---|---|---|---|---|
| S2-01 | APPROVE | Failure semantics / evidence loss — High | `aranumtoolkit/network/_lib.sh:23-32`; representative `enum-x11.sh:7-21` | `parse_common_args` returned 0 after `mkdir -p` failed against a regular-file output. The X11 dispatcher then failed evidence redirection, printed its done message, and returned 0. |
| S2-02 | APPROVE | Endpoint identity / evidence integrity — High | `bulk-enum-linux.sh:348-386`; `bulk-enum-windows.py:143-163,588-597` | Two Linux dry-run specs for different users and ports on one IP pointed to the same host-only directory. Windows uses the same host-only artifact/state key. |
| S2-03 | APPROVE | Resume state / false completion — High | `bulk-enum-linux.sh:388-390,449-470`; `bulk-enum-windows.py:601-603,636-653` | A pre-existing `.done` survived a non-resume Windows run ending `REMOTE_ERR`; the analogous Linux path also clears no prior marker before execution. |
| S2-04 | APPROVE | Input validation / scale control — Medium | `bulk-enum-linux.sh:163,176-180,537-540`; `bulk-enum-windows.py:728-747,828-842` | Linux `-P 0 --dry-run` returned 0 and delegates unlimited concurrency to `xargs -P0`; Windows `-P 0` reached `ThreadPoolExecutor(0)` and raised an uncaught `ValueError`. |
| S2-05 | APPROVE-WITH-REVISION | Transport endpoint correctness — High | `ssh-triage.sh:382-396,460-479`; `bulk-enum-windows.py:239-282,508-516` | **Final finding:** Windows-over-SSH discards a classified target's nondefault port. A target with `port=2222` was forwarded to `build_ssh_argv` with the global default 22. Delete the candidate's IPv6 claim and bracket remediation: OpenSSH correctly accepts the unbracketed IPv6 destination. |
| S2-06 | APPROVE | Cross-port evidence contamination / false positives and negatives — High | `aranumtoolkit/network/enum-ssh.sh:39-55,70-100,109-135` | A two-port shim left only the port-22 banner and generated both port-qualified CVE signal files from that same banner, losing port-2222 evidence and misattributing port-22 evidence. |
| S2-07 | APPROVE | Protocol selection / false-negative coverage — High | `nmap-parse.py:99`; `enum-ldap.sh:9-18,34-62,144-189`; `_lib.sh:113-126` | The parser routes 389/636/3268/3269, but the dispatcher reduces all targets to IPs and invokes `ldap_url` without port/scheme. LDAPS and Global Catalog endpoint identity is unrecoverable. |
| S2-08 | APPROVE | Protocol implementation / missing authenticated coverage — High | `enum-imap.sh:25-35,66-75`; `enum-pop3.sh:24-34,65-78` | An OpenSSL shim observed no stdin on IMAPS because `< /dev/null` overrides the capability pipe. POP3S uses the same construction; both auth branches explicitly exclude implicit-TLS ports. |
| S2-09 | APPROVE | Authentication-result parsing / false positive — High | `aranumtoolkit/network/enum-pop3.sh:65-76` | Greeting  `+OK`, accepted USER, rejected PASS, and successful QUIT still emitted `POP3 AUTH SUCCESS`; the implementation counts unrelated `+OK` lines rather than the PASS response. |
| S2-10 | APPROVE | Protocol mode mismatch / feature gap — Medium | `nmap-parse.py:109-110`; `enum-smtp.sh:17-37,52-57`; `enum-ftp.sh:9-19,31-36` | Ports 465 and 990 route to SMTP/FTP, but first-party probes use plaintext `nc`/`/dev/tcp`/`ftp://`; FTP's Nmap follow-up is fixed to port 21. No implicit-TLS branch exists. |
| S2-11 | APPROVE | Service classification / false routing — Medium | `nmap-parse.py:95-96,149,233-241`; `enum-x11.sh:10-18` | `categorize(6000, 'ssl')`, `categorize(6000, 'unknown')`, and `categorize(6000, 'x11')` all returned only `['x11']`. Positive incompatible service evidence cannot override the port heuristic. |
| S2-12 | APPROVE-WITH-REVISION | Product coverage opportunity — **Low** | Current absence across `nmap-parse.py:95-230` and `enum-*.sh`; generic conflicts at `nmap-parse.py:106,109,126,149` | **Final finding:** there is no bounded multi-signal Bambu/BBL device fingerprint despite established tuple/banner/certificate evidence. Narrow the impact: port 3000/3002 can fall through generic unknown triage and 8883 has compatible MQTT coverage; the concrete 990/6000 transport mismatches are already S2-10/S2-11. Add a conservative correlation feature, not a port-only identity. |
| S2-13 | APPROVE-WITH-REVISION | Standalone output correctness — Low | `standalones/linux/apt-source-check.sh:21-37,47-52` | Pipeline-subshell increments for writable apt files are lost, and the separate writable `APT_CONFIG` branch also prints a hit without incrementing `hits`. Either can precede the contradictory `No writable apt configuration surface found`. |
| S2-14 | APPROVE | Host-enumeration detection logic / false negatives — High | `Get-ServiceMisconfig.ps1:35-43`; `Get-UnquotedServices.ps1:25-45`; `Invoke-PrivEscEnum.ps1:90-119` | The quoted-path expression turns `"C:\Program Files\Vendor\svc.exe" -d` into `C:\Program`; the unquoted helper also keeps only `C:\Program` and never constructs the loader's progressive `.exe` candidates. |
| S2-15 | APPROVE | Host-enumeration predicate / false negatives — Medium | `standalones/windows/Invoke-PrivEscEnum.ps1:208-217` | `Select-String -SimpleMatch` receives one regex-shaped pipe-delimited string, so ordinary `password=...` content does not match. |
| S2-16 | APPROVE | Path construction / dead enumeration branch — Medium | `Invoke-PrivEscEnum.ps1:160-165`; comparison `Get-GPPCPassword.ps1:27-30` | Single quotes preserve the literal `\\$env:USERDOMAIN\SYSVOL`; the aggregate checks a nonexistent server name rather than interpolating a domain. |
| S2-17 | APPROVE | Detection correctness / false positive — High | `Get-ADCSMisconfig.ps1:7-13,85-105` | ESC1's condition omits the collected enrollment ACL entirely. A restricted administrator-only template satisfying attribute predicates can be labeled vulnerable to a low-privileged caller. |
| S2-18 | APPROVE | Feature gap / documentation accuracy — Medium | `Get-ADCSMisconfig.ps1:1-17,31,92-125`; `wiki/windows.md:136-150` | The helper contains only ESC1/2/4 counters/branches while the wiki promises ESC1-ESC8. The Certipy LDAP path does not make the host-local claim true. |
| S2-19 | APPROVE | Scale feature gap / option contract — Medium | `standalones/ot/ot-enum.sh:34-40,48-77,113-128`; protocol dispatchers, e.g. `enum-modbus.sh:23-61` | `OT_MAX_PARALLEL` is exported and logged but none of seven serial dispatcher loops consumes it; the option changes no scheduling behavior. |
| S2-20 | APPROVE | Authentication planning / false-negative coverage — Medium | `ssh-key-triage.py:133-182,191-304,552-571` | Attempt caps are applied to every sorted inventory path before error/encryption/probeability filtering. Even a passphrase-unlocked key is probed as its original encrypted file under noninteractive SSH. |
| S2-21 | APPROVE | Workflow integration / output contract — High | `ssh-key-triage.py:25-27,454-467`; `bulk-enum-linux.sh:85-99,348-370` | `authorized-pairs.txt` emits `key,user,host`, but the named bulk consumer accepts only host/user@host specs and one global key. Direct input turns the comma-filled row into a hostname. |
| S2-22 | APPROVE | Rate control / behavioral contract — Medium | `ssh-key-triage.py:20-23,323-337,609-627` | All futures are submitted together and each worker sleeps independently, so parallel attempts wake and connect as a burst rather than respecting a global inter-attempt interval. |

### Validator-originated finding

| ID | Decision | Final category / severity | Definitive anchor | Independent rationale and result |
|---|---|---|---|---|
| V-01 | APPROVE | IPv6 transport endpoint correctness — High | `bulk-enum-linux.sh:393-410,497`; `ssh-key-triage.py:301-303` | While disproving S2-05's Windows IPv6 claim, the gate found the inverse defect in two other paths: they change a valid OpenSSH destination into `user@[IPv6]`. `ssh -G` preserves the brackets as part of the hostname and a real `ssh` attempt fails name resolution. Pass the bare IPv6 host to `ssh`; brackets belong to URI/SCP-style host delimiters, not the `ssh` destination argument. |

## Sprint 3 gate — specialist tools and quality systems

Sprint 3 has 24 approvals and 2 approvals with revision. S3-02 is lowered from High to Medium because it visibly fails closed at the developer gate. S3-20 is rewritten to distinguish the recoverable missing-argument branch from the unrecoverable unreadable-path branch.

| ID | Decision | Final category / severity | Definitive anchor | Independent rationale and result |
|---|---|---|---|---|
| S3-01 | APPROVE | Dependency detection / exit-status logic — High | `deps-check.sh:10-23,47-55,257-269` | `bash deps-check.sh` returned 0 despite two required misses and several shims whose invoked command returned 127; the `dig` row probes a package-hint string rather than the executable. |
| S3-02 | APPROVE-WITH-REVISION | Build reliability / degraded-mode logic — **Medium** | `Makefile:52-70` | A present but non-runnable ShellCheck shim bypassed the syntax fallback and made `make lint` return 2. This is a visible, fail-closed QA outage, not silent runtime-result corruption; Medium is the calibrated severity. |
| S3-03 | APPROVE | CI/test integration gap — High | `.github/workflows/ci.yml:3-5,47-69`; `Makefile:38-39,76-87` | Unittest ran 278 tests while pytest collected 309; CI invokes lint, unittest, and smoke but no pytest target despite claiming to mirror the full local gate. |
| S3-04 | APPROVE | Protocol-state logic / false positive — High | `standalones/smtp/smtp-quickwin.sh:52-70,86-96` | A reject-all RCPT mock still produced CRITICAL because unrelated 250 replies from earlier SMTP commands satisfy whole-transcript greps. |
| S3-05 | APPROVE | Assessment logic / documentation error — High | `smtp-relay-test.sh:71-73,83-105`; `smtp/README.md:104-108` | A domain-aware mock accepted ordinary external-to-local delivery and rejected unauthenticated local-looking-to-external delivery; the tool labeled the former relay-open and the documentation expects the latter accepted. |
| S3-06 | APPROVE | Protocol-state logic / exit-status correctness — High | `standalones/smtp/smtp-phish-send.sh:137-151` | RCPT 550 and DATA 554 still printed `Message accepted` and returned 0 because an earlier generic 250 matched. |
| S3-07 | APPROVE | Shell parsing / uninitialized state — High | `standalones/smtp/spf-dmarc-check.sh:16-35,39-60,81-90` | SPF `v=spf1 -all` with no DMARC caused grep option parsing and then `policy: unbound variable`, terminating the verdict. |
| S3-08 | APPROVE | Capability inference / false positive — High | `standalones/redis/redis-quickwin.sh:88-106`; `redis/module/README.md:35-37` | A Redis 7.2 fixture with `enable-module-command no` permitted `MODULE LIST` and rejected `MODULE LOAD`; quickwin retained `module_capable=1`. Listing is not proof of load permission. |
| S3-09 | APPROVE | Target-state restoration / logic error — High | `redis-rce-module.sh:119-140,193-217`; `_redis_lib.sh:104-115` | Cleanup unconditionally executes `REPLICAOF NO ONE`; saved state omits original role/upstream and `masterauth`, so a pre-existing replica cannot be restored. |
| S3-10 | APPROVE | Packaging / offline readiness — Medium | `redis/module/README.md:9-19`; `module/Makefile:1-22`; `redis-rce-module.sh:106-115`; `.gitignore:1-5,33-35` | `system.so` is absent, untracked, and ignored despite documentation saying it is checked in; runtime silently falls back to a compiler build. |
| S3-11 | APPROVE | Version classification / false positive — High | `standalones/activemq/activemq-quickwin.sh:50-61`; `activemq/README.md:41-49` | A patched-version OpenWire signature fixture was assigned CRITICAL without any version acquisition or range predicate. |
| S3-12 | APPROVE | Event ordering / missed evidence — Medium | `activemq-cve-2023-46604.py:188-219` | Instrumented order was payload connect/send/close followed by callback bind; a fast proof callback can arrive before a listener exists. |
| S3-13 | APPROVE | Jolokia object discovery / parsing — Medium | `standalones/activemq/activemq-queues.sh:42-70,76-85` | Initial discovery fixes `brokerName=localhost`; queue names are shell-word-split and inserted unescaped, and empty output is counted as one. |
| S3-14 | APPROVE | CLI exit-status contract — High | `standalones/graphql/gql.py:448-465` | Raw mode printed a connection `_error` object for a refused port and returned 0 before error/status evaluation. |
| S3-15 | APPROVE | Response classification / false negative — Medium | `standalones/graphql/gql.py:707-725` | Valid values `false`, `0`, `[]`, and `""` all made `has_data=False`; response presence is incorrectly reduced to truthiness. |
| S3-16 | APPROVE | Assessment methodology / false positive — High | `standalones/graphql/gql.py:952-980` | Successful GET of read-only `__typename` was labeled CRITICAL arbitrary-query/mutation CSRF, without mutation, authenticated browser context, or a missing defense. |
| S3-17 | APPROVE | Feature wiring / invalid inference — Medium | `standalones/graphql/gql.py:602-625,983-1005` | Captured alias-DoS requests contained only repeated `__typename`; the selected operation/schema arguments never affect the request, while one latency ratio drives a categorical conclusion. |
| S3-18 | APPROVE | Documentation/CLI drift — Low | `standalones/graphql/README.md:176-182`; `gql.py:1037-1053` | The documented `gql.py ls --no-schema` command returned argparse status 2 because that option is not accepted by `ls`. |
| S3-19 | APPROVE | Authentication-response inference / false positive — High | `jabber-user-enum.py:14-29,159-190,297-325` | Direct classification mapped generic SASL `<not-authorized/>` to categorical `USER_EXISTS` despite the documented indistinguishability condition. |
| S3-20 | APPROVE-WITH-REVISION | Mutation ordering / recoverability — High | `openfire-cve-2023-32315.py:164-225,309-316` | **Final finding:** plugin prerequisites are validated only after admin creation. Missing `--plugin-jar` makes one create request, returns 1, and writes `step1_only`; a supplied nonexistent/unreadable path makes one create request, raises at line 225, and writes no recovery log. Preflight readability before any mutation. |
| S3-21 | APPROVE | Verification / exit-status correctness — High | `openfire-cve-2023-32315.py:237-250` | Simulated upload HTTP 500 still returned 0 and logged `step_reached=full_chain`; 200/302 also lacks deployed-plugin/webshell verification. |
| S3-22 | APPROVE | Protocol feature gap — Medium | `standalones/redis/_redis_lib.sh:24-43,52-101` | Shared Redis command construction supports only password authentication; no named ACL username is accepted or passed. |
| S3-23 | APPROVE | Regression-test coverage gap — High | `aranumtoolkit/tests/smoke.sh:45-65,170-239,349-370,569-590` | Repository test search found gates/help/dry-run checks but no semantic fixtures for the named SMTP, Redis, ActiveMQ, or Openfire verdict/cleanup paths, allowing the reproduced failures to pass. |
| S3-24 | APPROVE | Data-governance coverage gap — Medium | `aranumtoolkit/tests/data_audit.py:14-42`; `docs/DATA-SOURCES.md:1-19`; `Makefile:20-24` | `make data-audit` checked exactly two hard-coded datasets; other documented/embedded metadata and rule families lack audited freshness entries. |
| S3-25 | APPROVE | Product-positioning/feature gap — Low | `README.md:86-92`; `default-creds-sweep.py:1-16`; `standalones/creds/README.md:73-78` | Root docs promise native SSH/database protocol credentials, while implementation and specialist docs explicitly define an HTTP(S)-only portal sweeper. |
| S3-26 | APPROVE | Lifecycle/recovery feature gap — Medium | `openfire-cve-2023-32315.py:268-295`; `jabber/README.md:105-122` | Instrumented cleanup returned 78 with zero network calls. The README admits manual cleanup, but CLI/module help still describes the subcommand as reversal and the mutating workflow has no automated verification. |

## Cross-sprint reconciliation

No candidate is a duplicate at the remediation-unit level. Several findings share a theme but fail at different layers and require different code changes:

| Related IDs | Why they remain separate |
|---|---|
| S1-02, S2-01, S3-01 | S1-02 discards a dispatcher's nonzero status at campaign completion; S2-01 lets a dispatcher report success after evidence-directory failure; S3-01 falsely passes dependency preflight. Fixing one does not repair either other layer. |
| S1-03, S2-03 | S1-03 is cross-service parallel aggregation using stale `.rc` records and losing subshell skips; S2-03 is per-endpoint bulk resume state surviving a failed new run. |
| S1-16, S2-02, S2-06 | S1-16 loses endpoint identity during cross-run diffing; S2-02 collides bulk output directories; S2-06 overwrites per-port SSH evidence before reporting. |
| S1-21, S1-23, V-01 | These respectively corrupt protocol in Recce, fail IPv6 host attribution in the dashboard, and pass an invalid bracketed IPv6 hostname to OpenSSH. They affect different consumers. |
| S2-10, S3-04, S3-05, S3-06 | S2-10 is implicit-TLS transport selection; the S3 items are distinct SMTP reply association, relay-boundary semantics, and message-delivery status parsing. |
| S3-03, S3-23 | S3-03 omits existing pytest tests from CI; S3-23 identifies semantic protocol/lifecycle tests that do not exist yet. |
| S3-20, S3-21, S3-26 | These are independently necessary Openfire lifecycle repairs: prerequisite-before-mutation ordering, truthful upload/full-chain verification, and operational cleanup. |

The incorrect IPv6 half of S2-05 was not retained. It was replaced by the source-accurate V-01 rather than being silently folded into S2-05.

## Independent commands and results

The following commands were executed from `/home/jay/Documents/cyber/dev/aranum` at the validated commit.

| Command or fixture | Result |
|---|---|
| `git rev-parse HEAD` | `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` |
| `git status --short --branch` before validation | Branch `feat/bulk-enum-fix-expand`; only the untracked review `docs/` tree was present. No product edits were introduced. |
| `python3 -m pytest aranumtoolkit/tests/ -q` | `303 passed, 1 failed, 5 skipped, 68 subtests passed` in 84.86s. The one failure was `TestClassifyPrefilter.test_prefilter_matches_brute_force`: `None != 'critical'`, independently manifesting S1-01. |
| `ssh -G 'alice@2001:db8::1'` | Parsed `user alice`, `hostname 2001:db8::1`, `port 22`; this disproved the IPv6 half of candidate S2-05. |
| `ssh -G 'alice@[2001:db8::1]'` | Parsed the literal hostname `[2001:db8::1]`; brackets are not the corrective action for OpenSSH's `ssh` destination argument. |
| Isolated copied `auto-enum.sh` plus a fake `enum-ssh.sh` returning 7 | Dispatcher `.rc=7`, summary `FAIL=1`, overall status 0 (S1-02). |
| Same fixture with `.done`, stale `.rc=9`, `--resume --service-parallel 2` | Service printed `SKIPPED`, then summary `FAIL=1 SKIP=0`, overall status 0 (S1-03). |
| Same fixture with two queue phases and threshold selecting phase 1 only | One dispatcher invocation; state file marked phase 1 and phase 2 `done` (S1-06). |
| Same fixture with queue line `{broken json` | Python traceback, empty service run, summary `OK=0 FAIL=0`, overall status 0 (S1-07). |
| Temporary parser/planner/report/merge/diff/Recce fixtures described in the Sprint 1 ledger | Every S1-04 through S1-23 observed the value stated in its ledger row; all files were under `TemporaryDirectory` and no network request was made. |

Additional independent checks used for Sprints 2 and 3:

| Command or fixture | Result |
|---|---|
| `python3 -m pytest aranumtoolkit/tests/test_bulk_enum_linux_auth.py aranumtoolkit/tests/test_bulk_enum_windows.py aranumtoolkit/tests/test_bulk_enum_windows_transports.py aranumtoolkit/tests/test_ssh_triage.py aranumtoolkit/tests/test_ssh_key_triage.py aranumtoolkit/tests/test_nmap_parse.py aranumtoolkit/tests/test_dispatcher_contract.py aranumtoolkit/tests/test_new_dispatchers_tp.py aranumtoolkit/tests/test_wiki.py -q` | `143 passed, 53 subtests passed` in 15.12s. The suite's green status does not cover the adversarial paths in the gate. |
| `bash deps-check.sh` | Status 0 with two required misses and four non-runnable shim/version results (S3-01). |
| `shellcheck --version`; `make lint` | ShellCheck status 127; lint status 2 rather than the documented fallback (S3-02). |
| `python3 -m unittest discover -s aranumtoolkit/tests -p 'test_*.py' -v`; `python3 -m pytest aranumtoolkit/tests/ --collect-only -q` | 278 unittest tests executed versus 309 pytest-collected tests, confirming CI coverage drift (S3-03). |
| Regular-file dispatcher output fixture | `mkdir` and evidence redirection failed; dispatcher printed done and returned 0 (S2-01). |
| Bulk endpoint fixtures for two users/ports and success-to-failure resume | Host-only directory collision; failed latest run retained prior `.done` (S2-02/S2-03). |
| Bulk parallel validation with `-P 0` and Windows worker count 0 | Linux returned 0 with unlimited xargs; Windows raised `ValueError: max_workers must be greater than 0` (S2-04). |
| Two-port SSH banner/auth shim | Port 22 evidence overwrote port 2222 and drove both port-qualified CVE outputs (S2-06). |
| IMAPS OpenSSL stdin shim and POP3 transcript shim | IMAPS recorded `NO_STDIN`; rejected PASS still emitted authentication success (S2-08/S2-09). |
| PowerShell expression probes | Quoted and unquoted service examples both truncated to `C:\Program`; `password=hunter2` did not match the literal SimpleMatch expression; the SYSVOL UNC retained literal `$env:USERDOMAIN` (S2-14/S2-15/S2-16). |
| SSH key planner invalid-first/valid-second with cap 1; four-worker 0.2 s throttle timestamp shim | Only invalid key was planned; four connections began within 0.001 s (S2-20/S2-22). |
| SMTP local mocks: RCPT-reject-all, local-delivery-only, and rejected RCPT/DATA | Reproduced CRITICAL quickwin, false relay-open on normal inbound delivery, and false send success/status 0 (S3-04/S3-05/S3-06). |
| Fake `dig` returning `v=spf1 -all` and no DMARC | Grep option error followed by unbound `policy` (S3-07). |
| Redis 7.2 fixture with `enable-module-command no` | `MODULE LIST` succeeded while `MODULE LOAD` was denied; quickwin retained its module-capable conclusion (S3-08). |
| ActiveMQ signature and event-order fixtures | Patched/unspecified version signature became CRITICAL; callback bind occurred only after payload send/close (S3-11/S3-12). |
| `python3 standalones/graphql/gql.py --url http://127.0.0.1:1/graphql --raw-response raw --query 'query { __typename }'` | Printed a connection-error JSON object and returned 0 (S3-14). |
| Direct GraphQL response/CSRF/alias fixtures | `false`, `0`, `[]`, and empty string counted as no data; read-only GET became CRITICAL; alias requests ignored the selected operation (S3-15/S3-16/S3-17). |
| `python3 standalones/graphql/gql.py ls --no-schema` | Argparse rejected the documented option with status 2 (S3-18). |
| Openfire monkeypatches for missing JAR, nonexistent JAR, upload 500, and cleanup | Missing argument wrote `step1_only`; nonexistent path mutated then raised without a log; HTTP 500 returned 0/full-chain; cleanup returned 78 with zero requests (S3-20/S3-21/S3-26). |
| `git ls-files standalones/redis/module`; file existence check | `system.so` neither tracked nor present and is ignored (S3-10). |
| `make data-audit` | Status 0 after checking exactly two hard-coded paths (S3-24). |

## Approved remediation input

The validated work naturally divides into the requested three remediation phases. Every approved finding appears exactly once below.

### Phase R1 — trustworthy orchestration, artifacts, and quality gates

IDs: S1-01 through S1-23; S2-01 through S2-04; S3-01 through S3-03. Total: 30.

Primary outcome: campaigns, queues, reports, merge/diff artifacts, Recce exports, dependency checks, and CI must preserve canonical identity and distinguish success, failure, skip, clean assessment, and unassessed state. Acceptance should include failure-injection fixtures, protocol-aware task IDs, run-scoped state, complete schema/redaction provenance, logical finding deduplication, and both unittest and pytest paths in CI.

### Phase R2 — endpoint, transport, and host-detection correctness

IDs: S2-05 through S2-22 and V-01. Total: 19.

Primary outcome: preserve user/host/port/protocol from discovery through probe and evidence; use protocol-correct TLS modes; parse the exact command response that determines a verdict; make Windows/AD predicates match documented prerequisites; and make scale/rate controls real. Acceptance should use contradictory multi-port endpoints, IPv4/IPv6, implicit TLS, positive/negative protocol transcripts, same-host multi-user state, and Windows predicate fixtures.

### Phase R3 — specialist verdict semantics, lifecycle, and coverage

IDs: S3-04 through S3-26. Total: 23.

Primary outcome: specialist tools must not elevate indeterminate behavior to confirmed findings, mutation helpers must preflight/verify/restore their full lifecycle, modern authentication and offline packaging claims must work as documented, and semantic protocol fixtures must enter the standard CI/data gates. Acceptance should cover SMTP stages and relay boundaries, Redis permission/restoration variants, ActiveMQ version/object discovery, GraphQL result/method semantics, Jabber controls, and Openfire partial/full/cleanup transitions.

The revisions in this gate are binding for planning: do not add IPv6 brackets to S2-05, do not treat the narrowed Bambu gap above Low, include both APT counter paths, keep S3-02 at Medium, and preserve S3-20's distinction between the logged missing-argument case and the unlogged unreadable-path case.

## Validation limits

- No enterprise network or live service estate was scanned. Protocol behavior was reproduced with local shims/mocks or established directly from the executed control flow.
- Optional Recce was represented with a minimal in-memory model/store boundary; this was sufficient to observe protocol and completion-state translation without claiming a real Recce end-to-end run.
- Windows/AD predicates were source-checked and parser-checked; no domain-joined Windows lab was available for live validation.
- The Bambu support gap was validated against current repository coverage and prior authorized-lab evidence; the printer itself was not re-probed in this gate.
- Redis findings that require a live Redis runtime were admitted only where the current branch predicates or cleanup sequence alone prove the result; no live Redis target was used.
- Security hardening of aranum itself was not reviewed.
