# TESTPLAN-001 — Comprehensive Functional Test Campaign (07 JUN 2026)

**Goal:** Prove every parser and every feature of aranum is bulletproof, via paired
**positive** (valid input → correct output) and **negative** (malformed / hostile /
edge input → graceful, safe failure) testing. Real services are stood up in Docker;
the live `192.168.1.0/24` segment is used for end-to-end validation. Authorized:
operator owns the lab + home segment.

Status legend per item: ✅ pass · ❌ bug filed · ⚠️ partial/blocked · — not yet run.

---

## 1. Definitions of "bulletproof"

A unit is bulletproof when, across the positive **and** negative matrix, it:
1. **Positive:** produces correct, asserted output on valid input (exact values, not "ran ok").
2. **Negative — fails safe:** on malformed/empty/hostile/oversized input it exits with a
   clear stderr message and a **defined non-zero code**, never a Python traceback, never a
   bash `unbound variable`/syntax abort, never a silent no-op that looks like success.
3. **Never hangs:** every external operation is time-bounded; a tarpit/black-hole target
   cannot wedge the run.
4. **No injection / no escape:** hostile hostnames, ports, banners, filenames, session
   names cannot inject shell/SQL/XPath, traverse the filesystem, or trigger a write to a
   target without an explicit `--write`/`--exploit`/`--rce`/`--send` gate (CLAUDE.md §9).
5. **Deterministic exit contract:** documented exit codes hold (0 ok, 2 usage/parse, 3 XXE
   refusal, 7 planner bail, 78 config-refusal, etc.).

---

## 2. Surface under test (complete inventory)

**Core Python (7):** `aranum.py`, `nmap-parse.py`, `report.py`, `report-dashboard.py`,
`merge-results.py`, `plan.py`, `bulk-enum-windows.py`.

**Standalone Python (10):** `activemq-cve-2023-46604.py`, `creds/{default-creds-sweep,
hash-format,spray-scheduler}.py`, `graphql/gql.py`, `jabber/{jabber-user-enum,
jabber-validate,openfire-cve-2023-32315}.py`, `redis/redis-rogue-master.py`,
`smtp/smtp-smuggling-test.py`.

**Network dispatchers (61):** activemq ajp artifact backup cassandra consul couchdb dns
docker elastic etcd flexnet ftp hpc http https ike imap influxdb ipmi ipp jabber jmx kafka
kerberos kubernetes ldap memcached mongo monitoring mqtt msrpc mssql mysql neo4j netbios-ns
nfs oracle platform pop3 postgres print rabbitmq radius rdp redis rsync sip slp smb smtp snmp
solr storage telnet unknown vault vnc winrm zookeeper. (Gated: ike, radius, slp.)

**Orchestration:** `auto-enum.sh`, `iterative-enum.sh`, `bulk-enum-linux.sh`,
`bulk-enum-windows.py`, `autoenum-diff.sh`, `_lib.sh` (shared arg/throttle/curl/nmap libs).

**Standalone families (9):** activemq, creds, graphql, jabber, linux (16 privesc checks),
ot (7 ICS probes, all read-only/gated), redis, smtp, windows (8 AD PS1).

**Reporting pipeline:** nmap-parse → dispatch → report (md/html/json + severity rules +
redaction + structured v2) → report-dashboard (multi-page HTML + data.json) → merge-results.

---

## 3. Methodology

- **Parsers tested input-first**, decoupled from the network: build a fixture corpus of
  malformed/edge inputs and assert exit code + stderr + that no partial/garbage output is
  emitted. This is the highest-value, fully-deterministic bulletproofing work.
- **Service dispatchers tested against real Docker containers** for the positive path, and
  against (a) a closed port, (b) a *wrong* service on the expected port (shape-mimicry /
  false-positive class), and (c) a hostile banner where feasible, for the negative path.
- **Orchestration tested end-to-end** against the Docker lab subnet and the live segment.
- Every command run under `timeout` so a single hang can't wedge the campaign.
- Findings logged to `outputs/testcampaign-07JUN2026/` (gitignored); bugs fixed on a
  `dev/test-hardening` branch with a regression test added per bug before moving on.

---

## 4. Docker service lab (Phase 0)

A single user-defined bridge network `aranumlab` (subnet pinned, e.g. `172.30.0.0/24`) with
one container per service, static IPs, brought up/down via a campaign compose file under
`outputs/testcampaign-07JUN2026/lab/` (NOT committed). Target image set (positive path):

| Family | Image | Notes / negative twist |
|---|---|---|
| http/https | `nginx`, `vulnerables/web-dvwa` | TLS via self-signed; serve a fake non-HTTP banner on :80 for shape-mimicry |
| ftp | `fauria/vsftpd` | anon on/off |
| smtp | `rnwood/smtp4dev` or `namshi/smtp` | open-relay vs locked |
| pop3/imap | `dovecot/dovecot` | |
| redis | `redis:alpine` | unauth vs `--requirepass` |
| postgres | `postgres` (`POSTGRES_HOST_AUTH_METHOD=trust`) | trust vs scram |
| mysql | `mariadb` (empty root) | |
| mongo | `mongo` | unauth vs auth |
| mssql | `mcr.microsoft.com/mssql/server` | sa weak |
| smb/msrpc/netbios | `dperson/samba` | guest share + null session |
| snmp | `polinux/snmpd` | community `public` |
| ssh | `linuxserver/openssh-server` | |
| telnet | `inetutils`/busybox telnetd | |
| ldap | `bitnami/openldap` | anon bind |
| mqtt | `eclipse-mosquitto` | anon publish/subscribe |
| elastic | `elasticsearch:7` (security off) | open index |
| couchdb | `couchdb` | admin party |
| rabbitmq | `rabbitmq:management` | guest/guest |
| memcached | `memcached` | unauth stats |
| influxdb | `influxdb:1.8` | unauth |
| cassandra | `cassandra` | |
| neo4j | `neo4j` (no auth) | |
| solr | `solr` | core listing |
| zookeeper | `zookeeper` | four-letter words |
| vault | `hashicorp/vault` (dev) | unsealed dev token |
| consul | `hashicorp/consul` | open KV/UI |
| etcd | `quay.io/coreos/etcd` | v2/v3 unauth |
| dns | `internetsystemsconsortium/bind9` | recursion/zone-xfer |
| nfs | `erichough/nfs-server` | export world-read |
| docker-registry/artifact | `registry:2` | catalog list |
| ipp/print | `ydkn/cups` | |
| sip | `drachtio/drachtio-server` or asterisk | OPTIONS ping |
| activemq | `apache/activemq-classic` | jolokia/web |
| jabber | `quantumobject/docker-openfire` | XMPP + admin :9090 |
| ajp/jmx | `tomcat` | AJP connector + JMX |

Services with no practical container (ipmi, kerberos full AD, rdp, winrm, oracle-XE if too
heavy, hpc, flexnet, backup, kafka, kubernetes, storage-iscsi, ot/ICS) get **contract +
negative-only** coverage (dry-run, empty-targets, wrong-service, gate-refusal) plus, where a
light option exists, a best-effort container (e.g. `xrdp` for rdp, `gvenzl/oracle-xe` for
oracle, `kind` for k8s) — attempted, not blocking.

---

## 5. Phases

**Phase 0 — Lab + harness.** Stand up `aranumlab`, generate a master `nmap -sV` of the lab
subnet, confirm each target is reachable. Build the negative-input fixture corpus (§6).

**Phase 1 — Pure parsers (deterministic, no network).** For each of nmap-parse,
report, report-dashboard, merge-results, plan, bulk-enum-windows spec parser, gql schema/arg
internals: run the full positive+negative input matrix (§6). Highest priority.

**Phase 2 — Unified CLI (`aranum.py`).** Every subcommand positive (delegation correct) +
negative (bad subcommand, missing/again-traversal session, missing scan token, conflicting
flags). Confirm exit contract.

**Phase 3 — Service dispatchers vs Docker.** For each lab service: (positive) dispatch
against the real container, assert the dispatcher emits the right `_hints.txt` + evidence and
nmap-parse routes the port to the right category; (negative) point it at a closed port and at
a wrong-service port; confirm no FP finding, clean handling, bounded time. Run the FP harness
shape-mimicry scenarios.

**Phase 4 — Orchestration.** `auto-enum.sh` full run over the lab gnmap (parse → bucket →
dispatch → report), `--throttle`, `--resume`, `--profile/--plan-only`; `iterative-enum.sh`
second pass; `bulk-enum-linux.sh` against SSH containers (real creds) + `--dry-run`;
`bulk-enum-windows.py` `--dry-run` + arg validation; `autoenum-diff.sh` new-finding diff.

**Phase 5 — Reporting pipeline.** report.py md/html/json + severity classification +
`--redact` + structured v2 on real Phase-3/4 output (positive) and on malformed
findings/rules/dirs (negative). report-dashboard pages + data.json schema + AD-depth
criticals (the bug just fixed) + evidence path-containment. merge-results dedup + bad inputs.

**Phase 6 — Standalones.** Gated write-helpers dry-run without their gate (§9 invariant) for
all of activemq/redis/smtp/graphql/jabber; positive runs against the matching container
(activemq→activemq, jabber→openfire, redis→redis, smtp→smtp4dev, gql→a GraphQL container);
creds tools on synthetic input; linux privesc checks real-data run on this host (read-only);
ot probes gate-refusal + `--dry-run` only (never touch real ICS).

**Phase 7 — Live network.** Full `auto-enum.sh -report` against `192.168.1.0/24`
(bounded), exercising the real-world path end to end; confirm no crash, no hang, redacted
report option, dashboard renders.

**Phase 8 — Consolidate.** Triage every ❌, fix on `dev/test-hardening`, add a regression
test per bug, re-run `make test`, update CHANGELOG, commit per CLAUDE.md.

---

## 6. Negative-input matrix (per parser — the core of "bulletproof")

**nmap-parse.py:** empty file; truncated XML (mid-tag); non-XML text; XXE + billion-laughs
(must rc=3); `<port>` without `portid`/`state`; `portid` non-numeric / negative / >65535;
IPv6 + zone-id hosts; hostname with `$(...)`,`;`,backticks,newline,unicode; gnmap with
missing `Host:`/garbled `Ports:`; 100k-host file (perf/no-OOM); duplicate ports; mixed
proto; CRLF vs LF.

**report.py:** scan dir missing; empty dir; findings file unreadable/binary; broken symlink;
`--severity-rules` with bad JSON line / missing `pattern` key / invalid regex / catastrophic-
backtrack regex; evidence path with `../` traversal; ANSI-laden lines; 1MB single line;
`--redact` on IPv4/IPv6/hostnames; non-UTF8 evidence bytes.

**report-dashboard.py:** same bad scan dirs; ensure AD-depth criticals render; data.json
schema keys present; XSS payload in a finding line must be HTML-escaped in output; generated
dashboard dir not re-ingested.

**merge-results.py:** source missing findings.json; malformed findings.json; conflicting
schemas; duplicate finding dedup; evidence path rewrite correctness; 0 sources; 1 source.

**plan.py:** same malformed nmap inputs (must bail rc=7 not crash); unknown profile; empty
service set; every dispatcher/category has metadata (already tested — re-assert).

**aranum.py:** unknown subcommand; `--session-name` with `/`,`..`,leading-dot,unicode,empty,
1000-char; missing scan token; both `--session` and `--session-name`; queue.jsonl malformed
line; dashboard with no outputs.

**bulk-enum-windows.py / bulk-enum-linux.sh:** spec `user@host:port`, bare host, IPv6
bracketed, comment/blank lines, `-P` over cap, basic-over-HTTP refusal, `--use-smb-admin`
without `--pass`, missing hosts file, host with shell metacharacters.

**gql.py:** unreachable target clean exit; bad `--kv`; inverted/over-cap range; malformed
introspection schema; non-JSON server response; `--alias-dos-check` without `--confirm`.

**_lib.sh (affects all 61):** `parse_common_args` missing `-o`/targets/unknown flag (rc=2);
targets file with hostile hostnames; `nmap_bound_args`/throttle on/off; `nxc_creds_array`
preserves literal credential bytes (no word-split/injection); `split_ipport` on IPv6.

---

## 7. Safety / OPSEC

- Lab traffic stays on `aranumlab`; live scan limited to owned `192.168.1.0/24`.
- No write/exploit/send gate is set except inside an isolated, disposable lab container that
  is destroyed after (activemq/redis RCE PoCs only there, never on the home net).
- OT/ICS probes (Phase 6) are **dry-run / gate-refusal only** — no frames sent to anything
  (ADR-005 safety scope), no real ICS exists on the lab regardless.
- All output to `outputs/testcampaign-07JUN2026/` (gitignored). No engagement data committed.

---

## 8. Deliverables

1. Per-phase result log with positive/negative status per unit.
2. Bug list (severity, file:line, repro, fix).
3. Fixes committed on `dev/test-hardening` with a regression test each.
4. Updated CHANGELOG; `make test` green; final go/no-go on "every parser/feature bulletproof".

---

## Appendix A — Codex independent review

> Produced by `codex exec` (codex-cli 0.133.0, read-only) against this plan + the
> codebase on 07 JUN 2026. Verbatim. Reconciliation of these points is tracked in
> §9 below.

**Conclusion:** No. Executing this plan as written would improve coverage, but it would not prove every parser and feature is bulletproof. Several phases can pass with empty outputs, skipped targets, unimplemented paths, or Docker labs that never exercise the intended protocol behavior.

### 1. Parser Negative Cases Still Missing
- `nmap-parse.py:239`: malformed XML ports are silently skipped when `portid` is missing or nonnumeric. Missing assertion: XML with only malformed ports must fail or report a diagnostic, not return valid empty JSON.
- `nmap-parse.py:246`: `portid` is converted with no range check. Missing inputs: `0`, `65536`, `999999999999`, negative-looking gnmap ports, and missing `protocol`.
- `nmap-parse.py:261`: malformed `.gnmap` lines are skipped. A file of only malformed lines can succeed vacuously.
- `nmap-parse.py:291`: normal `.nmap` parsing only recognizes simple `Nmap scan report for <token>` and `NN/tcp open` forms. Missing inputs: hostnames with spaces/parentheses, IPv6 literals, extra version columns, scan headers with no usable ports.
- `plan.py:195`: invalid `--phase abc` or unavailable phase tokens can collapse to an empty task list instead of a hard failure. Invalid phase filters must return nonzero.
- `plan.py:184`: reversed ranges are silently swapped. `--phase 3-1` must be explicitly accepted by contract or rejected.
- `aranum.py:115`: `--session` and `--session-name` conflict is not rejected; later value wins. Must assert rc 2 and no directory creation.
- `aranum.py:223`: malformed queue JSONL lines are skipped while rc can remain 0. Must either fail or produce a counted warning.
- `_lib.sh:6`: dispatcher common parsing supports only `--targets` and `--output`, not `-o`, and missing option values can hit `set -u` unbound-variable failures. Missing cases: `--targets`, `--output`, unknown flag, bare IPv6 without brackets.
- `merge-results.py:120`: `evidence_path` is joined without containment validation. `../secret.txt` evidence must not be copied outside the evidence tree.
- `report.py:659`: report discovery recursively reads service files. Symlinks or evidence paths pointing outside `out_dir` must be refused, not leaked.
- `gql.py:555`: `--arg` accepts empty names, invalid GraphQL identifiers, duplicate variables, missing `@file`, malformed `@json` with uncaught exceptions. (Plan said “bad --kv”; tool uses `--arg`.)
- `gql.py:1106`: `raw` is exempted from the required `--url` check but still posts to `args.url`. `gql.py raw --query ...` without URL must exit rc 2.
- `default-creds-sweep.py:59`: bare IPv6 targets misparsed as `host:port`. Missing: `[::1]:8080`, `2001:db8::1`, `host:abc`, malformed catalog JSON, `--threads 0`.
- `bulk-enum-windows.py:154`: SMB admin execution is explicitly not implemented and returns 126. Plan tests missing password, not the “password supplied, feature still unavailable” path.
- `bulk-enum-linux.sh:223`: target hostnames are used in output paths. `../../outside`, quotes, newlines, JSON-breaking usernames must not escape or corrupt `_meta.json`.

### 2. Inventory and Feature Coverage Gaps
- Plan says “61 dispatchers” but its literal list omits `enum-ssh.sh`. SSH coverage can be missed entirely.
- Actual tests are under `aranumtoolkit/tests`; no top-level `tests/`.
- `service-metadata.json` has manual/null-dispatch services (`openfire-admin`, `ot-untouched`, `unknown`); plan does not distinguish “no dispatcher exists” from “dispatcher tested.”
- XMPP/Jabber routing ambiguous: parser emits `xmpp`, metadata also has `jabber` alias, dispatcher is `enum-jabber.sh`. Assert parser→metadata→dispatcher parity.
- Standalone inventory undercounted: many bash standalones + 16 Windows PowerShell scripts plus `enum.bat`, not “8 AD PS1”.
- `enum-http.sh` has many gated paths (nuclei, ffuf, whatweb, nikto, product fingerprints, JWT/CORS/cert/vhost). A single nginx/DVWA positive does not exercise them.
- `fp-harness.sh` covers a subset and mostly stubs protocols. It does not prove SMB, LDAP, Kerberos, WinRM, RDP, SQL, Mongo, Elastic, Docker, K8s, IPMI, VNC, JMX, RabbitMQ, Memcached, CouchDB, etcd, FTP, DNS, NFS, SMTP, SNMP, SSH.
- Real transport behavior for WinRM, SMB admin, OpenFire cleanup, ActiveMQ exploitability, Redis rogue-master clients, SMTP delivery is not covered.

### 3. Docker Lab Problems
- Matrix not reproducible: no compose file, pinned tags, commands, env, healthchecks, credentials, aliases, or expected banners.
- `mcr.microsoft.com/mssql/server` needs EULA/password env + health waits.
- `mariadb` “empty root” needs explicit empty-root config.
- `tomcat` does not expose AJP or JMX by default; positives pass only with custom config.
- `quay.io/coreos/etcd` + etcd v2 parser is fragile (v2 API needs explicit enablement).
- `kind` is not a simple unauth k8s container; default clusters are authenticated.
- `bind9` zone-transfer positives need a mounted authoritative zone + AXFR policy.
- `dperson/samba`, `dovecot`, `inetutils` telnetd, `ydkn/cups`, `polinux/snmpd`, `namshi/smtp`, `quantumobject/docker-openfire`, `vulnerables/web-dvwa` need exact tags + service config, none present.
- OpenFire/ActiveMQ CVE positives require vulnerable versions + stateful verification; merely starting a container does not prove exploit parser correctness.

### 4. Sequencing and Harness Risks
- Parser phases can pass vacuously because empty parsed target lists return rc 0.
- `plan.py` can generate zero tasks from invalid filters without failing.
- `auto-enum.sh:402` dry-run returns before running dispatchers; proves no category behavior.
- `auto-enum.sh:436` counts dispatcher failures but does not necessarily exit nonzero. Assert: any dispatcher failure fails the campaign or is reported as expected partial.
- `aranum run scan -report` can start the dashboard server and block. Require `--no-serve`, timeouts, process cleanup.
- Fixed Docker subnets/host ports create collision risk; assert preflight port availability.
- “Dashboard renders” too weak. Assert: generated HTML escapes hostile finding text; `data.json` consumed without `innerHTML` injection.

### 5. Safety Gaps
- Live `192.168.1.0/24` not constrained enough. HTTP dispatch can run nuclei/ffuf/nikto unless disabled; printers/IoT/OT may be touched.
- Local Linux standalone tests can collect sensitive files/credentials into outputs; require redaction review before saving.
- Credential sweep tools print discovered credentials to stdout/reports; assert masking in console, JSON, markdown, dashboard.
- Output safety assumed, not proven. Assert campaign outputs gitignored, no secrets staged/committed.
- Cleanup incomplete for exploit-like tests (OpenFire scaffolded; ActiveMQ/Redis/SMTP can leave state/listeners). Require post-test state verification.

### 6. Hard-To-Test Areas the Plan Glosses Over
- Real protocol edge cases: partial reads, malformed server replies, TLS downgrade, STARTTLS refusal, slow banners, reconnects.
- External tool availability changes behavior; assert gated tools absent/present both deterministic.
- Report/dashboard correctness depends on filesystem shape, escaping, browser JS — not just command success.
- Windows/AD coverage mostly dry-run/transport-syntax; does not prove pywinrm, PowerShell exec, SMB admin, DC behavior.
- Exploit-named standalones not proven safe/effective unless lab validates vulnerable + patched targets, negative controls, cleanup, and non-exploit dry-run.

**Bottom line:** a useful broad smoke campaign, but not a proof of bulletproofness. Real bugs can slip through via silent parser skips, inventory omissions, unimplemented transport paths, unpinned Docker labs, vacuous success conditions, and unsafe/stateful standalone behavior.

---

## 9. Reconciliation of codex review (what changes in execution)

Codex is right on the central risk: **a negative test that only checks "no crash" passes vacuously** when the parser's design is to silently skip bad input. Execution is upgraded accordingly:

- **R1 — Anti-vacuous assertions.** Every negative parser test asserts on *output + exit code together*, against a decided **contract**: for each "skip" path we decide whether the correct behavior is (a) documented-skip-with-rc0 (then assert a diagnostic/count is emitted, never a silent empty-but-valid result that mimics success) or (b) fail-nonzero. Where the current code silently returns empty valid JSON for an all-malformed input, that is treated as a **bug to fix**, not a passing test.
- **R2 — Confirmed-bug candidates to verify+fix in Phase 1/2** (promote to real fixes if reproduced): nmap-parse `portid` range (0/65536/huge), `.nmap` text parser IPv6/space-hostname/version-column, all-malformed-input vacuous success, `plan.py` invalid/`reversed --phase`, `aranum.py` `--session`+`--session-name` conflict, `gql.py raw` without `--url`, `default-creds-sweep` IPv6 + `--threads 0`, `merge-results`/`report.py` evidence-path containment + symlink escape, `bulk-enum-linux.sh` hostname-in-path injection, `_lib.sh` missing-option-value `set -u` abort + `-o` support question.
- **R3 — Inventory fixes:** include `enum-ssh.sh` (verify the true dispatcher count); map every `service-metadata.json` entry to {has-dispatcher | null/manual} so "no dispatcher" ≠ "tested"; assert parser→metadata→dispatcher parity for the xmpp/jabber alias; enumerate ALL standalones (bash + 16 Windows PS1 + `enum.bat`), and resolve whether `bulk-enum-windows.py`/`bulk-enum-linux.sh` exist in BOTH `aranumtoolkit/network/` and `standalones/` (duplicate-script finding if so).
- **R4 — Reproducible lab:** a pinned, committed-to-`outputs/` (gitignored) compose file with exact tags, env (mssql EULA+SA_PASSWORD, mariadb `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD`, postgres trust), healthchecks, and a documented expected banner per service; preflight host-port availability; tomcat AJP/JMX only claimed if the connector is actually configured, else dropped to contract-only. CVE positives (OpenFire 4.7.x for CVE-2023-32315, ActiveMQ 5.18.2 for CVE-2023-46604) use **specifically vulnerable** tags with a **patched negative control** and **post-run state/cleanup verification**; exploit gates fired ONLY in disposable lab containers.
- **R5 — Harness rigor:** dispatch tests assert the dispatcher actually ran (evidence file content, not just rc0); `aranum run -report` always `--no-serve` (or timeout-bounded + killed); dashboard test asserts hostile finding text is HTML-escaped (XSS) and `data.json` has no `innerHTML` sink; `enum-http.sh` gated branches (nuclei/ffuf/whatweb/nikto/JWT/CORS/cert/vhost/product) exercised explicitly with tools present AND absent.
- **R6 — Safety hardening:** live `192.168.1.0/24` run forces `--no-nuclei`/no-ffuf/no-nikto and avoids known printer/IoT/OT hosts; creds tools asserted to mask secrets in console/JSON/md/dashboard; campaign outputs confirmed gitignored and never staged; exploit-like tests verify clean post-state.
