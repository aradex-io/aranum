# ROADMAP-001 — Executing REVIEW-001 thoroughness improvements

**Date created:** 2026-05-19
**Source of truth:** `docs/REVIEW-001-19MAY2026-thoroughness-audit.md`
**Status legend:** ⬜ not started · 🟦 in progress · ✅ done · ⏸ blocked · ❌ declined

This is a **living document** — each iteration's status table is updated in the same commit that completes the iteration. The roadmap follows REVIEW-001 §6 sequencing, with one section per iteration. Each iteration is self-contained: prerequisites → deliverables → per-item plan → acceptance criteria → estimated commits → test plan → status.

Filename per CLAUDE.md §7 dated-naming convention.

---

## Overall status

| Iteration | Theme | Effort | Status | Tag |
|---|---|---|---|---|
| **A** | Bug fixes (P0/P1 correctness) | ~1 day | ✅ done 2026-05-19 | `v0.2.0` |
| **H** | **Jabber / XMPP tooling** *(added 2026-05-19; scoped via [ADR-001](ADR-001-19MAY2026-jabber-scope.md))* | ~2 days | ✅ done 2026-05-19 | `v0.9.0` |
| **B** | P0 service-coverage expansion | ~2 days | ✅ done 2026-05-19 | `v0.10.0` |
| **C** | P1 service coverage + HTTP depth | ~2 days | ✅ done 2026-05-19 | `v0.11.0` |
| **F** | GraphQL depth | ~1 day | ✅ done 2026-05-19 | `v0.12.0` |
| **E** | Reporting & ergonomics | ~1.5 days | ✅ done 2026-05-19 | `v0.13.0` |
| **G** | Tests + hardening | ~1 day | ✅ done 2026-05-20 | `v0.14.0` |
| **J** | **Bulk local-enum at scale (Linux)** *(added 2026-05-20; scoped via [ADR-002](ADR-002-20MAY2026-bulk-enum-design.md))* | ~1.5 days | ✅ done 2026-05-20 | `v0.15.0` |
| **K** | **Bulk local-enum (Windows)** *(added 2026-05-20; scoped via [ADR-003](ADR-003-20MAY2026-windows-bulk-enum-design.md))* | ~1 day | ✅ done 2026-05-20 | `v0.16.0` |
| **D1** | **AD remote depth + Windows local AD scripts** *(REVIEW-001 §2.2-§2.7; scoped via [ADR-004](ADR-004-20MAY2026-ad-depth-tool-deps.md))* | ~2 days | ✅ done 2026-05-20 | `v0.17.0` |
| **D2** | **Linux CVE checks + creds enhancements** *(REVIEW-001 §2.8/§2.9)* | ~1 day | ✅ done 2026-05-20 | `v0.18.0` |
| **I** | **Internal-pentest protocol expansion** *(added 2026-05-19; engineering/science facility focus)* | ~3 days | ⬜ (placeholder — needs ADR for protocol selection) | `v0.19.0` |

**Note on version mapping** (corrected 2026-05-19): the original roadmap aspired to map iteration A→v0.2.0, B→v0.3.0, etc. Reality: iteration H was prioritized ahead of B–G and shipped as v0.9.0, after which semver's monotonic-increase requirement means subsequent iterations occupy `v0.10.0+`. The iteration identity is preserved in commit messages and CHANGELOG sections; the version-to-iteration mapping is no longer 1:1 with the alphabetical letter.

**Total estimate:** ~12 working days. Iterations B–H are independent and can be reordered or parallelized once A is shipped.

**Tagging policy:** each iteration cuts a MINOR release (per CLAUDE.md §5: new dispatchers / new bug classes / new auth methods are MINOR). Iteration A's batch of bug fixes ships as `v0.2.0` because it includes interface additions (`--allow-huge` flag on `gql.py`) and the new `nxc_creds_array` helper that downstream dispatchers depend on. After `v1.0.0` the policy flips: bug-fix-only iterations would ship as PATCH.

---

## Iteration A — Bug fixes (the only prerequisite)

**Completed:** 2026-05-19 — tag `v0.2.0`

**Why first:** §3 of REVIEW-001 lists 10 correctness/safety bugs. The P0/P1 subset (5 items) must be fixed before any new coverage lands, because:
- A.1 (shell-quoting) means any new dispatcher copying the existing `NXC_ARGS+=` pattern would inherit the same vulnerability.
- A.2 (XXE) widens to other future XML inputs.
- A.3/A.4 (gql.py) clean up surprises that compound during F.

**Prerequisites:** none. `v0.1.0` tag is the starting point.

**Deliverable:** `v0.2.0` tag with 5 sub-commits + 1 CHANGELOG roll-up commit.

### A.1 — Fix shell quoting in `_lib.sh` and dispatchers

| | |
|---|---|
| **Status** | ✅ done 2026-05-19 (commit pending) |
| **Bug refs** | REVIEW-001 §3.1; prior observation `8321 6:05p` |
| **Files** | `network/_lib.sh`, `network/enum-smb.sh`, `network/enum-ldap.sh`, `network/enum-mssql.sh`, `network/enum-winrm.sh`, `network/enum-rdp.sh` |
| **Plan** | Delete broken `nxc_creds()` helper. Add `nxc_creds_array <ARRAY_NAME>` helper using bash nameref (4.3+) that populates a passed-in array. Convert every `NXC_ARGS=""; NXC_ARGS+=" -u $ENUM_USER"` → `nxc_creds_array NXC_ARGS`. Convert every callsite from `$NXC <module> $NXC_ARGS` → `"$NXC" <module> "${NXC_ARGS[@]}"`. Convert the inline `creds="-u $ENUM_USER -p $ENUM_PASS"` patterns in `enum-smb.sh` (smbmap, enum4linux-ng) and `enum-ldap.sh` (ldapsearch) to local arrays. |
| **Acceptance** | (1) `grep -rn 'NXC_ARGS+=" -u'` returns no hits. (2) `grep -rn 'creds="-u' network/` returns no hits. (3) Each dispatcher passes a smoke test with a credential containing a single quote: `ENUM_USER="al'ice"`. (4) `bash -n` parses every modified file. |
| **Commit** | `sec(network): use bash arrays for credential args (closes shell-injection footgun)` |

### A.2 — Harden `nmap-parse.py` XML against XXE / billion-laughs

| | |
|---|---|
| **Status** | ✅ done 2026-05-19. Surgical pre-scan (not blanket DOCTYPE rejection — nmap output legitimately carries `<!DOCTYPE nmaprun>`). |
| **Bug refs** | REVIEW-001 §3.2; prior observation `8304 5:59p` |
| **Files** | `network/nmap-parse.py`, `deps-check.sh` |
| **Plan** | Try `import defusedxml.ElementTree as ET`; if unavailable, fall back to stdlib `xml.etree.ElementTree` but install a `_HardenedParser` (XMLParser with `_target` rejecting any `_doctype` / `_entity_decl` events). Stamp a one-line stderr note when the fallback is active. Add `defusedxml` to `deps-check.sh` under OPTIONAL with `pip install defusedxml` hint. |
| **Acceptance** | (1) Existing `network/test.xml` still parses to identical output (byte-compare `nmap-parse.py test.xml --json` before/after). (2) A crafted `tests/fixtures/malicious.xml` with `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` is rejected with a clear error and zero file reads. (3) Works on a host without defusedxml installed (verified by `pip uninstall -y defusedxml` and re-run). |
| **Commit** | `sec(network): harden nmap-parse.py XML against XXE and entity expansion` |

### A.3 — Fix `gql.py` cache-key collision for cookie / job-token

| | |
|---|---|
| **Status** | ✅ done 2026-05-19 |
| **Bug refs** | REVIEW-001 §3.3 |
| **Files** | `graphql/gql.py` |
| **Plan** | In `cache_key()`, expand identity-source string to include `Cookie` and `JOB-TOKEN` headers as well as `PRIVATE-TOKEN` and `Authorization`. Format: `url|hdr1|hdr2|...` with stable ordering. |
| **Acceptance** | (1) Two `gql.py --cookie "_gitlab_session=AAA" introspect` and `--cookie "_gitlab_session=BBB" introspect` runs against the same URL produce two distinct cache files. (2) Same `--cookie X` twice hits the cache. (3) Backwards-compat: existing on-disk caches keyed under the old hash are still readable; they just get rebuilt under the new key on next miss. |
| **Commit** | `fix(graphql): include Cookie / JOB-TOKEN in cache key identity` |

### A.4 — Bound `gql.py --range` / `--gid-range`

| | |
|---|---|
| **Status** | ✅ done 2026-05-19 |
| **Bug refs** | REVIEW-001 §3.4 |
| **Files** | `graphql/gql.py` |
| **Plan** | Convert `--range` / `--gid-range` materialization from `[str(i) for i in range(lo, hi+1)]` to a generator. Pre-check `hi - lo + 1 > 1_000_000` and exit 2 with hint unless `--allow-huge` was passed. Add `--allow-huge` to the `loop` subparser. The signature-summary at the end already handles streaming because it only tracks counts; verify nothing else collects values. |
| **Acceptance** | (1) `gql.py loop project --vary id --range 1-2000000` exits with error mentioning `--allow-huge`. (2) `--allow-huge` allows it. (3) RSS during a `--range 1-100000` walk stays flat (no list materialized). |
| **Commit** | `enh(graphql): refuse oversize loop ranges without --allow-huge` |

### A.5 — IPv6 audit + LDAP URL bracket fix

| | |
|---|---|
| **Status** | ✅ done 2026-05-19 — bundled with A.1 commit (same files). Audit findings: enum-ssh.sh (nc + ssh accept bare v6) OK, enum-mssql.sh (nxc + nmap accept bare v6) OK, enum-redis.sh (redis-cli >=7.0 + nc + nmap accept bare v6) OK, enum-winrm.sh (nxc accepts bare v6) OK, enum-rdp.sh (nxc accepts bare v6) OK. Only enum-ldap.sh needed bracketing in the URL form. |
| **Bug refs** | REVIEW-001 §3.6 |
| **Files** | `network/enum-ldap.sh`, audit pass on `enum-ssh.sh`, `enum-mssql.sh`, `enum-redis.sh`, `enum-winrm.sh`, `enum-rdp.sh` |
| **Plan** | Add `ldap_url()` helper in `_lib.sh` that wraps IPv6 in brackets (`ldap://[::1]` vs `ldap://10.0.0.1`). Use it in every `ldap://$ip` callsite in `enum-ldap.sh`. Audit the others — `nc`/`ssh`/`redis-cli` accept bare v6 fine; `nxc` accepts bare v6 fine; `nmap -iL` accepts bare v6 fine. Document findings in commit body. |
| **Acceptance** | (1) `enum-ldap.sh` with a `[::1]:389` target invokes `ldapsearch -H ldap://[::1]:389` (verified by `bash -x`). (2) Other dispatchers unchanged but each gets a one-line "ipv6: OK — bare addr passes to <tool>" comment. |
| **Commit** | `fix(network): bracket IPv6 addrs in ldap:// URLs; audit other dispatchers` |

### A — Final CHANGELOG roll + tag

| | |
|---|---|
| **Status** | ⬜ |
| **Plan** | Roll `[Unreleased]` entries into `[v0.2.0] — 2026-05-19` (or the actual ship date). Reset `[Unreleased]` to empty headings. Tag annotated `v0.2.0`. |
| **Commit** | `chore(repo): release v0.2.0 — iteration A bug fixes` |

### A — Test plan

Smoke: rerun `bash deps-check.sh`, `python3 -m py_compile network/nmap-parse.py graphql/gql.py`, and execute each modified dispatcher with `--targets /tmp/empty.txt --output /tmp/out` (smoke-grade: confirms argparse + arg-handling don't regress).

Functional, where feasible offline:
- A.1: smoke-run `enum-smb.sh` with `ENUM_USER="al'ice"` against a localhost dummy (or `bash -x`).
- A.2: parse the existing test fixtures (`test.xml`, `test.gnmap`, `test.nmap`) and diff vs pre-change output. Then run the malicious fixture and confirm exit-code != 0.
- A.3: hash-comparison test in a tiny Python REPL session.
- A.4: actually run `gql.py loop ... --range 1-5000000` against `https://example.invalid/graphql` (will error on connect — but only after passing the bound check).
- A.5: `bash -x enum-ldap.sh --targets <(echo '[::1]:389') --output /tmp/v6` and grep the trace for `ldap://[::1]`.

---

## Iteration B — P0 service coverage

**Completed:** 2026-05-19 — tag `v0.10.0`

**Goal:** double the assessable service surface from one `auto-enum.sh` invocation by covering the data-store and orchestration services attackers most often find unauthenticated or with default creds.

**Prerequisites:** Iteration A complete (so new dispatchers inherit the array-quoting pattern).

**Deliverables:** seven new dispatchers + `nmap-parse.py` category additions + `auto-enum.sh` dispatch table wiring + `deps-check.sh` updates + `README.md` table updates + CHANGELOG.

| Item | Service | Default ports | New dispatcher | Status |
|---|---|---|---|---|
| B.1 | PostgreSQL | 5432 | `network/enum-postgres.sh` | ✅ done 2026-05-19 |
| B.2 | MySQL/MariaDB | 3306 | `network/enum-mysql.sh` | ✅ done 2026-05-19 |
| B.3 | MongoDB | 27017–27019 | `network/enum-mongo.sh` | ✅ done 2026-05-19 |
| B.4 | Elasticsearch/Kibana | 9200, 5601 | `network/enum-elastic.sh` | ✅ done 2026-05-19 |
| B.5 | Docker API | 2375, 2376 | `network/enum-docker.sh` | ✅ done 2026-05-19 |
| B.6 | Kubernetes API/kubelet | 6443, 8080, 10250 | `network/enum-kubernetes.sh` | ✅ done 2026-05-19 |
| B.7 | IPMI/BMC | 623/udp | `network/enum-ipmi.sh` | ✅ done 2026-05-19 |
| B.8 | nmap-parse categories (docker + kubernetes; others already present) | — | `network/nmap-parse.py` | ✅ done 2026-05-19 |
| B.9 | Release + docs | — | README + CHANGELOG + tag | ✅ done 2026-05-19 |

**Each dispatcher must:**
- Source `network/_lib.sh` and use `parse_common_args`.
- Run unauth probes first (banner, version, public API endpoint that doesn't require auth).
- Run auth probes when `ENUM_USER`/`ENUM_PASS` provided, using bash arrays for credential args (A.1 pattern).
- Pre-flight every external tool via `have <tool>` and `miss "tool not installed — install hint"` on absence.
- Write all output to `$OUT/<ip>/...` with idempotent file names.
- Surface critical findings (unauth API, default creds confirmed) to a `_findings.txt` per host.

**Per-item plan (skeleton — fleshed out at execution time):**

### B.1 PostgreSQL
- `psql -h $ip -U postgres -c '\l'` (no-pwd attempt — trust auth)
- `nxc postgres` cred check
- `nmap --script pgsql-brute,pgsql-empty-password`
- Flag `pg_read_server_files`, `COPY PROGRAM` if any superuser context found

### B.2 MySQL
- `mysql -h $ip -u root -e 'select version()'` (no-pwd attempt)
- `nxc mysql` cred check
- `nmap --script mysql-empty-password,mysql-info,mysql-users`
- Detect `FILE` priv, `INTO OUTFILE` writable docroots

### B.3 MongoDB
- `mongosh "mongodb://$ip:27017" --eval 'db.adminCommand({listDatabases:1})'` (unauth check)
- `nmap --script mongodb-info,mongodb-databases`
- If unauth, dump database list + collection counts to evidence

### B.4 Elasticsearch
- `curl -ks http://$ip:9200/` for cluster info
- `curl -ks http://$ip:9200/_cat/indices?v` for index inventory
- `curl -ks http://$ip:9200/_search?q=password*` for cred leak signal
- Kibana 5601 alive check

### B.5 Docker API
- `curl -ks http://$ip:2375/version`
- `curl -ks http://$ip:2375/containers/json`
- If responsive: `docker -H tcp://$ip:2375 ps` evidence capture
- Flag as CRITICAL — direct host-equivalent RCE

### B.6 Kubernetes
- API server: `curl -ks https://$ip:6443/api` (anon allowed?), `/version`, `/api/v1/namespaces`
- kubelet: `curl -ks https://$ip:10250/pods`
- Insecure 8080: `curl -ks http://$ip:8080/api/v1/pods`

### B.7 IPMI
- `nmap --script ipmi-cipher-zero,ipmi-version,ipmi-brute` against 623/udp
- `msf6 ipmi/scanner/ipmi_dumphashes` hint in `_hints.txt` (don't auto-run msf)

**`nmap-parse.py` additions:** ports + service regex for each new category (some already present: postgres, mysql, mongo, elastic, ipmi). Add docker, kubernetes.

**Acceptance:** seven new dispatchers each execute against a localhost dummy without crashing; service categories appear in `nmap-parse.py --list-categories`; `auto-enum.sh` routes targets to them via the existing dispatcher-lookup mechanism (no code change needed there — file naming convention drives it).

**Commit cadence:** one commit per dispatcher + one for `nmap-parse.py` category additions + one CHANGELOG/version roll. Tag `v0.3.0`.

---

## Iteration C — P1 service coverage + HTTP depth

**Prerequisites:** A.

**Deliverables:** six more dispatchers + HTTP bug-class checks + SMB extras.

| Item | Scope | Files | Status |
|---|---|---|---|
| C.1 | VNC dispatcher | `network/enum-vnc.sh` | ✅ done 2026-05-19 |
| C.2 | JMX/RMI dispatcher | `network/enum-jmx.sh` | ✅ done 2026-05-19 |
| C.3 | RabbitMQ mgmt | `network/enum-rabbitmq.sh` | ✅ done 2026-05-19 |
| C.4 | Memcached | `network/enum-memcached.sh` | ✅ done 2026-05-19 |
| C.5 | CouchDB | `network/enum-couchdb.sh` | ✅ done 2026-05-19 |
| C.6 | etcd | `network/enum-etcd.sh` | ✅ done 2026-05-19 |
| C.7 | HTTP: JWT extract + alg-confusion probe | `network/enum-http.sh` | ✅ done 2026-05-19 |
| C.8 | HTTP: CORS misconfig probe | `network/enum-http.sh` | ✅ done 2026-05-19 |
| C.9 | HTTP: exposed VCS dir check | `network/enum-http.sh` | ✅ done 2026-05-19 |
| C.10 | HTTP: virtual-host fuzz mode | `network/enum-http.sh` | ✅ done 2026-05-19 |
| C.11 | HTTP: cert collection + SANs | `network/enum-http.sh` | ✅ done 2026-05-19 |
| C.12 | HTTP: micro-wordlist of high-value paths | `network/enum-http.sh` | ✅ done 2026-05-19 |
| C.13 | SMB: NTLM-relay viability + PetitPotam coerce signal | `network/enum-smb.sh` | ✅ done 2026-05-19 |
| C.14 | SSH: CVE-2018-15473 user enum + key-only refusal | `network/enum-ssh.sh` | ✅ done 2026-05-19 |

**Acceptance:** each HTTP check has a fixture (captured response) and a unit-equivalent bash test that confirms detection vs negative case.

Tag `v0.4.0`.

---

## Iteration D — Windows / AD depth

**Prerequisites:** A.

**Deliverables:** new Windows scripts + LDAP dispatcher additions.

| Item | Scope | Files | Status |
|---|---|---|---|
| D.1 | `Get-LAPSPassword.ps1` | `windows/` | ⬜ |
| D.2 | `Get-ADCSMisconfig.ps1` (ESC1/2/4 via ADSI) | `windows/` | ⬜ |
| D.3 | `Get-GPPCPassword.ps1` (SYSVOL `cpassword=`) | `windows/` | ⬜ |
| D.4 | `Get-DPAPIBlobs.ps1` (locations only — no decrypt) | `windows/` | ⬜ |
| D.5 | `Get-NamedPipes.ps1` (ACL enumeration) | `windows/` | ⬜ |
| D.6 | `Get-PrintNightmare.ps1` (registry + Spooler state) | `windows/` | ⬜ |
| D.7 | `Test-CoercedAuth.ps1` (local-only safety probe) | `windows/` | ⬜ |
| D.8 | LDAP: BloodHound ingestion when creds + DC IP present | `network/enum-ldap.sh` | ⬜ |
| D.9 | LDAP: Certipy `find` for ADCS templates | `network/enum-ldap.sh` | ⬜ |
| D.10 | LDAP: delegation enum (constrained/unconstrained/RBCD) | `network/enum-ldap.sh` | ⬜ |
| D.11 | Linux: `pwnkit-check.sh`, `looney-check.sh`, `overlayfs-check.sh`, `io-uring-check.sh`, `namespaces-check.sh` | `linux/` | ⬜ |

Tag `v0.5.0`.

---

## Iteration E — Reporting & ergonomics

**Completed:** 2026-05-19 — tag `v0.13.0`

**Prerequisites:** ideally B (so the report has more services to cover), but technically only A.

**Deliverables:**

| Item | Scope | Files | Status |
|---|---|---|---|
| E.1 | `report.py` — unified Markdown / JSON / HTML report | `network/report.py` (new) | ✅ done 2026-05-19 |
| E.2 | `autoenum-diff.sh` — diff two run outputs | `network/autoenum-diff.sh` (new) | ✅ done 2026-05-19 |
| E.3 | Central `run.log` with tool versions + invocations + exit codes | `network/auto-enum.sh` + dispatchers | ✅ done 2026-05-19 |
| E.4 | `--resume` flag — per-service `.done` markers | `network/auto-enum.sh` | ✅ done 2026-05-19 |
| E.5 | SOCKS / HTTP proxy support across the suite | `network/_lib.sh`, `graphql/gql.py` | ✅ done 2026-05-19 (gql.py in F.7; network/_lib.sh helpers added) |
| E.6 | User-Agent customization + `--ua-rotate` | `graphql/gql.py`, curl callsites | ✅ done 2026-05-19 (gql.py in F.8; `curl_ua()` helper for dispatchers) |
| E.7 | `deps-check.sh` version-floor assertions | `deps-check.sh` | ✅ done 2026-05-19 |
| E.8 | Findings severity tagging (critical/high/medium/low) | E.1 implementation detail | ✅ done 2026-05-19 |
| E.9 | `--redact` mode for shareable output | E.1 implementation detail | ✅ done 2026-05-19 |
| E.10 | `auto-enum.sh` dispatcher-failure tally at end | `network/auto-enum.sh` | ✅ done 2026-05-19 |

Tag `v0.6.0`.

---

## Iteration F — GraphQL depth

**Completed:** 2026-05-19 — tag `v0.12.0`

**Prerequisites:** A (A.3 + A.4 already touch gql.py).

**Deliverables:**

| Item | Scope | Files | Status |
|---|---|---|---|
| F.1 | Field-suggestion harvest when introspection disabled | `graphql/gql.py` (new subcommand `suggest`) | ✅ done 2026-05-19 |
| F.2 | Batched-query support (`[{query:...}, ...]`) | `graphql/gql.py` (`--batch` on `call`/`raw`) | ✅ done 2026-05-19 |
| F.3 | Persisted-query bypass probe (APQ) | `graphql/gql.py` (new subcommand `apq-probe`) | ✅ done 2026-05-19 |
| F.4 | `@skip` / `@include` directive abuse helper | `graphql/gql.py` (`--directive-bypass` on `diff`) | ✅ done 2026-05-19 |
| F.5 | CSRF-via-GET probe | `graphql/gql.py` (new subcommand `csrf-probe`) | ✅ done 2026-05-19 |
| F.6 | Alias-DoS detection (latency growth measurement; detect-only) | `graphql/gql.py` (`--alias-dos-check` on `call`) | ✅ done 2026-05-19 |
| F.7 | SOCKS proxy support | `graphql/gql.py --proxy` + env | ✅ done 2026-05-19 |
| F.8 | User-Agent flag + rotation | `graphql/gql.py --user-agent / --ua-rotate / GQL_UA` | ✅ done 2026-05-19 |

Tag `v0.7.0`.

---

## Iteration G — Tests + hardening

**Prerequisites:** ideally all of B/C/D so there's something to test; technically only A.

**Deliverables:**

| Item | Scope | Files | Status |
|---|---|---|---|
| G.1 | `tests/fixtures/services/` synthetic nmap-XML banners per service | new | ✅ done 2026-05-20 |
| G.2 | `tests/test_nmap_parse.py` unit tests (19 tests) | new | ✅ done 2026-05-20 |
| G.3 | `tests/test_gql_internals.py` — pure-function tests for gql.py (28 tests; renamed from `test_gql_query_builder.py` because the testable seams are `cache_key`, `_check_range_size`, `type_str`, `unwrap`, `type_by_name`, `parse_kv_args`, `build_selection` — not an abstraction we'd invent) | new | ✅ done 2026-05-20 |
| G.4 | `Makefile` with `test`, `lint`, `unittest`, `smoke`, `deps-check`, `clean`, `help` targets | `Makefile` | ✅ done 2026-05-20 |
| G.5 | CI config — GitHub Actions YAML, lint + unittest + smoke on push/PR to main | `.github/workflows/ci.yml` | ✅ done 2026-05-20 |
| G.6 | `shellcheck -S warning -e SC1091` clean across every `.sh`; SC2069/SC2155/SC2164 real-bug fixes; SC2034/SC2046 disables annotated with reasons | all `.sh` files | ✅ done 2026-05-20 |
| G.7 | `--throttle` mode for sensitive environments; operator-explicit CLI wins over throttle defaults; `throttle_delay()` / `throttle_sleep()` / `throttle_nmap_args()` helpers in `_lib.sh` | `network/auto-enum.sh`, `network/_lib.sh` | ✅ done 2026-05-20 |
| G.8 | Engagement-scoped-write audit (CLAUDE.md §9 invariant 1); 6 helpers gained explicit `--exploit` / `--write` / `--send` gates; findings + methodology in [REVIEW-002](REVIEW-002-20MAY2026-write-gate-audit.md) | `activemq/`, `redis/`, `smtp/`, `docs/` | ✅ done 2026-05-20 |

Tagged `v0.14.0` (corrected from the stale `v0.8.0` text — see [Overall status](#overall-status) version-mapping note). After this iteration, interfaces are reasonably stable but still pre-1.0 because of pending D (Windows/AD depth) and I (engineering-facility protocols).

---

## Iteration H — Jabber / XMPP tooling *(added 2026-05-19; scoped 2026-05-19)*

**Completed:** 2026-05-19 — tag `v0.9.0`

**Origin:** user milestone, not in REVIEW-001.

**Scope decisions:** locked in [ADR-001](ADR-001-19MAY2026-jabber-scope.md). Summary:
- **D1** target surface = XMPP/Jabber only (Ejabberd, Prosody, Openfire). Cisco UC, SIP/voice, and modern team chat are deferred to future iterations.
- **D2** enumeration + single-cred validation only. **No spray.**
- **D3** OpenFire CVE-2023-32315 ships as default-detect / `--exploit`-full-chain / `--cleanup`-reverse. Mandatory typed-FQDN confirmation on `--exploit`.
- **D4** stdlib-only Python (matches `gql.py` precedent). No `requirements.txt` in `jabber/`.

**Why:** XMPP is the recurring blind spot in network enum kits. Self-hosted Jabber routinely ships with open in-band registration (XEP-0077), permissive S2S to any domain, unencrypted BOSH/WebSocket endpoints, MUC enumeration that leaks org structure, MAM history exposure, and OpenFire admin consoles fronted by CVE-2023-32315.

### Per-item plan

| Item | Scope | Files | Status |
|---|---|---|---|
| H.1 | Add XMPP/Jabber service categories to nmap-parse: 5222 (c2s STARTTLS), 5223 (legacy implicit-TLS c2s), 5269 (s2s), 5280/5281 (BOSH / WebSocket / HTTP-bind), 5298 (link-local), 7777 (Openfire file-transfer proxy), 9090/9091 (Openfire admin console). Two categories: `xmpp` and `openfire-admin` so the dispatchers can route differently. | `network/nmap-parse.py` | ✅ done 2026-05-19 |
| H.2 | `enum-jabber.sh` dispatcher routed automatically by `auto-enum.sh` based on H.1 categorization. Phases: (a) raw banner via `nc`, (b) STARTTLS feature probe + cert collection (SANs feed domain inventory), (c) advertised SASL mechanisms parse, (d) XEP-0077 in-band-registration probe (no actual register — just `<iq type='get'><query xmlns='jabber:iq:register'/></iq>` to confirm IBR is advertised), (e) server `disco#info` + `disco#items`, (f) MUC discovery on `conference.<domain>` with anonymous-and-then-auth attempts, (g) BOSH/WebSocket endpoint detection on 5280/5281. All output to `$OUT/<ip>/`. | `network/enum-jabber.sh` (new), sources `network/_lib.sh` | ✅ done 2026-05-19 |
| H.3 | `jabber-user-enum.py` — SASL response differential as the primary read-only enum technique. Per-user verdict (USER_EXISTS / EXISTS_DISABLED / EXISTS_EXPIRED / INVALID_FORMAT / NO_PLAIN / SERVER_ERROR / UNCLASSIFIED / STREAM_FAIL) + per-user response time. Timing fallback documented for hardened servers that return identical `<not-authorized/>` for every name. Stdlib-only (per ADR-001 D4). XEP-0077 IBR-based probing **deliberately not used** — it creates accounts when the conflict-error path doesn't fire (write side-effect; ADR-001 D2 violation). MUC nick harvest + vCard lookup deferred to a follow-up; this version focuses on the strongest signal (SASL differential). Output: per-user JSONL via `--out` + final summary table. | `jabber/jabber-user-enum.py` (new) | ✅ done 2026-05-19 |
| H.4 | `jabber-validate.py` — single-credential validation only (per ADR-001 D2 — **no spray**). Accepts `--jid` + `--password`, attempts SASL PLAIN / SCRAM-SHA-1 / SCRAM-SHA-256 against the host, confirms auth or surfaces the SASL failure reason (`<not-authorized/>`, `<account-disabled/>`, etc.). Stdlib-only. SCRAM verified against RFC 5802 §5 reference vector. | `jabber/jabber-validate.py` (new) | ✅ done 2026-05-19 |
| H.5 | `openfire-cve-2023-32315.py` — default behavior: detection only (probes the path-traversal signature, reports version + verdict). `--exploit`: typed-FQDN confirm → admin create via the bypass → JSP webshell plugin upload → returns webshell URL + writes `<out>/exploit_log.txt` with admin-username, plugin-name, timestamp. `--cleanup <log>`: takes the log from a prior `--exploit` run, deletes the admin user via the legitimate REST API, removes the plugin. README must document `--cleanup` before `--exploit`. Stdlib (urllib) + bash glue. Per ADR-001 D3. | `jabber/openfire-cve-2023-32315.py` (new) | ✅ done 2026-05-19 (detect mode complete; exploit + cleanup paths written per public PoC pattern and explicitly marked REQUIRES_LAB_VERIFICATION against a known-vulnerable 4.7.4 container before engagement use — see README §lab-verify) |
| H.6 | Ejabberd / Prosody admin-API exposure check — detection only. Probes Ejabberd commands API on `<host>/api/` (returns 401 vs 200 vs 404 — flag if any method responds without auth), Prosody `mod_admin_telnet` on TCP 5582, `mod_admin_web` on 5280/admin. | `jabber/jabber-admin-api-probe.sh` (new), wired into `enum-jabber.sh` as a final phase | ✅ done 2026-05-19 |
| H.7 | README + workflow doc. Order of sections: safety invariants (from ADR-001), `--cleanup` before `--exploit` for the OpenFire helper, common workflows (enum → user-enum → validate → optionally OpenFire), tool index. | `jabber/README.md` (new) | ✅ done 2026-05-19 |
| H.8 | `deps-check.sh` — detect `nc`, `openssl s_client`, Python stdlib XML modules (assert importable). No new external deps required by iteration H. | `deps-check.sh` | ✅ done 2026-05-19 |
| H.9 | Top-level `README.md` — add `jabber/` row to the layout tree + scripts table, and `enum-jabber.sh` row under network dispatchers. | `README.md` | ✅ done 2026-05-19 |

**Prerequisites:** A (inherits `nxc_creds_array` pattern + `ldap_url` IPv6 bracketing for any LDAP cross-references). Independent of B–G.

**Acceptance criteria** (per item, all must pass before tagging `v0.9.0`):
- H.1: `nmap-parse.py --list-categories` shows `xmpp` and `openfire-admin`; a test fixture containing `<port portid="5222">` and `<port portid="9090">` is routed to those categories.
- H.2: `enum-jabber.sh --targets /tmp/lab.txt --output /tmp/out` against a Prosody container produces non-empty `<out>/<ip>/banner.txt`, `cert.pem`, `sasl_mechs.txt`, `ibr_probe.xml`, `disco_info.xml`, `muc_items.xml`. No crash with empty `ENUM_*` env.
- H.3: against a Prosody container with a known account `alice@example.org`, XEP-0077 probe correctly returns `EXISTS` for `alice` and `AVAILABLE` for `nobody-here`; SASL response-based check returns `USER_UNKNOWN` vs `BAD_PASSWORD` distinguishably.
- H.4: against the same Prosody, `jabber-validate.py --jid alice@example.org --password correct` returns `AUTH_OK rc=0`; wrong password returns `AUTH_FAIL: <not-authorized/>` rc=1.
- H.5: against vulnerable Openfire 4.7.4 container, default run reports `VULNERABLE` with version banner; `--exploit` after typed-FQDN confirm creates the admin, uploads webshell, returns URL; `--cleanup` removes both. Against patched 4.7.5+ container, default run reports `NOT VULNERABLE`.
- H.6: against the Prosody container with `mod_admin_telnet` enabled on 5582, the probe reports `EXPOSED admin_telnet`; with it disabled, `NOT_EXPOSED`.
- H.7: README opens with the safety section, documents `--cleanup` before `--exploit` for OpenFire helper, and provides a copy-pasteable end-to-end example.
- H.9: top-level README's layout tree includes `jabber/`; scripts table includes the four jabber helpers and the dispatcher.

**Commit cadence:**
- H.1: `feat(network): add xmpp + openfire-admin service categories to nmap-parse`
- H.2: `feat(network): add enum-jabber.sh dispatcher`
- H.3: `feat(jabber): jabber-user-enum.py — XEP-0077 + SASL + MUC nick harvest`
- H.4: `feat(jabber): jabber-validate.py — single-credential SASL validation`
- H.5: `feat(jabber): openfire CVE-2023-32315 — detect / exploit / cleanup`
- H.6: `feat(jabber): admin-API exposure probe (ejabberd/prosody)`
- H.7+H.8+H.9: `docs(jabber): README + deps-check + top-level README update`
- Release: `chore(repo): release v0.9.0 — iteration H jabber/XMPP tooling`

Tag `v0.9.0`.

### Out of scope for H (recorded by ADR-001)

Cisco UC stack, SIP/voice telephony, modern team chat, password spray, CVE-2023-32315 persistence variant, server-to-server SSRF reconnaissance. Any of these would need a fresh ADR before being added.

---

## Iteration I — Internal-pentest protocol expansion *(added 2026-05-19)*

**Origin:** user milestone — "RemoteAnywhere — add any protocols that may be faced on an internal network pentest of a large engineering and science facility."

**Why:** the dispatchers shipped through v0.12.0 cover the modern cloud-native + Windows-AD surface well, but engineering and science facilities have a distinct protocol stack: industrial/OT control systems, scientific-instrument license servers, remote-support tools, HPC schedulers, lab-bench RDP-alternatives, and out-of-band hardware management. None of these are covered yet.

**Status:** placeholder — needs ADR-002 before sequencing. The candidate list below is for scope conversation, not commitment.

**Candidate protocol surface (clustered by category):**

### I-A. Industrial / OT (read-only probing — these systems often have NO auth at all)
| Service | Default ports | Notes |
|---|---|---|
| Modbus TCP | 502 | Function 17 (Report Slave ID) discloses device family; many PLCs have no native auth |
| Siemens S7comm | 102 | TPKT + COTP wrapper; CPU model + firmware version via job-request |
| EtherNet/IP | 44818 (TCP/UDP), 2222 (UDP I/O) | Rockwell / Allen-Bradley CIP — `List Identity` UDP broadcast |
| BACnet/IP | 47808/udp | Building automation; `Who-Is` broadcast lists every device |
| OPC UA | 4840 | Modern industrial; supports nmap `opcua-info` |
| DNP3 | 20000 | SCADA telecontrol; unauth `link-status` reveals master/outstation |
| IEC 61850 MMS | 102 (shared with S7) | Electrical substations |
| IEC 60870-5-104 | 2404 | European SCADA — energy grids |
| Modbus RTU-over-TCP | 8502 | Less common variant |

### I-B. Remote support / screen sharing
| Service | Default ports | Notes |
|---|---|---|
| TeamViewer | 5938 (tcp) | Cloud-relay; rarely server-side, mostly outbound — banner check |
| AnyDesk | 7070 (mgmt), 6568 (legacy) | Same — mostly outbound |
| ScreenConnect / ConnectWise Control | 8040, 8041 | Server is on-prem — admin panel + relay |
| NoMachine | 4000 (tcp) | NX protocol — handshake banner |
| ICA / Citrix | 1494, 2598 (Session Reliability), 80/443 (StoreFront) | ICA-browser UDP enum |
| Microsoft RDWeb | 443/RDWeb/Pages | RD Web Access portal — pre-auth user enum on poor configs |
| RustDesk | 21115-21119 | Open-source remote desktop |
| pcAnywhere | 5631 (data), 5632 (status) | Legacy but still found |
| GoToMyPC / RemoteAnywhere | cloud-relay | Mostly outbound — domain-name + cert inspection only |

### I-C. License servers (characteristic of engineering/science labs)
| Service | Default ports | Notes |
|---|---|---|
| FlexNet Publisher (FLEXlm) | 27000-27009 (lmgrd), 27010-27999 (vendor daemons) | `lmstat -a` discloses every licensed product + user; common on MATLAB, Cadence, Synopsys, Ansys, COMSOL hosts |
| Sentinel HASP/LM | 1947 | `hasplm -ms` — discloses vendor licenses, sometimes pre-auth admin UI |
| IBM LUM | 4660 | Lotus / IBM legacy |
| Reprise RLM | 5053 | Newer FLEXlm-alternative |
| LabVIEW VI Server | 3363 | Stack overflow CVEs + VI execution if exposed |

### I-D. Out-of-band BMC (paired with the IPMI dispatcher from B.7)
| Service | Default ports | Notes |
|---|---|---|
| HPE iLO | 17988 (legacy), 443 (modern web) | Default creds (Administrator/random — but printed on the chassis sticker) |
| Dell iDRAC | 443 (web), 5900 (vKVM via VNC), 5901, 5902, 5903, 5904 | Default root/calvin |
| Supermicro IPMI / BMC | 443, 5900 | Default ADMIN/ADMIN |
| Lenovo XCC / IMM | 443, 5900 | Default USERID/PASSW0RD |
| Cisco CIMC | 443 | Default admin/password |

### I-E. Hypervisor / virtualization management
| Service | Default ports | Notes |
|---|---|---|
| VMware ESXi | 902, 443, 8000 (vSphere) | Pre-auth CVEs (Log4Shell-adjacent, ESXiArgs ransomware vector via OpenSLP 427) |
| vCenter | 443, 5480 (VAMI), 7444 (legacy STS) | vCenter SSO bypasses + Log4Shell era |
| Proxmox VE | 8006 | Pre-auth /api2/json/version |
| oVirt / RHV | 443 (web), 8443 | Default admin |
| XenServer / XCP-ng | 443 | XenAPI |
| Nutanix Prism | 9440 | Default admin/nutanix/4u |
| OpenStack Horizon | 80/443/5000 (Keystone) | Default admin / well-known passwords in lab installs |

### I-F. HPC scheduler / cluster management
| Service | Default ports | Notes |
|---|---|---|
| Slurm slurmctld | 6817 (mgr), 6818 (compute slurmd) | `sacctmgr show` discloses every user + account |
| PBS / Torque | 15001-15005 | `qmgr -c 'list server'` |
| Univa / Sun Grid Engine | 6444 (qmaster), 6445 (execd) | `qconf -spl` lists projects |
| HTCondor | 9618 | `condor_status` lists every machine |
| Spark master UI | 8080, 7077 | Often unauth |
| HDFS NameNode | 8020, 50070 (legacy), 9870 (modern) | Unauth /jmx + /webhdfs |
| YARN ResourceManager | 8088 | Pre-auth RCE in Hadoop versions |

### I-G. Scientific / lab data services
| Service | Default ports | Notes |
|---|---|---|
| DICOM | 104, 11112 | C-FIND / C-STORE unauth on many imaging modalities |
| HL7 MLLP | 2575, 6661 | Healthcare data exchange |
| LDAP for instrument inventory | 389/636 — already covered |
| Splunk | 8000 (web), 8089 (mgmt API) | Default admin/changeme on lab Splunk installs |
| Grafana | 3000 | admin/admin default; CVE-2021-43798 path traversal |
| InfluxDB | 8086 | Pre-1.x had no auth by default |
| Zabbix | 10050 (agent), 10051 (server), 80/443 (web) | Admin/zabbix default; SQLi CVEs |
| Nagios NRPE | 5666 | Pre-auth RCE in 3.x via $ARG1 |

### I-H. Backup infrastructure (high-value lateral)
| Service | Default ports | Notes |
|---|---|---|
| Veeam B&R | 9392 (REST), 10001-10006 | Multiple high CVEs 2023-2024 — pre-auth RCE chains |
| CommVault | 8400, 81 | Pre-auth RCE in commserve API |
| Veritas NetBackup | 1556, 13724 | bpcd CVE-2017-15743 era |

### I-I. Source / CI infrastructure (often misconfigured in lab DevOps)
| Service | Default ports | Notes |
|---|---|---|
| Jenkins | 8080, 50000 (JNLP), 8443 | Anon "Overall/Read" frequently left enabled; classic Java RCE |
| Gerrit | 29418 (SSH), 8080 | Anon `gerrit ls-projects` |
| Bamboo / Confluence / Jira | 8085, 8090, 8080 | Atlassian's perennial RCE parade |

### I-J. VPN concentrators (the way in / the way around)
| Service | Default ports | Notes |
|---|---|---|
| Cisco AnyConnect / ASA | 443 (WebVPN) | CVE-2020-3187, CVE-2023-20198 cascade |
| Pulse Secure / Ivanti | 443 | CVE-2024-21887 + CVE-2023-46805 |
| Fortinet SSL VPN | 443, 10443 | CVE-2022-42475 |
| Palo Alto GlobalProtect | 443 | CVE-2024-3400 |
| OpenVPN | 1194/udp, 443/tcp | Mostly mTLS — banner only |
| WireGuard | 51820/udp | Stealthy by design — no banner |
| PPTP/L2TP/IPsec | 1723, 500/4500/udp | Legacy enum |

### I-K. Print servers (forgotten but rich in creds)
| Service | Default ports | Notes |
|---|---|---|
| IPP / IPPS | 631, 443 | `ipp-detect-server-version` |
| JetDirect | 9100 | Direct-print, PJL info commands disclose firmware |
| LPD | 515 | Banner |
| Print server admins | 80/443 | Lexmark / Xerox / HP web consoles — default creds common |

### Open scope questions for ADR-002:

1. **OT scope safety**: probing Modbus/S7/DNP3/IEC 60870-5 on a LIVE control system can crash production PLCs even with "read-only" function codes. Acceptable mitigations: dispatcher requires `--ot-confirm` flag + a documented engagement-window restriction. Or: split OT dispatchers into a separate top-level dir (`ot/` not `network/`) so they're not auto-routed by `auto-enum.sh`.

2. **License-server cred-disclosure**: FLEXlm `lmstat -a` is unauth and discloses every user with a checked-out license. Useful intel but technically "engaging" the service. We probably treat as enum (same as `nxc smb -u guest`).

3. **VPN concentrator probing**: most of the high-value VPN findings are vendor-specific CVE check (Pulse/Ivanti, Fortinet, Palo Alto). Do we bundle Nuclei templates for these (already partly covered by enum-http.sh nuclei phase) or build dedicated probes?

4. **Cisco UC stack** (mentioned in ADR-001 D1 as deferred) — does it belong in I-B (remote support adjacent: Jabber-over-CUCM) or stay deferred to its own iteration? Recommendation: keep deferred; it's a deep separate domain.

5. **Stop-list**: Iteration I should be scoped enough to ship in ~3 days. Categories I-A through I-K total ~40 candidate protocols. Realistic v0.16.0 ship: probably the top 12-15 by engagement-frequency. ADR-002 should pick them.

### Out-of-scope for I (decline up front)

- Active exploitation of OT systems (write-side Modbus function codes, PLC code download, etc.) — never. Even with operator confirmation. The blast radius is too large.
- Default-cred brute-force against BMC at scale — single-cred validation only, same policy as Jabber (ADR-001 D2). `creds/default-creds-sweep.py` already exists for vendor-default sweeps and is the right place for that work.
- Anything that modifies HPC scheduler state (submit jobs, cancel jobs).

**Pre-execution requirement:** `docs/ADR-002-<DATE>-internal-pentest-scope.md` resolving questions 1–5 and committing to a top-12-15 protocol list for v0.16.0. Operator approves before code lands.

---

## Out of scope (declined — same as REVIEW-001 §7)

- Detection-evasion tooling
- C2 framework / implant
- Auto-exploit chaining (`auto-enum.sh` discovering RCE and firing exploitation)
- Internet-scale mass enumeration

If a future iteration needs to revisit any of these, that decision goes in a new ADR, not here.

---

## Updating this roadmap

- Mark sub-item status (`⬜` → `🟦` → `✅`) **in the same commit that delivers the change**, per CLAUDE.md §6.
- If a planned item is dropped, set status `❌` and add a "reason: ..." note next to it.
- If new items emerge during execution, add them under the appropriate iteration with `(added YYYY-MM-DD)`.
- Iteration completion adds a `**Completed:** YYYY-MM-DD — tag vX.Y.0` line under that iteration's heading and rolls the CHANGELOG.

End of roadmap.
