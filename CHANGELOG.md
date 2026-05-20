# Changelog

All notable changes to **aratool** will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See `CLAUDE.md` §6 for the entry style guide.

## [Unreleased]

*(empty — accumulating since v0.14.0)*

---

## [v0.14.0] — 2026-05-20

**Iteration G** of ROADMAP-001 — tests + hardening.

### Added
- **G.1 service banner fixtures:** `tests/fixtures/services/` — five synthetic nmap-XML fixtures exercising routing for every category in `SERVICE_MAP` (`all-services.xml`), IPv6 bracketing semantics (`ipv6-host.xml`), the documented dual-routing of openfire-admin on 9090 vs the generic http category (`openfire-vs-http-collision.xml`), closed/filtered port filtering (`closed-and-filtered.xml`), and the unknown-bucket fallthrough (`unknown-service.xml`). All synthetic — no real-target captures.
- **G.2 nmap-parse unit tests:** `tests/test_nmap_parse.py` — 19 stdlib-`unittest` tests across `SERVICE_MAP` completeness, `categorize()` precedence (the openfire/http collision regression case is explicit), full XML-routing through `dispatch()`, IPv6 bracketed-target output, closed-port exclusion, XXE / billion-laughs rejection (anchored on the A.2 hardening), the `--list-categories` / `--unknown` / `--json` CLI surface, and XML-vs-gnmap parser parity. `tests/__init__.py` added so `python3 -m unittest tests.test_nmap_parse` resolves the module.
- **G.3 gql.py pure-function tests:** `tests/test_gql_internals.py` — 28 stdlib-`unittest` tests across seven internal functions chosen for testability without HTTP: `cache_key` (the A.3 identity-expansion fix — distinct cookies / job-tokens / PATs produce distinct cache files; anon path stable), `_check_range_size` (the A.4 bound check — `LOOP_HARD_CAP` boundary, inverted-range exit code, `--allow-huge` bypass), `type_str` (NON_NULL / LIST / nested `[String!]!` reconstruction), `unwrap` (wrapper stripping), `type_by_name` (schema lookup hit / miss / None-input), `parse_kv_args` (only the first `=` splits — base64 values survive; bad input exits 2), and `build_selection` (auto-selection generation for scalar / object / unknown / required-arg-field-skipped cases). Cache dir redirected via `GQL_CACHE_DIR` so tests don't pollute `graphql/.cache/`.
- **G.4 `Makefile`:** convenience targets `test` (lint + unittest + smoke), `lint` (shellcheck), `unittest` (`unittest discover`), `smoke` (`tests/smoke.sh`), `deps-check`, `clean`, `help`. `make help` is the default target.
- **G.5 GitHub Actions CI:** `.github/workflows/ci.yml` — on push + PR to `main`. Installs Python 3.11 + shellcheck (apt) + defusedxml, then runs `make lint && make unittest && make smoke`. `fetch-tags: true` so the smoke test's `git tag` presence check works on CI.

### Enhanced
- **G.7 `--throttle` mode for sensitive environments:** `network/auto-enum.sh --throttle` sets gentle defaults for OT/legacy/lab targets — `ENUM_PARALLEL=1`, `NUCLEI_RATE=20`, `NO_FFUF=1`, `NO_NIKTO=1`, and exports `ENUM_THROTTLE=1` so dispatchers can opt in. **Operator CLI args win over `--throttle` defaults** — `--throttle -P 8` keeps `-P 8` and prints a "operator-explicit; --throttle did not override" line so the precedence is visible. `--throttle --dry-run` previews the effective environment without scanning (the smoke-test interface). `network/_lib.sh`: new helpers `throttle_delay()` (returns the inter-host pause in seconds, default 1, override via `ENUM_THROTTLE_DELAY`), `throttle_sleep()` (no-op when off), and `throttle_nmap_args()` (returns `-T2` under throttle, empty otherwise — use as `nmap $(throttle_nmap_args) ...`).
- `tests/smoke.sh`: extended with throttle-precedence stanza (11b) and write-gate dry-run assertions for every helper that gained a gate in G.8 (11c).
- `deps-check.sh`: added `shellcheck` under OPTIONAL — install via `pip install shellcheck-py` or distro package.

### Security
- **G.6 shellcheck-clean baseline:** every `.sh` file now passes `shellcheck -S warning -e SC1091`. Library files (`network/_lib.sh`, `activemq/_activemq_lib.sh`, `redis/_redis_lib.sh`, `smtp/_smtp_lib.sh`) carry a `# shellcheck shell=bash` directive so the lint scope is unambiguous. Genuine bugs fixed: `SC2069` redirect-order in `network/enum-smtp.sh` and `smtp/smtp-quickwin.sh` (the `2>&1` was before the file redirect, so stderr leaked); `SC2155` declare+assign masking return values in `network/auto-enum.sh` and `smtp/smtp-user-enum.sh`; missing `|| exit` after `cd` in `tests/smoke.sh`. Two unused colour vars (`G`, `C`) dropped from `network/autoenum-diff.sh`. Intentional state vars (`REACHABLE`, `AUTH_REQUIRED`, `REDIS_VERSION`, `RCMD_RC`) in `_redis_lib.sh` and word-splitting `$(curl_auth)` callsites in `_activemq_lib.sh`/`activemq-quickwin.sh` carry targeted `# shellcheck disable=…` directives with reasons. Three parsed-but-unwired flags (`MAX_MSGS`, `PASS_LIST`, `KEEPALIVE`) annotated with TODO reasons rather than silently dropped.
- **G.8 write-gate audit + fixes:** every exploitation helper now honours CLAUDE.md §9 invariant 1 (default = enumeration; mutation requires an explicit gate flag). Audit findings + remediation captured in [REVIEW-002](docs/REVIEW-002-20MAY2026-write-gate-audit.md). Six helpers were in violation at audit start and were fixed in this iteration:
  - `activemq/activemq-cve-2023-46604.py`: added `--exploit` gate (previously default-fired the OpenWire RCE chain on first invocation).
  - `activemq/activemq-jolokia-rce.sh`: added `--exploit` gate (previously default-loaded the MBean and ran the command).
  - `redis/redis-rce-module.sh`: added `--exploit` gate (previously default-chained CONFIG SET + REPLICAOF + MODULE LOAD).
  - `redis/redis-rce-ssh.sh`: added `--write` gate (previously default-dropped `authorized_keys` via CONFIG SET + SAVE). Gate name is `--write` rather than `--exploit` because the primitive is a file write, not an RCE.
  - `smtp/smtp-phish-send.sh`: added `--send` gate (previously default-delivered the spoofed message).
  - `smtp/smtp-smuggling-test.py`: added `--send` gate (previously default-transmitted DATA payloads including the smuggled second-message).
  Every gate prints a dry-run summary and exits 0 when omitted — no env-var bypass. Per-tool READMEs updated to show the new gate flag in the quickstart examples.

---

## [v0.13.0] — 2026-05-19

**Iteration E** of ROADMAP-001 — reporting + ergonomics.

### Added
- `network/report.py` (E.1+E.8+E.9): walks an auto-enum output tree and emits `findings.json` (machine-readable, severity-tagged), `report.md` (Markdown summary + per-host CRITICAL/HIGH detail), and `report.html` (single-file HTML, embedded CSS, no external deps). Severity heuristics anchored on the literal markers dispatchers emit. `--redact` produces a stable `<TARGET-N>` mapping for shareable output. `--severity-rules FILE` lets operators add custom JSON-line rules. Stdlib-only.
- `network/autoenum-diff.sh` (E.2): compares two output trees via their `findings.json`. Surfaces NEW hosts, NEW (host, service) pairs, NEW findings (grouped by severity), and DROPPED findings. Auto-runs `report.py --findings-only` when `findings.json` is missing in either tree. Exit 1 iff any new findings — CI-loop friendly.

### Enhanced
- `network/auto-enum.sh` (E.3+E.4+E.10): central `run.log` under `$OUTDIR` capturing timestamp + auth-presence flags + per-tool versions + per-dispatch begin/end with elapsed seconds and rc. New `--resume` flag honors per-service `.done` markers from prior runs (skip-and-log). Final summary now reports `OK=N FAIL=N SKIP=N` and lists the failed dispatchers; closing hint points at `report.py`.
- `network/_lib.sh` (E.5+E.6): new `curl_ua()`, `curl_proxy_arg()`, `curl_extra_args()` helpers. `ENUM_USER_AGENT` env honored (defaults to the same Chrome-stable string `gql.py` adopted in F.8 — consistent suite fingerprint). `ENUM_PROXY` parallels `GQL_PROXY` for explicit `-x` override; curl's native `*_PROXY` env honor remains the no-config default.
- `network/enum-http.sh`: per-URL header probe now sets `-A "$(curl_ua)"`. Other curl callsites can adopt incrementally.
- `deps-check.sh` (E.7): new `version_floor()` helper using `sort -V`. Floors applied to `nxc`, `netexec`, `kerbrute`, `nuclei`, `ffuf`, `httpx`, `redis-cli`, `mongosh`, `impacket`. Output uses `>=` (green) / `<` (red — upgrade) / `?` (unparseable, manual check).

---

## [v0.12.0] — 2026-05-19

**Iteration F** of ROADMAP-001 — GraphQL depth probes + transport-layer extras.

### Added
- `graphql/gql.py suggest` (F.1): field-name harvest from "Did you mean X?" error messages. Walks a 32-guess built-in corpus or `--corpus FILE`. Useful when introspection is disabled — many resolvers still leak schema structure via suggestion errors.
- `graphql/gql.py apq-probe` (F.3): two-step Apollo Persisted Queries enforcement check. Confirms APQ is implemented, then sends body + forged `sha256Hash` — if server returns data, persisted-query whitelist is bypassable (CRITICAL).
- `graphql/gql.py csrf-probe` (F.5): `GET /graphql?query={__typename}`. Spec-compliant servers reject (400/405). Servers that accept GET combined with cookie auth = one img/iframe away from arbitrary-query CSRF.

### Enhanced
- `graphql/gql.py call --batch N` (F.2): send the same body in a JSON array of length N. Tests batched-body gateways for per-request authz / shared-resolver state leakage.
- `graphql/gql.py call --alias-dos-check --confirm` (F.6): DETECT-ONLY latency growth measurement with N=1,2,4,…,16 aliases of `__typename`. Super-linear growth = missing alias normalization = DoS-amplification surface. Refuses to run without `--confirm`.
- `graphql/gql.py diff --directive-bypass` (F.4): wraps every field in `@skip(if:$gqlSkip)`; reference profile sets it `false`, others `true`. Detects authz checks that key on AST-presence rather than resolver-execution.
- `graphql/gql.py raw --batch N` (F.2): same batched-POST semantics for the literal-query subcommand.
- `graphql/gql.py --proxy URL` (F.7): HTTP/HTTPS/SOCKS proxy via urllib's `ProxyHandler`. Env fallback `GQL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`. SOCKS via `socks5h://` requires PySocks (not a hard dependency).
- `graphql/gql.py --user-agent / --ua-rotate / GQL_UA` (F.8): default User-Agent changed from `gql.py/1.0` to a Chrome-stable string. `--user-agent gql` re-enables legacy UA; `--user-agent <literal>` overrides; `--ua-rotate FILE` picks a random UA per request.

### Refactored
- `graphql/gql.py`: `http_post()` now uses `_opener()` (builds urllib opener with proxy + TLS context); `http_get()` added for the CSRF probe. All existing subcommands inherit the new transport behavior unchanged.
- `tests/smoke.sh`: extended with `v0.12.0` tag check + suggest/apq-probe/csrf-probe smoke against unreachable target.
- `docs/ROADMAP-001-...`: iteration F marked complete (tag v0.12.0). Overall iteration table reordered to match real ship order (A→H→B→C→F, with E/G/D/I still ⬜). Iteration I added as placeholder for the new user milestone (engineering/science facility internal-pentest protocols — industrial/OT, remote-support, license servers, BMC, hypervisor mgmt, HPC schedulers, lab data services, backup, source/CI, VPN concentrators, print). 40+ candidate protocols listed; ADR-002 required before any code lands.

---

## [v0.11.0] — 2026-05-19

**Iteration C** of ROADMAP-001 — P1 service coverage + HTTP-depth bug-class checks + SMB/SSH extras. Fifteen sub-items shipped (C.0–C.14).

### Added
- `network/enum-vnc.sh` (C.1): nmap `vnc-info`/`vnc-title`/`realvnc-auth-bypass` (CVE-2006-2369 raises CRITICAL) + raw RFB banner.
- `network/enum-jmx.sh` (C.2): nmap `rmi-dumpregistry`/`rmi-vuln-classloader` across 1099/9999/9010/11099/7199 + JRMI handshake probe. Hints document mjet/ysoserial/msf follow-ups; never auto-run.
- `network/enum-rabbitmq.sh` (C.3): mgmt-API probe with default `guest:guest` and optional `ENUM_USER`/`ENUM_PASS`. Pulls users/vhosts/exchanges/queues/connections/permissions on auth.
- `network/enum-memcached.sh` (C.4): `stats` / `stats slabs` / `stats items` / `stats sizes` / `stats settings` + cachedump enumeration of first 5 slabs × 50 keys. Memcrashed amplification warning in hints.
- `network/enum-couchdb.sh` (C.5): `_all_dbs`/`_users/_all_docs`/`_config`/`_membership`/`_node/_local/_config`. Version-range signal for CVE-2017-12635 (pre-1.7.0 / pre-2.1.1).
- `network/enum-etcd.sh` (C.6): `/version`/`/v2/keys/?recursive=true`/`/metrics` across HTTP and HTTPS. Unauth v2 keys response = full k8s control-plane secret-store read = CRITICAL.
- `network/nmap-parse.py` (C.0): four new categories — `rabbitmq` (5672/15672/5671/15671), `memcached` (11211), `couchdb` (5984/6984), `etcd` (2379/2380). `vnc` (5800/5900-5902) and `jmx` (1099/9999/9010/11099) were already present.

### Enhanced
- `network/enum-http.sh` (C.7–C.12): six new probes gated on at-least-one-live-URL —
  - **C.7 JWT extraction**: greps response bodies for the three-part `eyJ...` shape, decodes header, raises err() on `alg=none`, hit() on HS* (hashcat -m 16500). `_jwts.txt` aggregates findings.
  - **C.8 CORS misconfig**: `Origin: https://attacker.example.invalid` reflected back + `Access-Control-Allow-Credentials: true` = CRITICAL.
  - **C.9 exposed VCS/sensitive paths**: `.git/HEAD`, `.git/config`, `.svn/entries`, `.svn/wc.db`, `.hg/store`, `.DS_Store`, `.env*`, `web.config`, `wp-config.php.bak`, `config.json`, `server-status`, `server-info`.
  - **C.10 vhost-fuzz seed**: aggregates collected SAN domains into `_all_sans.txt`; hints document the ffuf command.
  - **C.11 cert+SAN collection**: `openssl s_client -showcerts` per HTTPS URL; per-URL SANs feed C.10.
  - **C.12 high-value path micro-wordlist**: `/api/swagger.json`, `/swagger.json`, `/openapi.json`, `/actuator/health`/`env`/`heapdump`, `/wp-json/wp/v2/users`, `/admin`, `/phpmyadmin/`, `/manager/html` (folded into C.9's HEAD sweep).
- `network/enum-smb.sh` (C.13): parses existing nmap-smb-vuln output for "signing enabled but not required" / "enabled: false"; aggregates relay candidates to `_relay_candidates.txt` and raises CRITICAL with host count. PetitPotam signal via rpcclient `\pipe\lsarpc` anonymous reachability when `ENUM_DC_IP` is set. Does NOT run impacket coerce tools.
- `network/enum-ssh.sh` (C.14): parses `auth_methods.txt` from phase 3 — `publickey` advertised AND no `password`/`keyboard-interactive` → `_key_only_<port>.txt` (refuse spray hint). Parses OpenSSH version from `banner.txt`; < 7.7 raises CVE-2018-15473 candidate signal.

### Refactored
- `tests/smoke.sh` extended to cover all 13 new dispatchers + `v0.11.0` tag check.
- `README.md` network table extended with six new C.0-C.6 dispatcher rows.

---

## [v0.10.0] — 2026-05-19

**Iteration B** of ROADMAP-001 — P0 service-coverage expansion. Adds 7 new network dispatchers + 2 new nmap-parse categories. Auto-routed by `auto-enum.sh` based on the new categories. Version is `v0.10.0` (not the originally-reserved `v0.3.0`) because semver requires monotonic increase and iteration H already shipped at `v0.9.0`; the roadmap's iteration→tag mapping is corrected to reflect actual chronology.

### Added
- `network/enum-postgres.sh` (B.1): trust-auth probe (no-pwd attempts as `postgres`/`admin`/`app`) + `nxc postgres` cred check + `psql` authenticated recon dumping `pg_roles` + database list + version. Hints cover post-auth escalation: `COPY ... TO PROGRAM`, untrusted PL languages, `lo_import`/`lo_export`, `dblink`.
- `network/enum-mysql.sh` (B.2): anonymous + root-no-pwd probes (`root`/`admin`/`mysql`) + `nxc mysql` + auth recon dumping `mysql.user`, `secure_file_priv`, `local_infile`, `SHOW GRANTS`. Hints cover `INTO OUTFILE`, UDF RCE, `LOAD DATA LOCAL INFILE`.
- `network/enum-mongo.sh` (B.3): `mongosh`-preferred-or-`mongo`-legacy unauthenticated `listDatabases` probe + per-database collection enumeration (capped at 10 dbs × 50 collections each). IPv6-aware connection-URI construction (per MongoDB URI spec). Auth recon via `usersInfo` + `rolesInfo`. nmap mongodb-info/mongodb-databases NSE.
- `network/enum-elastic.sh` (B.4): `curl`-based probes of `_cluster/health`, `_cluster/state`, `_cat/indices?v`, `_cat/nodes?v`, `_security/user`. Cred-leak sweep via `_search?q=password*|passwd*|secret*|api_key*|token*` with hit-count parsing. Kibana 5601 `/api/status` detection. TLS-insecure by default (engagement targets).
- `network/enum-docker.sh` (B.5): **CRITICAL when triggered.** Remote Docker daemon API probe — `/version`, `/info`, `/containers/json`, `/images/json`, `/networks`, `/volumes` against 2375 (plaintext — dangerous) and 2376 (TLS). Unauth 2375 success raises an `err()`-tagged alert with the explicit "host-equivalent RCE via `docker run -v /:/mnt --privileged`" warning text. **Never invokes `docker run`** — the operator decides.
- `network/enum-kubernetes.sh` (B.6): TLS apiserver 6443 + insecure apiserver 8080 (raises CRITICAL when present — deprecated, full cluster control) + kubelet 10250 (`/pods`, `/stats/summary`, `/metrics`, `/healthz`) + readonly kubelet 10255 + kube-proxy 10256. Optional `K8S_TOKEN` env for operator-supplied Bearer token. Captures apiserver `gitVersion`.
- `network/enum-ipmi.sh` (B.7): `nmap -sU -p623` with `ipmi-version`, `ipmi-cipher-zero`, `ipmi-brute` NSE scripts. Cipher-0 hits raise CRITICAL alert via parsed nmap output. Hints document the manual `msfconsole auxiliary/scanner/ipmi/ipmi_dumphashes` and `ipmitool sol activate` follow-ups — never auto-executes msf.
- `network/nmap-parse.py` (B.8): two new categories — `docker` (ports 2375, 2376) and `kubernetes` (6443, 8080, 10250, 10255, 10256). Both use the canonical never-match regex `a^` because nmap fingerprints them as generic `http`/`ssl/http`; the dispatchers handle product detection. Synthetic-XML routing verified: `docker → {2375}`, `kubernetes → {6443, 10250}`, no false positives on port 80.

### Refactored
- ROADMAP-001: iteration B marked complete; tag-mapping note added clarifying that iteration ordering (H before B) determined actual tag order (`v0.9.0` then `v0.10.0`), not the original aspirational mapping.

---

## [v0.9.0] — 2026-05-19

**Iteration H** of ROADMAP-001 — Jabber/XMPP pentesting tooling per [ADR-001](docs/ADR-001-19MAY2026-jabber-scope.md). Iteration H jumps the version from v0.2.0 to v0.9.0 to match the roadmap's tag plan (B–G iterations are not yet shipped; their tag slots are reserved).

### Added
- `jabber/README.md`: complete tool index + workflow for iteration H. Opens with safety summary (read first), documents the `--cleanup`-before-`--exploit` discipline for the OpenFire CVE helper, walks the typical workflow (discover → enum-jabber → user-enum → validate → optional Openfire detect/exploit/cleanup), gives the JSP plugin manifest template, and explicitly lists what the iteration does NOT do and why (no spray, no XEP-0077 conflict-probe, no Cisco UC, no bundled webshell, no Openfire persistence variant). (ROADMAP-001 H.7)
- `deps-check.sh`: new `JABBER / XMPP` section verifying `nc`, `openssl`, and the Python stdlib modules the jabber/ helpers depend on (`socket`, `ssl`, `base64`, `hashlib`, `hmac`, `urllib.request`, `xml.etree.ElementTree`). No new external deps required by iteration H. (ROADMAP-001 H.8)
- `README.md`: layout tree updated to reflect every top-level dir (was missing `graphql/`, `activemq/`, `redis/`, `smtp/`, `creds/`, `docs/`). New `jabber/` row added. New `enum-jabber.sh` row added under network dispatchers. New "Jabber / XMPP (iteration H)" section with the four jabber/ tool descriptions and ADR pointer. (ROADMAP-001 H.9)
- `jabber/jabber-admin-api-probe.sh`: read-only detection of exposed Ejabberd / Prosody admin surfaces — Ejabberd HTTP commands API at `/api/status` over ports 5280/5281/80/8088 (HEAD-classified: 200/400/405 = EXPOSED, 401/403 = auth-required, 404 = module not enabled), Prosody `mod_admin_telnet` banner probe on TCP 5582, Prosody `mod_admin_web` at `/admin/` on 5280/5281. Sends only HTTP HEAD/GET and a single TCP banner read. Per-finding evidence files written to `--out` dir; one-line INFO/HIT/MISS per probe to stdout. Wired into `enum-jabber.sh` as phase 7 (de-duped per host so multi-port targets don't re-probe). (ROADMAP-001 H.6)
- `jabber/openfire-cve-2023-32315.py`: detect / exploit / cleanup helper for the Openfire admin-console auth-bypass path traversal (per ADR-001 D3). **Default behavior (`detect`)** probes `/setup/setup-/%u002e%u002e/log.jsp`, classifies VULNERABLE / NOT_VULNERABLE / UNKNOWN based on HTTP status + admin-console markup, and prints the server version banner. **No state change.** **`exploit`** prompts the operator to type the target FQDN/IP literally (no `--yes-i-mean-it` short-circuit), then performs the DWR-based `userService.createUser` call via the bypass, then multipart-uploads an operator-supplied JSP-plugin JAR (`--plugin-jar`), then prints the resulting webshell URL and writes a log file for `cleanup`. **`cleanup`** consumes the log and reverses the changes via the legitimate admin interface. Cleanup is currently a **scaffold** with documented manual procedure — the legitimate-login-then-delete flow varies enough by Openfire version that we will not ship untested removal code. Stdlib-only (per ADR-001 D4). The full chain is written per the public CVE advisory PoC pattern and explicitly flagged REQUIRES_LAB_VERIFICATION against a known-vulnerable Openfire 4.7.4 container before any engagement use. (ROADMAP-001 H.5)
- `jabber/jabber-validate.py`: stdlib-only single-credential XMPP SASL validation (per ADR-001 D2 — no spray). Tries mechanisms in order (default: `scram-sha-256,scram-sha-1,plain`), only those advertised by the server, with the stream re-opened between each failed attempt (the SASL state machine treats `<failure/>` as terminal). SCRAM-SHA-1 and SCRAM-SHA-256 implemented inline via stdlib `hashlib.pbkdf2_hmac` + `hmac` — verified against the RFC 5802 §5 reference vector byte-for-byte. Reads password from `--password` or `JABBER_PASSWORD` env. Exit codes: 0 = AUTH_OK, 1 = AUTH_FAIL (with reason), 2 = pre-auth protocol/connect error. (ROADMAP-001 H.4)
- `jabber/jabber-user-enum.py`: stdlib-only XMPP user enumerator using the SASL PLAIN response differential (read-only — no account creation). For each candidate username, opens a stream, optionally negotiates STARTTLS, attempts SASL PLAIN with a deliberately bogus password, and classifies the `<failure/>` XML per RFC 6120 §6.5 — `<not-authorized/>` → USER_EXISTS, `<account-disabled/>` → EXISTS_DISABLED, `<credentials-expired/>` → EXISTS_EXPIRED, `<invalid-authzid/>` → INVALID_FORMAT, etc. Per-user response time recorded as a timing-side-channel fallback for servers that return identical `<not-authorized/>` for every name. Per-user JSONL output via `--out`, summary table at end. Deliberately does NOT use the XEP-0077 IBR conflict-error trick (it creates accounts when the conflict path doesn't fire — violates ADR-001 D2). (ROADMAP-001 H.3)
- `network/enum-jabber.sh`: XMPP/Jabber enumeration dispatcher, auto-routed from the `xmpp` category. Seven phases — raw TCP banner, STARTTLS feature probe + cert/SANs collection (extracts domain from cert SAN when `ENUM_XMPP_DOMAIN` not set), SASL-mechanism inventory, XEP-0077 in-band-registration advertisement check (no actual register call), server `disco#info` + `disco#items`, MUC discovery on `conference.<domain>`, BOSH/WebSocket endpoint detection on 5280/5281. All probes are read-only; tools gracefully no-op when `nc`/`openssl`/`curl` absent. Output per-host per-port under `$OUT/<ip>_<port>/`. (ROADMAP-001 H.2)
- `network/nmap-parse.py`: two new service categories — `xmpp` (ports 5222/5223/5269/5280/5281/5298/7777; service-name regex matching `xmpp`/`jabber`/`xmpp-client`/`xmpp-server`) and `openfire-admin` (ports 9090/9091, port-only — uses the canonical never-match regex `a^` so HTTP service names on other ports don't accidentally tag as openfire-admin). Verified: 9090 routes to both `http` (intentional overlap) and `openfire-admin`; port 80 does NOT route to `openfire-admin`. (ROADMAP-001 H.1)
- `docs/ADR-001-19MAY2026-jabber-scope.md`: Architecture Decision Record locking in scope for iteration H (Jabber/XMPP tooling). Records four decisions: XMPP-only surface (Cisco UC, SIP/voice, modern team chat deferred), no spray (enum + single-cred validation only), OpenFire CVE-2023-32315 ships as detect-default / `--exploit` full-chain / `--cleanup` reverse with typed-FQDN confirm, stdlib-only Python.
- `docs/ROADMAP-001-...`: iteration H placeholder replaced with full per-item plan (H.1–H.9), commit cadence, and acceptance criteria all bound to ADR-001.

### Refactored
- ROADMAP-001 iteration A marked complete (tag `v0.2.0` shipped); iteration H marked complete (all nine sub-items, this release).

---

## [v0.2.0] — 2026-05-19

**Iteration A** of ROADMAP-001 — bug fixes from REVIEW-001 §3 (5 of 10 items addressed; the remaining 5 are lower-severity tracked items not blocking later iterations) plus the governance artifacts that established the repo's commit/changelog/versioning discipline.

### Security
- `network/_lib.sh` + `network/enum-{smb,ldap,mssql,winrm,rdp}.sh`: replaced shell-string credential concatenation (`NXC_ARGS+=" -u $ENUM_USER"`) with bash arrays via new `nxc_creds_array` helper. Closes the shell-injection footgun where credentials containing quotes, spaces, or shell metacharacters could break tooling or — given a hostile credential — execute arbitrary commands. Verified end-to-end with a payload-style credential (`al'ice"bob; rm -rf /tmp/X`) — no shell expansion, no rm execution. (REVIEW-001 §3.1)
- `network/nmap-parse.py`: hardened XML parsing against XXE / billion-laughs. Prefers `defusedxml.ElementTree` when installed; falls back to stdlib with a regex pre-scan of the prolog that rejects `<!ENTITY` declarations and `SYSTEM`/`PUBLIC` external references inside DOCTYPE. Benign nmap output (which always emits `<!DOCTYPE nmaprun>` with no internal subset) parses byte-identically. Verified: `tests/fixtures/malicious_xxe.xml` and `tests/fixtures/billion_laughs.xml` rejected under both backends with clean stderr messages. (REVIEW-001 §3.2)

### Fixed
- `network/enum-ldap.sh`: IPv6 LDAP server addresses are now bracketed in the `ldap://` URL via new `ldap_url()` helper. Previously `ldap://2001:db8::1` would be parsed ambiguously by `ldapsearch`'s URL handler. v4 callsites unchanged. (REVIEW-001 §3.6)
- `graphql/gql.py`: `cache_key()` now includes `Cookie` and `JOB-TOKEN` headers (in addition to `PRIVATE-TOKEN` and `Authorization`) in the per-identity cache hash. Two cookie-based or job-token-based sessions against the same URL no longer collide on a single cache file. Anonymous calls still share a single cache entry. (REVIEW-001 §3.3)

### Enhanced
- `graphql/gql.py`: added `--insecure` / `-k` flag and `GQL_INSECURE=1` env var to bypass TLS certificate verification (mirrors `curl -k`). Default behavior (verify) unchanged. Affects every subcommand that hits the network (`introspect`, `ls`, `describe`, `call`, `loop`, `diff`, `raw`).
- `graphql/gql.py loop`: `--range` and `--gid-range` now materialize values lazily via generators. A new `LOOP_HARD_CAP = 1_000_000` ceiling refuses unbounded sweeps (the prior code would build a 10-billion-element Python list and OOM before the first request fired). Pass `--allow-huge` to override. Inverted ranges (hi < lo) now produce a clean error instead of a silent zero-iteration loop. Verified: 2M-element generator stays under 25 MB RSS for partial consumption. (REVIEW-001 §3.4)

### Added
- `network/_lib.sh`: `nxc_creds_array <ARRAY_NAME>` helper using bash namerefs (4.3+) to populate credential argv safely.
- `network/_lib.sh`: `ldap_url <ip> [port] [scheme]` helper to construct LDAP URLs that respect IPv6 bracketing.
- `tests/fixtures/malicious_xxe.xml` + `tests/fixtures/billion_laughs.xml`: regression fixtures for `nmap-parse.py` XML hardening.
- `deps-check.sh`: detect `defusedxml` Python package; lists `pip3 install defusedxml` under install hints.
- `CLAUDE.md`: agent mandates covering scope, model split (Opus plan / Sonnet execute), commit format, semver, changelog discipline, code style, safety invariants.
- `CHANGELOG.md`: this file.
- `.gitignore`: excludes `__pycache__/`, `.cache/`, `enum-results/`, `*.so`, local secrets.
- `docs/REVIEW-001-19MAY2026-thoroughness-audit.md`: collection-wide audit identifying coverage gaps and hardening opportunities.
- `docs/ROADMAP-001-19MAY2026-thoroughness-execution.md`: living, dated execution plan sequencing all REVIEW-001 items across 7 iterations (A–G) tied to MINOR release tags `v0.2.0`–`v0.8.0`. Iteration H (Jabber/XMPP/comp pentesting) added 2026-05-19 as user-requested milestone targeting `v0.9.0`.

### Refactored
- Repo re-initialized as a standalone git repository (was previously untracked).

---

## [v0.1.0] — 2026-05-19

Initial inventory of the toolkit (pre-versioning baseline). Documented in `README.md`. No formal release tag was cut; this entry exists so future releases have a numeric anchor.

### Added
- `windows/` — PowerShell privesc enumeration (services, tasks, tokens, registry, creds, AlwaysInstallElevated, writable PATH dirs) plus `enum.bat` no-PS fallback.
- `linux/` — bash privesc enumeration (SUID, sudo, capabilities, cron, containers, writable files, group, creds hunt) and `linenum-fast.sh` one-shot.
- `network/` — `nmap-parse.py` (XML/gnmap/nmap → JSON inventory), `auto-enum.sh` orchestrator, and per-service dispatchers for SMB, LDAP, Kerberos, WinRM, RDP, MSSQL, HTTP(S), SSH, FTP, SNMP, NFS, DNS, Redis, SMTP, ActiveMQ, plus an `enum-unknown.sh` catch-all.
- `graphql/gql.py` — stdlib-only GraphQL toolkit (introspect / ls / describe / call / loop / diff / raw), GitLab catalog fallback when introspection is disabled.
- `redis/` — quickwin, lateral, RCE-via-SSH-key, RCE-via-module, rogue-master scripts and Redis module source.
- `activemq/` — CVE-2023-46604 PoC, Jolokia RCE, queue dump, quickwin.
- `smtp/` — quickwin, user enumeration, relay test, SMTP smuggling test, SPF/DMARC check, phishing send.
- `creds/` — default-credentials sweep (JSON catalog of vendor defaults).
- `deps-check.sh` — verify presence of required / recommended / optional tools.
