# Changelog

All notable changes to **aratool** will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See `CLAUDE.md` §6 for the entry style guide.

## [Unreleased]

*(empty — accumulating since v0.10.0)*

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
