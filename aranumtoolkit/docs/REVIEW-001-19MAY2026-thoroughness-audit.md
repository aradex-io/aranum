# REVIEW-001 — Thoroughness Audit of `aratool`

**Date:** 2026-05-19
**Reviewer:** Claude (Opus, plan-only)
**Scope:** Full repo at HEAD as of `v0.1.0` baseline
**Companion change in this commit:** `standalones/graphql/gql.py --insecure` flag added

---

## Executive summary

`aratool` covers the standard auth/no-auth network-enum perimeter well and has solid privesc enumeration on both OSes. It's strongest where the operator gives it nmap output and walks away with structured per-service findings, and where it provides bug-class-specific helpers (GraphQL authz diff, Redis RCE, ActiveMQ CVE-2023-46604).

The biggest opportunities to make the toolkit **more thorough** are:

1. **Service-coverage gaps** — common high-yield services (PostgreSQL, MongoDB, Elasticsearch, Memcached, IPMI, VNC, IPP/printer, JMX/RMI, RabbitMQ) have no dispatcher.
2. **Authentication-and-AD post-discovery gaps** — no AD CS misconfig (ESC1–8), no LAPS reader, no PetitPotam check, no PrintNightmare, no GPP cpassword sweep, no Kerberos delegation enum, no bulk Kerberoast.
3. **Bug-class gaps in HTTP** — no JWT analysis, no virtual-host fuzz, no CORS/CSRF probe, no subdomain takeover check, no exposed-VCS dir check.
4. **Output is fragmentary** — `auto-enum.sh` produces a directory tree but no single consolidated findings file. There is no Markdown/HTML report, no diff between runs, and no machine-readable findings index.
5. **A handful of correctness/safety bugs** in existing tools, listed below.

A medium-effort plan covering items 1–4 plus the priority-1 bugs would roughly double the assessable surface from a single `auto-enum.sh` invocation.

---

## 1. Coverage gaps — new dispatchers (priority order)

### 1.1 Data stores not covered
| Service | Default ports | Why it matters | Priority |
|---|---|---|---|
| **PostgreSQL** | 5432 | Trust-auth misconfig → `pg_read_server_files`, `COPY PROGRAM` RCE | **P0** |
| **MySQL/MariaDB** | 3306 | Anon/root login, `INTO OUTFILE` webshell, UDF RCE | **P0** |
| **MongoDB** | 27017, 27018 | Frequently unauth; full DB dump trivial | **P0** |
| **Elasticsearch / Kibana** | 9200, 5601 | Unauth API → secrets, `_search` for creds, `_snapshot` RCE | **P0** |
| **Memcached** | 11211 | Unauth read; UDP amp | P1 |
| **CouchDB** | 5984, 6984 | CVE-2017-12635 admin add, CVE-2022-24706 RCE | P1 |
| **etcd** | 2379, 2380 | k8s control-plane keys/certs | P1 |
| **Cassandra** | 9042 | Default cassandra/cassandra | P2 |

### 1.2 Management / out-of-band services
| Service | Default ports | Why it matters | Priority |
|---|---|---|---|
| **IPMI / BMC** | 623/udp | Cipher 0 auth bypass, RAKP password hash recovery | **P0** |
| **VNC** | 5900-5910 | Auth-bypass, weak passwords, screen scrape | P1 |
| **JMX / RMI** | 1099, 7199, 9010 | `mjet`/`ysoserial` deserialization → RCE | P1 |
| **WS-Management (non-WinRM HTTP)** | 5985 from non-Windows | Quick auth probe | P2 |
| **IPP / printer** | 631, 9100 | LDAP creds in print server config, JetDirect direct-print | P2 |
| **Telnet** | 23 | Banner + default creds | P2 |

### 1.3 Messaging / orchestration
| Service | Default ports | Why it matters | Priority |
|---|---|---|---|
| **RabbitMQ mgmt** | 15672 | guest/guest default | P1 |
| **NATS** | 4222 | Often unauth | P2 |
| **Kafka** | 9092 | No-auth message read | P2 |
| **Docker API** | 2375, 2376 | 2375 unauth → container RCE | **P0** |
| **Kubernetes API** | 6443, 8080, 10250 | Anon RBAC, kubelet exec, etcd access | **P0** |

### 1.4 Add catch-all banner grab
`enum-unknown.sh` exists but a generic `nc -nv $ip $port` + 30s banner read + `curl -ksI` would handle 80% of "unknown" cases. Worth checking what it currently does and extending it.

---

## 2. Coverage gaps — checks within existing dispatchers

### 2.1 `aranumtoolkit/network/enum-http.sh`
Currently runs httpx, whatweb, curl -I headers, nuclei (high+critical), ffuf (top-30 alive only), nikto (opt-in). Add:

- **JWT extraction & weakness** — scan headers/bodies/cookies for `eyJ` JWTs; decode header.alg; flag `none`/`HS256` (try common HMAC secrets offline).
- **CORS misconfig probe** — `Origin: https://evil.com` reflected, `Access-Control-Allow-Credentials: true` with reflected origin.
- **Subdomain-takeover signals** — `dig CNAME` then string-match GitHub/Heroku/S3/CloudFront fingerprints in body.
- **Exposed VCS dirs** — `/.git/HEAD`, `/.svn/entries`, `/.hg/store`, `/.DS_Store`. One-liner curl loop.
- **`/server-status`, `/.env`, `/api/swagger.json`, `/actuator/*`, `/wp-json/wp/v2/users`** — micro-wordlist of high-value paths even when ffuf is skipped.
- **Virtual-host fuzz** when target presents a default page — `ffuf -u "http://$ip" -H "Host: FUZZ.$domain" -w subs.txt -fs <baseline_size>`.
- **Cache-deception probe** — append `;.css`, `;.jpg`, `;.php.bak` to known endpoints.
- **HTTP/2 + Range smuggling baseline** — at least record whether server speaks h2/h2c.
- **Cert collection** — `openssl s_client -showcerts -connect ip:port < /dev/null` per HTTPS URL; saves to `cert_<safe>.pem` and dumps SANs. Feeds vhost-fuzz seed and DNS pivot.

### 2.2 `aranumtoolkit/network/enum-smb.sh`
- **NTLM relay viability** — check `SMB signing: disabled` and `SMBv1: enabled` and surface a one-liner: `"smb signing disabled on N hosts — candidate for ntlmrelayx"`.
- **PetitPotam coerce check** — `petitpotam.py` test against DC if `--dc-ip` provided.
- **Shadow Credentials / msDS-KeyCredentialLink** support hint when LDAP is also up.

### 2.3 `aranumtoolkit/network/enum-ldap.sh`
- **BloodHound ingestor** — if creds present, run `bloodhound-python` and drop the zip under `<out>/ldap/<dc>/bloodhound.zip`.
- **AD CS enumeration** — `certipy find` against the DC; flag ESC1–8 templates.
- **Kerberos delegation enum** — constrained / unconstrained / RBCD; one-shot LDAP query.
- **Pre-2000 computer accounts** with password == hostname-lowercase.

### 2.4 `aranumtoolkit/network/enum-kerberos.sh`
- **Bulk Kerberoast** — currently does one-off; add a "give me every SPN and try roasting all" mode with throttling.
- **AS-REP roast on filtered DC** — needs the user list from `enum-smb`/`enum-ldap` rusers; cross-link automatically.

### 2.5 `aranumtoolkit/network/enum-ssh.sh`
- **Algorithm-downgrade fingerprint** beyond `ssh-audit` raw text — surface "negotiates deprecated kex" as a one-liner.
- **Username enum via CVE-2018-15473** check (timing-based).
- **Key-only target detection** — refuse password spray loudly if `PasswordAuthentication no`.

### 2.6 `standalones/graphql/gql.py`
- **Field-suggestion recon when introspection disabled** — `{ __schema { __typename } }` returns "Did you mean `xyz`?" — script can systematically extract symbol names.
- **Alias-based DoS detection** — send a query with N aliases of the same expensive field; record latency growth. (Detect — never weaponize against unauthorized targets.)
- **Batched-query support** — `[{query:...},{query:...}]` body shape; many gateways accept it; differs from spec.
- **Persisted-query bypass** — when target uses APQ (`sha256Hash`), try sending `extensions.persistedQuery` with no body to confirm.
- **`@skip` / `@include` directive abuse** — variable-controlled field inclusion to bypass authz that gates by field name.
- **CSRF check on HTTP GET** — `GET /graphql?query={currentUser{id}}` with a cookie-only browser session.

### 2.7 `standalones/windows/`
- **`Get-LAPSPassword.ps1`** — readable `ms-Mcs-AdmPwd` via LDAP from the host.
- **`Get-ADCSMisconfig.ps1`** — local Certify-equivalent ESC1/ESC2/ESC4 detection (no external dep — pure ADSI).
- **`Get-GPPCPassword.ps1`** — search SYSVOL mounts (`\\domain\SYSVOL`) for `cpassword=...`.
- **`Get-DPAPIBlobs.ps1`** — enumerate Master Keys / credentials / vaults (location only — no decrypt).
- **`Get-NamedPipes.ps1`** — list pipes; flag ones where ACL permits Everyone WRITE.
- **`Get-PrintNightmare.ps1`** — checks `RestrictDriverInstallationToAdministrators`, `NoWarningNoElevationOnInstall`, Spooler service state.
- **`Get-PetitPotamSignals.ps1`** — checks if SMB signing is required on this host and lists IPC interfaces commonly coerced.
- **`Test-CoercedAuth.ps1`** — local-only test, never against arbitrary targets.

### 2.8 `standalones/linux/`
- **`pwnkit-check.sh`** — pkexec presence + version check for CVE-2021-4034.
- **`looney-check.sh`** — CVE-2023-4911 (glibc tunables) version pin.
- **`overlayfs-check.sh`** — CVE-2023-0386 (Ubuntu HWE kernels).
- **`io-uring-check.sh`** — io_uring availability + sysctl `kernel.io_uring_disabled`.
- **`namespaces-check.sh`** — user-namespace unprivileged-create (sysctl `kernel.unprivileged_userns_clone`).
- **`apt-source-check.sh`** — `apt-get` writable cache / hook scripts.

### 2.9 `standalones/creds/`
- **Spray scheduler** with per-target lockout-policy awareness (currently a sweep, not aware of `--threshold=N --interval=M`).
- **Hash-cracking trigger** — write the captured hashes (NTLMv2 from `Inveigh`/responder output, AS-REP/TGS) to `<out>/hashes/` in formats hashcat/jtr-ready.

---

## 3. Correctness / safety bugs in existing tools

Listed in roughly descending severity.

### 3.1 ⚠️ Shell-quoting risk in `_lib.sh::nxc_creds()`  (P0)
`nxc_creds` builds a string `args+=" -u '$ENUM_USER'"` then expects callers to `eval` or expand it. Even though current dispatchers all build their own arg strings (so `nxc_creds` is dead code right now), the function itself is a footgun. If a credential contains a single quote (`Passw'rd`), the shell will break or — worse — execute. **Fix:** convert helper to return a bash array via nameref, or delete it and standardize on inline argv building. Same pattern exists inline in `enum-smb.sh:19,20,21,58,76,77` — those need to use arrays.

### 3.2 ⚠️ `nmap-parse.py` uses stdlib `xml.etree.ElementTree`  (P1)
ET is not safe against XXE / billion-laughs on untrusted XML. In operator-only usage the input is your own nmap output, so this is low risk in practice — but if `auto-enum.sh` is ever invoked from a pipeline that takes XML from outside the operator, this is a hole. **Fix:** swap to `defusedxml.ElementTree` (one-line import change; pip dep) and add a guard so it errors on schemas with DTDs/entities even with stdlib if defusedxml isn't installed.

### 3.3 ⚠️ `gql.py` cache-key collides for cookie/job-token identities  (P1)
`cache_key()` only hashes `PRIVATE-TOKEN` or `Authorization` — a cookie session or `JOB-TOKEN` falls back to literal string `"anon"`, so two distinct cookie-based sessions hit the same cache file. **Fix:** include `Cookie` and `JOB-TOKEN` in the identity-source string.

### 3.4 ⚠️ `gql.py loop --range` has no upper bound  (P2)
`--range 1-9999999999` will materialize a 10-billion-entry Python list before the first request. **Fix:** convert to a generator, refuse ranges > 1M without an explicit `--allow-huge`.

### 3.5 ⚠️ `gql.py` `--header` has no newline/CR validation  (P2)
A header containing `\r\n` would let the operator (themself) inject a second header. Not externally exploitable — operator-supplied — but should reject with a clear error.

### 3.6 IPv6 inconsistency in dispatchers  (P2)
`_lib.sh::split_ipport` handles `[v6]:port` correctly. Some dispatchers (notably `enum-http.sh` lines 40-44 — checked, fine) wrap IPv6 in brackets. **Audit needed:** `enum-ssh.sh`, `enum-ldap.sh`, `enum-mssql.sh`, `enum-redis.sh` — confirm they don't break on bracketed v6 input. Quick test: run each with a `test_v6.targets` file containing `[::1]:22`.

### 3.7 No timeout on inner `while read` loops  (P3)
Several dispatchers loop over URLs / IPs running `curl` per entry. A non-responsive host on a slow path can block the loop. Most already pass `--connect-timeout`/`--max-time`; audit the holdouts (`enum-snmp.sh`, `enum-redis.sh`).

### 3.8 `auto-enum.sh` doesn't honor `-e` / failure detection of dispatchers  (P3)
A dispatcher that exits non-zero has its log captured but `auto-enum.sh` keeps going silently. Add a tally: at the end, print `[!] N dispatchers exited non-zero — check OUTDIR/<svc>/_dispatcher.log`.

### 3.9 `standalones/windows/Invoke-PrivEscEnum.ps1` `Get-HotFix` is slow on Server 2022  (P3)
Replace with `wmic qfe list brief` fallback when `Get-HotFix` takes > 30s.

### 3.10 `gql.py` `_color` ANSI is stripped when stdout is not a TTY but always emitted to stderr  (cosmetic)
Warnings printed to stderr always include color codes. Minor — strip when `sys.stderr.isatty() == False`.

---

## 4. Hardening / OPSEC additions

### 4.1 Proxy / SOCKS support (P0)
On real engagements the operator routes through a pivot (chisel, ligolo-ng, ssh -D). Every tool should honor:
- `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` env (curl/httpx/nuclei already do)
- `--proxy socks5://127.0.0.1:1080` flag where applicable
- `gql.py` does not — `urllib.request.ProxyHandler` add-in, ~10 lines.

### 4.2 User-Agent rotation / customization (P1)
`gql.py` always sends `User-Agent: gql.py/1.0` — easily fingerprinted by WAFs and IDS. Add `--user-agent` flag and a `--ua-rotate` knob. Several other dispatchers (curl callsites) hardcode no UA, getting default `curl/8.x`. Pick a sensible default (Chrome-stable string) and let the operator override.

### 4.3 Source-IP rotation (P2)
Only matters when running through multiple egress proxies. Document a `--proxy-file` pattern.

### 4.4 Throttling defaults (P1)
`auto-enum.sh --parallel 4` is reasonable; document a `--throttle` mode that caps per-target connection rate to <10/sec for sensitive environments.

### 4.5 Engagement-scoped writes (P2)
Some scripts (Redis lateral, Redis SSH-key, ActiveMQ RCE) actually modify target state. **Audit:** confirm each is gated behind an explicit `--write` / `--exploit` flag that defaults off, per CLAUDE.md §9 invariant 1. (Brief skim: looks compliant for `redis-rce-*.sh`, but a formal audit pass is warranted.)

### 4.6 Output redaction mode (P2)
`--redact` flag on the report step that replaces target IPs/hostnames with `<TARGET-N>` for sharing screenshots/snippets externally.

---

## 5. Quality-of-life and reporting

### 5.1 Unified report (P0)
After `auto-enum.sh`, run a `report.py` that walks `OUTDIR/` and emits:

- `report.md` — Markdown: per-service summary table, per-host findings, links to raw files.
- `findings.json` — machine-readable inventory: `{host, port, service, finding, severity, evidence_path}`.
- `report.html` — single-file HTML rendering of the markdown for sharing.

Findings would be tagged with severity heuristics:
- `critical` — unauth RCE evidence (nuclei `critical` tag, redis writable, AMQ vulnerable CVE banner)
- `high` — unauth data access (mongo no-auth, ES unauth `_cluster/state`, anonymous SMB shares with files)
- `medium` — info leak / misconfig (no-SMB-signing, expired cert, CORS reflected)
- `low` — informational fingerprint

### 5.2 Diff between runs (P1)
`autoenum-diff.sh PREV_OUT CURR_OUT` — show new hosts, new services per host, new findings since last run. Critical for long engagements.

### 5.3 Central run log (P1)
`OUTDIR/run.log` with timestamp, tool versions, all dispatcher invocations and exit codes. Reproducibility.

### 5.4 Resume-on-fail (P2)
`auto-enum.sh` re-runs all services if interrupted. A `--resume` flag that consults per-service `.done` markers would let operators iterate quickly.

### 5.5 `deps-check.sh` version checks (P2)
Currently only checks presence. Add minimum-version assertions:
- `impacket` >= 0.11 (older versions miss many SMB3 features)
- `kerbrute` >= v1.0.3
- `nxc` >= 1.2.0
- `nuclei` >= 3.2 (different output format)

### 5.6 Test fixtures (P2)
Only `aranumtoolkit/network/test.{xml,nmap,gnmap}` exist. Add:
- `aranumtoolkit/tests/fixtures/services/` — captured banners/responses per service for offline parser tests
- `aranumtoolkit/tests/test_nmap_parse.py` — unit tests
- `aranumtoolkit/tests/test_gql_query_builder.py` — exercise `build_query` over a tiny schema
- A `make test` target

---

## 6. Recommended execution plan

If you adopt the above, propose this sequencing:

**Iteration A — bug fixes (≈1 day)**
1. §3.1 quoting in `_lib.sh` and `enum-{smb,ldap}.sh`
2. §3.2 `defusedxml` swap (with stdlib fallback that errors on DTDs)
3. §3.3 `gql.py` cache-key fix
4. §3.4 `gql.py` range generator + cap
5. §3.6 IPv6 audit pass

**Iteration B — coverage P0 (≈2 days)**
6. `aranumtoolkit/network/enum-postgres.sh`, `enum-mysql.sh`, `enum-mongodb.sh`, `enum-elastic.sh`, `enum-docker.sh`, `enum-kubernetes.sh`, `enum-ipmi.sh`
7. Wire all into `nmap-parse.py` service-category table

**Iteration C — coverage P1 (≈2 days)**
8. `aranumtoolkit/network/enum-vnc.sh`, `enum-jmx.sh`, `enum-rabbitmq.sh`, `enum-memcached.sh`, `enum-couchdb.sh`, `enum-etcd.sh`
9. HTTP additions in §2.1 (JWT, CORS, VCS dirs, virtual-host fuzz, cert collection)
10. SMB §2.2 NTLM-relay + PetitPotam signals

**Iteration D — Windows/AD depth (≈2 days)**
11. ADCS, LAPS, GPP, PrintNightmare scripts in §2.7
12. `enum-ldap.sh` BloodHound + Certipy integration

**Iteration E — reporting & ergonomics (≈1.5 days)**
13. `report.py` for unified report (§5.1)
14. `autoenum-diff.sh` (§5.2)
15. Central run log (§5.3) + resume (§5.4)
16. SOCKS/proxy support (§4.1) across all tools
17. `deps-check.sh` version assertions (§5.5)

**Iteration F — graphql depth (≈1 day)**
18. `gql.py` field-suggestion harvest, batched-query, persisted-query, directive abuse (§2.6)
19. Proxy + UA flags

**Iteration G — tests + hardening (≈1 day)**
20. Test fixtures + first round of unit tests (§5.6)
21. OPSEC redaction (§4.6)
22. UA rotation (§4.2)

**Total: ~10 working days for full thoroughness pass.** Iteration A is the only mandatory prerequisite; B–G are independent and can be parallelized across PRs.

---

## 7. Out-of-scope / explicitly declined

These came up while reviewing but **should not** be added to this repo:

- **Detection-evasion tooling** (AMSI bypass, ETW patching, EDR unhook) — belongs in a separate red-team repo with stricter access controls. Per CLAUDE.md §9 invariant 5.
- **C2 framework / implant** — distinct project, distinct threat model.
- **Auto-exploit chaining** — `auto-enum` discovering RCE and automatically firing exploitation crosses the operator-in-the-loop line. Keep findings → operator → manual fire.
- **Mass-target enumeration** at internet scale — wrong tool, wrong ethics for this kit. Operators should use shodan/censys for that.

---

## 8. What was already good

To balance the critique: the design choices that should be preserved as the toolkit grows:

- **stdlib-only Python** in `gql.py` and `nmap-parse.py` — trivial to drop on a jump box.
- **`set -uo pipefail` (no `-e`)** in dispatchers — correct for tools that must continue past partial failures.
- **Per-service-per-host output directories** — idempotent re-runs, easy grep, clear evidence per finding.
- **Env-var pass-through for auth** — clean separation, no creds in argv `ps` output.
- **`enum-unknown.sh` catch-all** — important for "the scan found a thing on 47474/tcp" cases.
- **Catalog fallback** in `gql.py` for when introspection is disabled — operators get useful output even on hardened GitLabs.
- **The auth-diff in `gql.py diff`** — quietly the highest-ROI feature in the whole repo for GitLab work.

---

*End of review. Next action per CLAUDE.md §10: commit this file with `docs(repo)` scope, then user picks the iteration to schedule first.*
