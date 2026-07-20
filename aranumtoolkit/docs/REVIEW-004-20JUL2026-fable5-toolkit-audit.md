# REVIEW-004 — Fable 5 whole-toolkit audit (gaps, improvements, additions)

- **Date:** 2026-07-20
- **Reviewed version:** v0.32.0 (`45c43f6`)
- **Method:** Six parallel Fable-5 reviewers, one per subsystem, each reading the
  code in full and verifying every claim against source. Findings already tracked
  in REVIEW-001/002/003 and ROADMAP-001/002/003 were excluded.
- **Standing constraint on every recommendation:** stay on **bare Linux + minimal
  dependencies** — bash + coreutils + stdlib `python3` (3.9+), plus tools already
  assumed. No new heavy runtime deps; honor the §9 OPSEC invariants and §8 style.

This is an audit artifact, not a change. Nothing here has been implemented. Items
are grouped by subsystem; the cross-cutting action list at the end ranks the whole
set. Priorities: **P0** ship-blocking / safety, **P1** high-value, **P2** worthwhile,
**P3** polish.

---

## 0. Headline items (read these first)

1. **[P0 · safety] `redis-rce-ssh.sh` wipes all victim data.** Line 121 runs
   `FLUSHALL ASYNC` inside the `--write` path for every candidate `.ssh` dir —
   an unrecoverable keyspace delete. It contradicts the subsystem README's
   explicit "no data loss occurs" claim and CLAUDE.md §1 ("Do not add scripts that
   … destroy data"), is undisclosed in the dry-run summary, and REVIEW-002 passed
   it by checking only that the `--write` gate exists, not that the gated action is
   destructive. The flush is not load-bearing (the pad-with-newlines trick already
   isolates `authorized_keys`). **Remove it**; if a minimal RDB is ever wanted, put
   it behind a distinct `--flush` opt-in, disclose it in the dry-run, and fix the
   README's false claim.

2. **[P0 · gap] The Windows bulk sweep silently omits every D1.4 AD check.**
   `bulk-enum-windows.py` ships only `Invoke-PrivEscEnum.ps1`, which re-implements a
   *subset* inline and dot-sources **none** of `Get-ADCSMisconfig` / `Get-LAPSPassword`
   / `Get-GPPCPassword` / `Get-DPAPIBlobs` / `Get-NamedPipes` / `Get-PrintNightmare`
   / `Test-CoercedAuth` / `Get-PetitPotamSignals`. So a `bulk-windows` engagement
   produces zero ADCS/ESC, LAPS, GPP, DPAPI, named-pipe, PrintNightmare, or coercion
   signal — exactly the AD-depth work the toolkit invested in. Compounded by the
   verdict-plumbing bug in item 3.

3. **[P1 · gap] XMPP/Jabber servers are never enumerated.** `nmap-parse.py` routes
   XMPP ports to category `xmpp`, but `auto-enum.sh:344` derives the dispatcher as
   `enum-${svc}.sh` and there is no `enum-xmpp.sh` — every discovered XMPP host hits
   the "no dispatcher" fall-through even though `enum-jabber.sh` exists and is
   name-agnostic. **One-line fix**: symlink `enum-xmpp.sh -> enum-jabber.sh` (exact
   precedent: `enum-https.sh -> enum-http.sh`), then make the planner's `dispatcher`
   field authoritative in `--queue` mode so the category→filename divergence can't
   recur.

---

## 1. Network orchestration core

### [P1] `auto-enum.sh` ignores the metadata `dispatcher` field
`plan.py:367` records each task's `dispatcher`, but `auto-enum.sh` (normal and
`--queue` modes) reconstructs `enum-${svc}.sh` from the category. They agree by luck
for all categories except `xmpp`/`openfire-admin` (item 3 above). Prefer the queued
`dispatcher` value; fall back to the derived name. **S.**

### [P2] `generated_utc` timestamps are malformed ISO-8601 (`…+00:00Z`)
`report.py:870`, `report.py:1069`, `merge-results.py:186` all do
`datetime.now(timezone.utc).isoformat() + "Z"`, yielding `…+00:00Z` — two tz
designators, rejected by `datetime.fromisoformat()` on every Python version. Drop the
literal `"Z"` or use `strftime("%Y-%m-%dT%H:%M:%SZ")`. Breaks any consumer parsing
the field (incl. `autoenum-diff.sh`, `merge-results.py`). **S.**

### [P2] `report.py` scans JSON/XML despite a comment claiming it skips them
`walk_findings` (`report.py:721-751`) has no suffix filter, so structured evidence
(`default-creds.json`, nxc `--jsonl`, nuclei `-json`, `_meta.json`) is line-scanned;
the broad LOW banner rule + CVE rules fire on JSON, inflating/duplicating findings.
Comment at line 733 says the opposite. Skip `.json`/`.xml`/`.pem` by suffix. **S.**

### [P2] Severity classification is O(lines × ~90 regexes) with no prefilter
`_classify` (`report.py:403-413`) walks ~90-100 rules per line; the vast majority of
verbose tool output matches nothing and pays the full cost. Add a substring pre-gate
(`any(tok in line for tok in _HOT_TOKENS)` over `UNAUTH`/`CRITICAL`/`EXPOSED`/`CVE-`/…)
to skip the regex loop; combined with the JSON/XML skip this is the biggest
dependency-free perf + finding-quality win at 500+ host scale. **M.**

### [P2] `aranum run … -report` blocks indefinitely serving the dashboard
The documented `aranum run scan01 -report` chains report→dashboard, and the chained
`_run_dashboard` call omits `--no-serve` (`aranum.py:613`), so it falls into a
blocking `http.server`. Generate-only by default; add an explicit `--serve` opt-in;
print the `file://…/index.html` path. **S.**

### [P2] `queue.jsonl` has no execution-state writeback → no per-task resume
The planner emits a rich per-task queue with `status`, but nothing writes status back;
`--resume` is only the coarse per-service `.done` marker. Have queue-mode
`run_dispatcher` append to a sibling `queue.state.jsonl` (`{task_id,status,rc,ts}`,
append-only so the plan stays immutable); resume can then skip done `task_id`s. **M.**

### [P3] Other verified defects
- **No cross-service parallelism** — `auto-enum.sh:426` runs services strictly
  serially; `-P` only fans out hosts within a dispatcher. Optional bounded
  `--service-parallel N` via `xargs -P`, default unchanged. **M.**
- **gnmap parser mislabels version as `product`** — `nmap-parse.py:284-295` maps
  `parts[6]` (version) into `product`, leaving `version` empty (gnmap path only). **S.**
- **`autoenum-diff.sh` drops non-canonical severities** — buckets seed only
  critical/high/medium/low; other labels count toward exit code but never print
  (`autoenum-diff.sh:83-95`). **S.**
- **`--session` flags silently ignored** for `plan`/`report`/`merge` — stripped by
  `_strip_session_args` but never used; either wire session placement or reject with a
  message. **S.**

---

## 2. Service dispatcher coverage

### [P1] Add the UDP amplification / discovery cluster: NTP, SSDP/UPnP, mDNS
None of `ntp` (123), `ssdp`/`upnp` (1900), `mdns`/`dns-sd` (5353) are in
`nmap-parse.py` SERVICE_MAP and no dispatcher exists — three of the highest-yield
internal-recon + reflection-precondition surfaces. Reuse the existing E4
`--aggressive` / `ENUM_RUN_X=1` double-gate. Pure stdlib-python3 socket (mode-6
`readvar`/mode-7 `monlist`; `M-SEARCH`; `_services._dns-sd._udp.local` PTR) with nmap
NSE fallbacks. Gate the reflection-capable ones like `--slp`. **M.**

### [P1] `enum-ssh.sh` missing regreSSHion (CVE-2024-6387) + Terrapin (CVE-2023-48795)
The dispatcher emits only CVE-2018-15473. It already has the OpenSSH banner parsed —
add a patch-level parse and emit signals for the two vulnerable regreSSHion ranges
(`<4.4p1`, `8.5p1 ≤ x < 9.8p1`, distro-backport caveat) and a Terrapin candidate note
from the KEX/cipher list. **S.**

### [P1] `enum-mssql.sh` never probes UDP 1434 SQL Browser
NSE is hardcoded `-p1433`, so named/dynamic-port instances (discoverable only via the
UDP 1434 Browser datagram → `ServerName;InstanceName;tcp;<port>`) are silently missed.
Add a `-sU -p1434 --script ms-sql-info,ms-sql-dac` (or 1-byte `\x02` socket) pass and
feed discovered ports back into the TCP probes. (Also: the default `-x 'whoami'`
xp_cmdshell exec fires on any credentialed run — align with §9 read-default like the
other dispatchers.) **S.**

### [P1] Port 9100 routes only to `print`, swallowing Prometheus `node_exporter`
`categorize()` sends 9100 exclusively to `enum-print.sh` (JetDirect/PJL), but in
modern estates 9100 is overwhelmingly node_exporter (`GET /metrics` — unauth host
inventory). Disambiguate in-dispatcher (PJL `@PJL INFO ID` vs HTTP `GET /metrics`) or
let 9100 also land in an HTTP-capable bucket. Document the softer 9000/9090 multi-maps.
**M.**

### [P2] Top ~10 missing service dispatchers (all curl/nc/nmap/stdlib, detect-and-skip)
NATS (4222 + 8222 `/varz`) · ClickHouse (8123 `/?query=SHOW+DATABASES`) · Git daemon
(9418 `git ls-remote`) + SVN (3690) · X11 (6000-6009 `x11-access`) · TFTP (69/udp
canonical-config grab) · AFP (548 `afp-serverinfo`) · Couchbase (8091 `/pools`) ·
RethinkDB (28015) · Squid/open-proxy (3128 CONNECT test) · legacy trust (Finger 79,
r-services 512-514, TACACS+ 49). **L as a batch; each S.**

### [P2] ADCS web-enrollment (ESC8) + Exchange/ADFS HTTP detectors
`enum-smb.sh` already flags signing-disabled relay candidates + PetitPotam, but the
network side never probes `/certsrv/` (the ESC8 relay *target*), nor OWA/ECP/Autodiscover
(ProxyShell/ProxyLogon) or `/adfs/ls/`. Add marker-gated detectors to the existing
`enum-http.sh` product-detect fan-out, cross-linked to `enum-smb.sh`'s
`_relay_candidates.txt`. **S.**

### [P2] `enum-redis.sh` is the shallowest DB dispatcher
Hardcoded `-p6379` (misses 6380/16379/26379); no TLS path; no open-unauth vs
`NOAUTH` vs ACL classification; no Sentinel (26379); no version→CVE signal (notably
CVE-2022-0543 Debian/Ubuntu Lua sandbox escape). Parse `INFO server` for version+os,
classify reachability, add `--tls` retry, probe Sentinel, switch the `nc` fallback to
`/dev/tcp`. **M.**

### [P3] Downstream / depth
- **New dispatchers need `report.py` severity rules** or their CRITICAL findings render
  as info (ROADMAP-002 tail step). Add a first-match tuple per new hit string + extend
  `test_nmap_parse.py` fixtures. **S.**
- **`enum-smtp.sh`** open-relay probe uses one canonical form — add null-sender /
  source-route variants (the `standalones/smtp/` toolkit already has the logic). **S.**
- **`enum-nfs.sh`** relies on `showmount`/rpcbind → returns nothing on NFSv4-only
  servers; emit an "NFSv4-only — try `mount -t nfs4 -o ro`" hint when 111 closed / 2049
  open. **S.**

---

## 3. Linux local-audit standalones (highest-relevance to the bare-Linux constraint)

### [P1] `io-uring-check.sh` violates the no-dependency contract
Lines 29-52 gate the reachability test on `command -v python3` and do the syscall via
`ctypes` — on the bare host this toolkit targets (no python), the check is skipped and
prints "not reachable": a **false negative on exactly the hosts that matter**. Syscall
`425` is also hardcoded (wrong on i386). Re-base the verdict on pure reads: `uname -r`
(io_uring since 5.1), `/proc/sys/kernel/io_uring_disabled`, `/proc/kallsyms`,
`CapEff`. **M.**

### [P1] sudo CVE list stale + patchlevel discarded
`sudo-enum.sh:10-27` (and `linenum-fast.sh:71-80`) cover only 2021-3156 / 2019-14287 /
2023-22809 — missing the mid-2025 local-root CVEs **CVE-2025-32463** (`--chroot`, fixed
1.9.17p1) and **CVE-2025-32462** (`-h`). The version parse
(`[0-9]+\.[0-9]+\.[0-9]+`) drops the `pN` patchlevel, so `1.8.31p2` (patched) flags as
Baron-Samedit-vulnerable — a false positive. Capture `(pN)?` and compare with
`sort -V`; add the 2025 ranges. **S.**

### [P1] `linenum-fast.sh` kernel-hint `case` is dead for modern kernels
`linenum-fast.sh:38-43` buckets `5.[0-9].*` and `4.1[0-3].*` — **no arm for 5.10,
5.15, or any 6.x**, i.e. the majority of 2026 hosts get zero kernel-exploit hint.
Extend the `case` to modern LTS/stable (DirtyPipe, nf_tables/CVE-2024-1086, OverlayFS,
io_uring). **S.**

### [P1] New detection class: kernel/proc hardening (sysctl) + LSM posture
Nothing reads `yama/ptrace_scope`, `dmesg_restrict`, `kptr_restrict`,
`perf_event_paranoid`, `unprivileged_bpf_disabled`, `kexec_load_disabled`,
`fs.protected_*`, `suid_dumpable`, `randomize_va_space`, nor LSM state
(`getenforce`/`/sys/kernel/security/lsm`/`/proc/self/attr/current`) or `/proc`
`hidepid`. An entire CIS/Lynis class is uncovered and these are LPE preconditions. New
`proc-hardening-check.sh`, pure `cat` of `/proc` + `/sys`. **M.**

### [P1/P2] Version-only checks false-positive on backport-patched glibc/polkit
`looney-check.sh:21` strips `-0ubuntuX`; `pwnkit-check.sh:31` compares upstream
`0.105`/`0.120` — so fully-patched Ubuntu/Debian/RHEL (fix backported, version
unchanged) flag **CRITICAL**. Compare the full package revision against the distro
fixed revision, or downgrade to "version-in-range — confirm distro patch revision." **M.**

### [P2] Other high-value coverage gaps
- **LD/PATH hygiene** — `writable-files.sh:6` checks `ld.so.preload`/`ld.so.conf` but
  not `/etc/ld.so.conf.d/` (dir + `*.conf`); PATH checks never flag `.`/empty
  elements. **S.**
- **systemd** — writable-unit detection matches only `*.service`; misses drop-in
  `*.d/*.conf`, `.timer`/`.socket`/`.mount`/`.path`, and writable `ExecStart=` targets.
  **M.**
- **Cloud metadata (IMDS)** — no reachability probe of `169.254.169.254`
  (IMDSv1-enabled signal); `curl --max-time 1` or bash `/dev/tcp` fallback,
  reachability-only (no cred material printed). **M.**
- **cron** — writable-script scan omits `cron.{daily,hourly,weekly,monthly}`,
  `at`-jobs, `cron.allow`/`deny`, and wildcard-injection patterns. **S.**
- **`container-detect.sh:63` is dead code** (`grep 'cap_sys_admin' /proc/self/status`
  never matches the hex `CapEff`; `grep '/proc/sysrq' /proc` errors). Delete it; decode
  `CapEff` by masking, print `Seccomp:`/`NoNewPrivs:`, check writable `core_pattern` +
  host-PID-ns. **M.**

### [P3] Signal→verdict + robustness
- `report.py` has no default-tier rules for the `[!!]`/`[+]` markers emitted by
  `container-detect.sh` / `capabilities-enum.sh` / `group-enum.sh` when run individually
  (only the linenum-specific `_BULK_RULES` cover them) → high-value findings render LOW.
  Add rules keyed on their literal banners. **S.**
- NFS export hardening (`no_root_squash`/`no_all_squash`/`insecure`) has a `report.py`
  rule but no script emits a clean marker; add an explicit `/etc/exports` emitter +
  flag NFS/CIFS mounts lacking `nosuid`. **S.**
- Bash-4 constructs (`declare -A`, `mapfile`, process-sub) in `group-enum.sh` /
  `juicy-files-hunt.sh` / `linenum-fast.sh` hard-fail under busybox/dash instead of
  degrading; prefer POSIX or add a `[ -n "$BASH_VERSION" ]` fail-loud guard. **M.**

---

## 4. Service exploitation & credential helpers

### [P1] `default-creds.json` catalog aged out of the 2023-2025 admin-portal targets
Add (pure JSON, no code): Apache Superset (`admin:admin` + CVE-2023-27524), Consul
(8500), Ollama (11434), Portainer, Harbor (`admin:Harbor12345`), Zabbix
(`Admin:zabbix`), etcd, kubelet, Cacti (CVE-2022-46169), Confluence
(CVE-2023-22515/22518). **M.**

### [P1] No Redis 7.x RCE path (the README's own documented dead-end)
Module-load is blocked by default on Redis 7.0+; the README leaves "polyglot RDB+ELF
(TODO)". The Lua/`EVAL` class (e.g. CVE-2024-31449) works against exactly those hosts
with only `redis-cli`. Add a `--rce`-gated `redis-rce-lua.sh` + a "LUA_RCE candidate"
tier in `redis-quickwin.sh` when module-load is blocked but `EVAL` is ACL-permitted.
Gate + lab-verify like the openfire helper. **M.**

### [P1] No Tomcat Manager follow-on for the creds catalog's flagship finding
`default-creds-sweep.py`'s #1 example is Tomcat → WAR-deploy RCE, but no standalone
performs the `/manager/text/deploy` step. Add an `--exploit`-gated,
operator-supplies-the-WAR helper (same "bring your own payload" model as openfire /
jolokia). Bare curl. Consider a Jenkins script-console sibling. **M.**

### [P2] Two broken-but-shipping features
- **`gql.py --directive-bypass` (`gql.py:773-783`)** injects only the `$gqlSkip`
  variable *declaration*, never a single `@skip` directive — the test never runs, and
  a declared-but-unused variable makes spec-compliant servers reject the whole
  document, so passing the flag actively breaks the otherwise-working `diff`. Thread the
  directive onto leaf fields or remove the flag. **M.**
- **`smtp-phish-send.sh:147`** — `grep -qE '…\|…'` uses `\|` under ERE (a literal
  pipe, not alternation), so every successful send is reported as failed. Use
  `grep -qiE '^250 .*(Ok|queued|accepted)'`. **S.**

### [P2] Other
- **`spray-scheduler.py`** — hardcoded 30s per-call timeout (kills real sprays yet still
  records the attempt), captures no output so can't stop on first lockout/success, and a
  docstring example wires `default-creds-sweep.py` with `-u/-p` flags it doesn't accept.
  Make timeout a flag, add optional `--stop-on`, fix the example. **M.**
- **`activemq-cve-2023-46604.py`** fires blind — treat the inbound XML GET (already
  logged) as a PROGRESSED verdict and offer an opt-in `--callback host:port` evidence
  channel (stdlib `socketserver`). **M.**

### [P3] Robustness / quality
- `redis-rce-ssh.sh:123` checks `CONFIG SET dir` via `$?`, but `redis-cli` exits 0 on
  `(error) ERR` — grep the reply for `^OK` instead. **S.**
- `default-creds-sweep.py:116` substitutes `{USER}`/`{PASS}` raw into JSON/form bodies —
  URL-encode / `json.dumps`-escape so passwords with `&`/`"`/`\` don't corrupt the
  request. **S.**
- `openfire-cve-2023-32315.py` uses deprecated `datetime.utcnow()`; the ANSI color
  helper is re-implemented under three different names across the Python helpers. **S.**
- `smtp-relay-test.sh:84` / `smtp-user-enum.sh:112` read the RCPT code positionally
  (`sed -n '3p'`), which breaks against multi-line EHLO — track replies per-command. **M.**

---

## 5. Windows local-audit standalones

*(P0 orchestration gap is item 2 in §0.)*

### [P1] report.py rule/producer mismatches on the winenum path
`Get-NamedPipes.ps1` emits `"[+] WRITABLE PIPE: …"` (Hit prepends `[+] `) but the rule
`^WRITABLE PIPE:` (`report.py:657`) is line-anchored and never matches; the SCCM rule
(`report.py:605`) has no producer; and all `_AD_DEPTH_RULES` are appended only on the
`auto-enum.sh` path (`report.py:1048`), never in the winenum grader (`report.py:787`).
Fix the anchor, wire/remove the SCCM rule, fold `_AD_DEPTH_RULES` into `win_rules`, and
add a producer↔rule drift test. **S.**

### [P1] ADCS coverage stops at ESC1/2/4 with false-positive gaps
`Get-ADCSMisconfig.ps1:88-110` never checks enrollment principal, manager-approval
flag, or published-on-a-CA — flagging DA-only/approval-gated templates as ESC1. One
unreadable template SD throws and kills the whole loop (no per-template try/catch). Add
pure-ADSI ESC6/ESC7/ESC8 (CA-object) + ESC9/10/13/15 (CVE-2024-49019) for 2022-2026
currency; extend the `report.py:629` regex to ESC13/15/16. **M.**

### [P1] CLM + downlevel (PSv2) survivability
`Get-ScheduledTask*` / `Get-SmbServerConfiguration` are PS3+/2012+ and throw on
Win7/2008R2 (which `_BULK_RULES_WIN` treats as live targets); under Constrained
Language Mode arbitrary `.NET`/`New-Object` calls are blocked — i.e. the flagship fails
on exactly the hardened/EOL hosts you most want. Detect `LanguageMode`, capability-gate
each cmdlet, and fall back to native EXEs (`schtasks`/`reg`/`sc`/`whoami`/`net`) that
work under CLM/PSv2. **M.**

### [P1] Missing cheap pure-registry checks (also fixes the orphan SCCM rule)
WSUS-over-HTTP (`WUServer`+`UseWUServer`, critical only when `http://`), UAC/token
(`LocalAccountTokenFilterPolicy=1`, `EnableLUA`, `FilterAdministratorToken`), LSASS
posture (`WDigest\UseLogonCredential`, `RunAsPPL`, `LmCompatibilityLevel`,
Credential-Guard `LsaCfgFlags`), SCCM/MECM (`C:\Windows\CCM`,
`HKLM\SOFTWARE\Microsoft\CCM` → NAA). All one-line `Get-ItemProperty` reads
(CLM-safe via `reg query`). `Invoke-PrivEscEnum.ps1:6` already *claims* WSUS/UAC/autoruns
but the body implements none. **M.**

### [P2] Coverage/currency + posture
- **Coercion** — EFS/DFS/Spooler only; add ShadowCoerce (MS-FSRVP), MS-EVEN6, make
  WebClient/WebDAV a first-class "coercion → relayable to LDAP/HTTP" HIGH signal, add
  MachineAccountQuota (Certifried CVE-2022-26923) and a CVE-2025-33073 reflective-relay
  note. **M.**
- **Credential stores (paths-only)** — add `.aws`/`.azure`/`gcloud`, `.git-credentials`,
  RDCMan `.rdg`, FileZilla, VNC registry, McAfee SiteList, `vaultcmd /list`,
  `repair`/`RegBack` hive backups to `Get-DPAPIBlobs`. **S.**
- **Autorun / COM-hijack** — no writable Run-key / `InprocServer32` phantom-DLL
  enumeration; add `Get-AutorunHijack.ps1` reusing `Test-CanWrite`. **M.**
- **Secret-disclosure inconsistency** — `Get-StoredCreds` prints AutoLogon/WiFi/PuTTY/
  WinSCP secrets in cleartext, contradicting the paths-only posture `Get-DPAPIBlobs`
  documents; redact to `REDACTED(len,sha1)` or add `-ShowSecrets` (keep LAPS/GPP as-is,
  that's the finding). §8 "no Write-Host for data" is violated fleet-wide. **M.**

### [P3]
- `Invoke-PrivEscEnum.ps1:5-8` synopsis over-claims (WSUS/UAC/autoruns not implemented);
  group detection regexes localized `whoami` strings — prefer well-known SID membership.
  **S.**
- `bulk-enum-windows.py` — no TCP preflight on 5985/5986 (can't distinguish port-closed
  from auth-fail); `--use-smb-admin` always returns `rc=126` (documented no-op). Add a
  stdlib `socket` preflight; implement or clearly label the SMB stub. **S.**

---

## 6. Cross-cutting: tests, CI, packaging, data, docs

### [P1] CI tests only Python 3.11 despite a 3.9 floor
The v0.32.0 CHANGELOG documents a same-quote nested f-string that is a **SyntaxError on
3.9–3.11** and "only passed because it ran on 3.13." Add
`strategy.matrix.python-version: ['3.9','3.11','3.13']` (free on GitHub runners); gate
shellcheck/lint to one leg. Highest leverage-to-cost in the audit. **S.**

### [P1] The dispatcher fleet has almost no true-positive tests; `report-dashboard.py` has none
`smoke.sh` proves only syntax/`--help`/empty-target/write-gate; the FP/TP harness proves
detection for only a handful of ~66 dispatchers — ~40 have zero evidence they still
detect their own service. `report-dashboard.py` (91 KB, biggest file) has no unit test
and already regressed once. Add a few stdlib stub servers (redis/mongo/elastic/
memcached/smtp/ftp) + TP assertions, and a `test_report_dashboard.py` asserting
CRITICAL-parity with `report.py`, `data.json` schema, and wiki deep-link resolution.
**M.**

### [P1] `smoke.sh` release-tag gate is stale (asserts only through v0.21.0)
`smoke.sh:842` hardcodes tags to v0.21.0 while the repo is v0.32.0 — the last 11
releases are unverified, and this is the exact gate that should have caught v0.31.0's
"changelogged but never tagged" slip. Derive the expected tag from the CHANGELOG top
block (`git tag | grep -qx "$latest"`) so it's self-maintaining; fix the header. **S.**

### [P2] Framework ergonomics
- **`aranum version` / `selftest` / `deps-check` subcommands + a canonical `VERSION`
  file** — there is no `__version__`/VERSION anywhere, so an operator can't tell what
  checkout they have, and the entrypoint can't verify its environment. **S.**
- **Packaging / offline prep** — no `pyproject.toml`/`requirements*.txt`/`install.sh`.
  Add `requirements-optional.txt` (`defusedxml`, `pywinrm`), a `make install`
  (chmod + symlink to `~/.local/bin/aranum`), and a README quickstart/offline-prep
  block. **S-M.**
- **`deps-check.sh` gaps** — dispatchers invoke `psql`, `mysql`, `swaks`, `lmutil`,
  `amap`, and GNU `parallel` (load-bearing for bulk fan-out) but deps-check surfaces
  none; add them + a `make deps-audit` that diffs dispatcher `command -v` calls against
  deps-check. **S.**
- **`make lint` shellcheck globs drift** — coverage is a hand-maintained per-dir glob
  list while `smoke.sh` syntax uses dynamic `find`; a new `standalones/<svc>/` dir
  escapes shellcheck. Switch to `git ls-files '*.sh'`. **S.**

### [P2] Data provenance / freshness discipline
GTFOBins subset (inline string, prose "as of 2026-05"), `default-creds.json` (`_meta`
has no date/version/source), and other offline datasets have no auditable freshness
signal. Add `updated`+`source` to each dataset's `_meta`, a `docs/DATA-SOURCES.md`, and
a `make data-audit` staleness warning (no live fetching). **S.**

### [P3]
- **Wiki lag** — 34 pages vs ~63 dispatchers; the dashboard deep-links to playbooks that
  don't exist for ~29 services (vault, consul, etcd, solr, neo4j, kafka, …). Extend
  `test_wiki.py` to assert coverage; fill highest-traffic pages first. **M.**
- **`aratool`→`aranum` rename** incomplete in operator-facing strings (`CLAUDE.md` H1/§1,
  `smoke.sh` header); leave functional identifiers (`/tmp/aratool-*`, `aratool-probe`).
  Add `docs/README.md` indexing the 11 dated ADR/REVIEW/ROADMAP docs. **S.**
- **Schema docs / SARIF** — the versioned `findings.json` (`schema_version: 2`) is
  defined only in code; add `docs/SCHEMA.md` + an optional `report.py --sarif`
  (minimal SARIF 2.1.0, stdlib `json`) for CI consumers. **S/M.**

---

## 7. Consolidated priority ranking (whole toolkit)

**Do first — safety / silent-miss (P0-P1):**
1. Remove `FLUSHALL` from `redis-rce-ssh.sh` + fix the README claim *(safety)*.
2. Wire `Invoke-PrivEscEnum.ps1` to the D1.4 standalones **and** fold `_AD_DEPTH_RULES`
   into the winenum grader + fix `^WRITABLE PIPE:` *(the two together restore all
   Windows bulk AD signal)*.
3. `enum-xmpp.sh -> enum-jabber.sh` symlink + make the planner `dispatcher` field
   authoritative.
4. `io-uring-check.sh` → drop python; `linenum-fast.sh` kernel `case` → cover 5.10/5.15/
   6.x; sudo CVEs → add 2025 + honor patchlevel; Looney/PwnKit → backport-aware.
5. Repair the broken-but-shipping features: `gql.py --directive-bypass`,
   `smtp-phish-send.sh` success grep.

**High-value adds (P1-P2):**
6. CI Python matrix (3.9/3.11/3.13); self-maintaining `smoke.sh` tag gate.
7. `enum-ssh.sh` regreSSHion/Terrapin; `enum-mssql.sh` UDP 1434; 9100 print/node_exporter
   collision.
8. UDP amplification cluster (NTP/SSDP/mDNS) + NATS/ClickHouse dispatchers (with
   `report.py` severity rules).
9. `default-creds.json` refresh; Redis 7.x Lua RCE path; Tomcat WAR-deploy helper.
10. New `proc-hardening-check.sh` (sysctl+LSM); Windows WSUS/UAC/LSASS/SCCM registry
    checks + CLM survivability.
11. `report.py` substring pre-gate + skip JSON/XML; malformed `+00:00Z` timestamps;
    `aranum run -report` non-blocking.

**Worthwhile / polish (P2-P3):** queue-state resume; dispatcher TP tests +
`test_report_dashboard.py`; `aranum version`/`selftest`; packaging + deps-check gaps;
data-provenance discipline; wiki coverage; systemd/cron/LD-path depth; ADCS ESC
expansion; container-detect dead-code + capability decode; SARIF/schema docs.

---

## 8. Method notes

- Six Fable-5 reviewers ran in parallel over: (1) network core, (2) dispatcher
  coverage, (3) Linux local-audit, (4) service/cred helpers, (5) Windows local-audit,
  (6) cross-cutting. Each verified claims against source; line numbers are as-read at
  `45c43f6`.
- Every recommendation was checked against the bare-Linux / minimal-dependency
  constraint and the §9 OPSEC invariants. No item requires a new heavy runtime dep; the
  handful that touch state (Redis Lua, Tomcat WAR) stay behind the documented explicit
  gates.
- Anything already tracked in REVIEW-001/002/003 or ROADMAP-001/002/003 was excluded by
  design, so this list is additive to the existing backlog.

---

## 9. Remediation status (as of 2026-07-20)

Remediated on branch `dev/review-004-remediation` (see CHANGELOG `[Unreleased]`), each
change committed granularly with tests where applicable. The full unittest suite
(minus the pre-existing `pywinrm`-absent errors) and `smoke.sh` are green.

**Done — safety / correctness / currency (all P0-P1 defects):**
- redis `FLUSHALL` data-destruction removed + README corrected; redis `CONFIG SET dir`
  detection fixed.
- XMPP routing (symlink) + openfire-admin hint.
- `gql.py --directive-bypass` removed (broken); `smtp-phish-send.sh` success grep fixed.
- `io-uring-check.sh` de-python'd; `linenum-fast.sh` kernel `case` + sudo currency;
  `sudo-enum.sh` 2025 CVEs + `sort -V`; Looney/PwnKit backport-aware (no more false
  CRITICAL); `container-detect.sh` dead code replaced.
- report/merge malformed timestamps; report walker JSON/XML skip; gnmap version field;
  autoenum-diff non-canonical severities; `aranum run -report` non-blocking (+`-serve`).
- Windows verdict plumbing (`WRITABLE PIPE` anchor + `_AD_DEPTH_RULES` on the bulk path)
  + regression tests.
- `default-creds-sweep.py` `{USER}`/`{PASS}` encoding.

**Done — additions / infra (P1-P2):**
- New `enum-nats.sh` + `enum-clickhouse.sh` (fully wired: routing + metadata + rules +
  test); `enum-ssh` regreSSHion/Terrapin; `enum-mssql` UDP 1434 Browser.
- New `proc-hardening-check.sh` (sysctl+LSM+/proc); `default-creds.json` refresh + provenance.
- CI Python matrix + py_compile sweep; self-maintaining `smoke.sh` tag gate; `make lint`
  via `git ls-files`; `deps-check.sh` tool gaps; `aranum version`/`selftest`/`deps-check`
  + `VERSION`; `make install` + `requirements-optional.txt`; `docs/README.md` index.

## 10. Second remediation pass (2026-07-20) — backlog cleared

The §9 "deferred" list and all literal `TODO`/"not implemented" markers were then
completed on the same branch. Full unittest suite (minus the pre-existing
`pywinrm`-absent errors), `py_compile` sweep, `bash -n` over every tracked `.sh`,
and `smoke.sh` are green.

**Literal TODOs eliminated:** redis `--keep`/`--passlist` wiring; activemq
`--max-msgs` (Jolokia `maxCollectionSize`); jabber SCRAM-SHA-256/1 fallback
(RFC-5802-verified); `bulk-enum-windows.py --use-smb-admin` (impacket-wmiexec,
size-guarded); redis README polyglot dead-end; `aratool`→`aranum` rename.

**Windows P0 done:** `Invoke-PrivEscEnum.ps1` now emits WSUS-over-HTTP, UAC
token-filter, LSASS posture, SCCM NAA, MachineAccountQuota/Certifried, LAPS
readability, and WebClient coercion-relay — all graded on the bulk winenum path;
`Get-ADCSMisconfig.ps1` per-template try/catch + ESC1 approval gate + ESC1-16.

**Network done:** UDP cluster (ntp/ssdp/mdns, gated) + 8 TCP dispatchers
(git/finger/squid/tftp/x11/afp/couchbase/rethinkdb) fully wired with wiki pages;
ADCS-ESC8/Exchange/ADFS HTTP detectors; `enum-redis`/`enum-nfs`/`enum-smtp` depth;
report.py combined-alternation prefilter (perf); queue-state writeback + live
`aranum queue` overlay; `--service-parallel`; `--session` surfaced.

**Exploit helpers done:** `redis-rce-lua.sh`; `standalones/tomcat/tomcat-war-deploy.sh`;
activemq PROGRESSED/CONFIRMED verdicts + `--callback`; spray-scheduler
`--timeout`/`--stop-on`; smtp relay variants + robust per-command reply parsing.

**Linux done:** `imds-check.sh`; LD.so.conf.d + systemd drop-ins/timers +
writable-ExecStart + PATH-`.`/relative; cron periods/at/allow-deny/wildcard;
report.py rules for the container-detect/capabilities/group markers; NFS
`no_root_squash` emitter + NFSv4-only detect; bash guards.

**Docs/infra done:** `SCHEMA.md` + `report.py --sarif`; `test_report_dashboard.py`
+ new-dispatcher true-positive tests (which caught a real `crit()`-undefined bug);
all wiki pages (every dispatcher covered, asserted); `DATA-SOURCES.md` +
`make data-audit`; packaging + docs index (in the first pass).

Residual, genuinely out of scope for a Linux-hosted CI: the Windows and WinRM/SMB
**transports** remain CI-unvalidated per ADR-003 — the first real run against a
known-good Windows host is the transport validation.
