# Changelog

All notable changes to **aranum** will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See `CLAUDE.md` §6 for the entry style guide.

## [Unreleased]

Remediation of the REVIEW-004 (20JUL2026) Fable-5 whole-toolkit audit. See
`aranumtoolkit/docs/REVIEW-004-20JUL2026-fable5-toolkit-audit.md`.

### Added
- `aranumtoolkit/network/enum-nats.sh`, `enum-clickhouse.sh` — two new dispatchers for modern cloud-native, unauth-by-default services, fully wired (SERVICE_MAP routing in `nmap-parse.py`, `service-metadata.json` entries, `report.py` severity rules, and a `test_nmap_parse.py` routing test). NATS: 4222 client `INFO` banner + 8222 monitoring `/varz` config exposure + `auth_required=false` anonymous pub/sub (CRITICAL). ClickHouse: 8123 HTTP `/ping` + unauth `SHOW DATABASES` / `system.users` on the default no-password user (CRITICAL). Both read-only (SELECT/SHOW/GET only), curl/stdlib.
- `standalones/linux/proc-hardening-check.sh` — new read-only host-hardening auditor covering an entire previously-uncovered CIS/Lynis class: sysctl knobs (`ptrace_scope`, `dmesg_restrict`, `kptr_restrict`, `perf_event_paranoid`, `unprivileged_bpf_disabled`, `kexec_load_disabled`, `randomize_va_space`, `fs.protected_*`, `suid_dumpable`), LSM/MAC posture (SELinux/AppArmor, `/sys/kernel/security/lsm`, `/proc/self/attr/current`), and `/proc` `hidepid`. Pure `/proc`+`/sys` reads (no dependencies, dash/busybox-safe); each weak setting prints a `HARDENING:` marker graded by `report.py` (`report.py` rules added).
- `VERSION` — canonical single-source version string (`0.32.0`); `smoke.sh` asserts it matches the CHANGELOG top released block.
- `aranum.py`: `version` / `--version` / `-V` (prints the version + `git describe`), `selftest` (runs `smoke.sh`), and `deps-check` (runs `deps-check.sh`) subcommands, so the single entrypoint can report its own version and verify its environment. Version resolves from the `VERSION` file, falling back to the CHANGELOG top block.

### Enhanced
- `aranumtoolkit/network/enum-mssql.sh`: added a UDP 1434 SQL Server Browser probe (stdlib socket) that reveals named/dynamic-port instances a 1433-only TCP scan silently misses, records the instance map, and re-probes each discovered dynamic port with `nmap ms-sql-info`.
- `aranumtoolkit/network/enum-ssh.sh`, `report.py`: added regreSSHion (CVE-2024-6387) and Terrapin (CVE-2023-48795) version signals — the dispatcher previously flagged only CVE-2018-15473. regreSSHion (OpenSSH < 4.4p1 and 8.5p1 ≤ x < 9.8p1) is graded HIGH (pre-auth RCE, ahead of the generic CVE rule) with a distro-backport caveat; Terrapin prefers ssh-audit's verdict when captured and otherwise flags pre-9.6 (no strict-kex) as a candidate.
- `standalones/creds/default-creds.json`: refreshed the catalog for 2023–2025 admin-portal targets — added Apache Superset (`admin:admin` + CVE-2023-27524 default-`SECRET_KEY` note), Harbor (`admin:Harbor12345`), Zabbix (`Admin:zabbix`), and Cacti (`admin:admin` + CVE-2022-46169), each fitting the sweeper's existing basic-auth/form/JSON `post` mechanism. Added `_meta.updated`/`source`/`entry_count` provenance fields (data-freshness discipline).
- `deps-check.sh`: surface external tools the dispatchers actually invoke but that were previously unlisted, so a missing one is reported instead of silently degrading enumeration — `parallel` (recommended; load-bearing for bulk/auto-enum host fan-out), `psql`, `mysql`, `swaks`, `lmutil`, `amap` (optional).
- `standalones/linux/linenum-fast.sh`: the kernel-hint `case` matched no 5.10/5.15/6.x kernel — i.e. the majority of 2026 hosts got zero kernel-exploit signal. Added dot-anchored arms for 5.10–5.15 (DirtyPipe/StackRot), 5.16–6.5 (nf_tables/GameOverlay/io_uring), and 6.6+ (recent LPEs + io_uring sysctl), widened the 4.x arm to all 4.1x LTS, and refreshed the sudo triage to keep the `pN` patchlevel and flag the 2025 CVE-2025-32462/32463 window (1.9.14–1.9.17).
- `standalones/linux/sudo-enum.sh`: added the 2025 sudo local-root CVEs — CVE-2025-32463 (`sudo --chroot`, affected 1.9.14–1.9.17) and CVE-2025-32462 (`sudo --host` rule leak, affected 1.8.8–1.9.17; both fixed 1.9.17p1) — and replaced the brittle glob version matching with `sort -V` range checks that preserve the `pN` patchlevel (the parse previously discarded it). Added a note that these are version-based signals a distro may have patched via backport without bumping the version.

### Fixed
- `standalones/creds/default-creds-sweep.py`: `{USER}`/`{PASS}` were substituted raw into `post` bodies, so a credential containing `&`/`=` (form) or `"`/`\` (JSON) corrupted the request and silently produced a false negative. Now URL-encodes values for form bodies and JSON-escapes them for `application/json` bodies.
- `aranumtoolkit/tests/smoke.sh`: the release-tag gate hardcoded tags through `v0.21.0` while the repo is at `v0.32.0`, so the last 11 releases went unverified — and it therefore missed exactly the `v0.31.0` "changelogged but never tagged" slip it exists to catch. Replaced the static list with a self-maintaining check: derive the latest released version from the `CHANGELOG.md` top block and assert its git tag exists. Fixed the stale `aratool`/`v0.9.0` header comment.
- `aranumtoolkit/network/report.py`: two Windows verdict-plumbing bugs — (1) the `^WRITABLE PIPE:` rule never matched because `Get-NamedPipes.ps1` emits the marker with a `[+] ` prefix (via `Hit()`), so writable-pipe findings were silently ungraded; anchored the pattern to match the marker anywhere. (2) `_AD_DEPTH_RULES` (LAPS/ADCS/PrintNightmare/pipes/coercion) were only wired into the auto-enum classifier, never the bulk `winenum`/`linenum` grader, so a `bulk-windows` sweep produced ungraded (LOW-looking) AD-depth signal — folded them into both bulk rule sets. Added `test_structured_findings.py::TestWindowsBulkGrading` regression tests.
- `standalones/linux/looney-check.sh`, `pwnkit-check.sh`, `aranumtoolkit/network/report.py`: version-only detection flagged fully backport-patched hosts as CRITICAL (e.g. Ubuntu glibc `2.35-0ubuntu3.x` for Looney, polkit `0.105-33ubuntu0.1` for PwnKit — fix backported, upstream version unchanged). Both scripts now show the full distro package revision, emit a HIGH "candidate" verdict with an explicit "confirm the distro patch revision" caveat instead of CRITICAL, and the two `report.py` rules are downgraded to `high` to match (a version-only signal can't confirm exploitability).
- `standalones/linux/container-detect.sh`: removed a dead escape check — `grep 'cap_sys_admin' /proc/self/status` never matched (the file holds a hex `CapEff` mask, not the literal string) and `grep '/proc/sysrq' /proc` errored (grepping a directory without `-r`), so the check emitted nothing. Replaced with real detections: CAP_SYS_ADMIN decoded from the `CapEff` bitmask, `Seccomp`/`NoNewPrivs` state, writable `core_pattern`/`sysrq-trigger`/`notify_on_release`, and a host-PID-namespace (`--pid=host`) heuristic from PID 1's cmdline.
- `standalones/linux/io-uring-check.sh`: the reachability test was gated on `command -v python3` and issued the `io_uring_setup` syscall via `ctypes` — so on the bare minimal hosts this toolkit targets (no python), it silently no-oped and reported "not reachable": a false negative on exactly the hosts that matter. It also hardcoded syscall `425` (x86_64-only). Rewrote the verdict to pure read-only `/proc` + `uname` signals (kernel ≥ 5.1 presence, `io_uring_disabled` sysctl, `CapEff` CAP_SYS_ADMIN bit, `/proc/kallsyms` symbol) — no python, arch-independent, dash/busybox-safe. The `… reachable to current user — known CVE surface` banner is preserved so `report.py` still classifies it.
- `aranumtoolkit/network/nmap-parse.py`: the gnmap parser stored the version banner (`parts[6]`) under `product` and left `version` empty — the gnmap `Ports:` layout is `portid/state/proto/owner/service/rpcinfo/version/`. Mapped it to `version` (XML, the preferred path, was already correct; this only affected gnmap-fed runs' `--with-service` output and product hints).
- `aranumtoolkit/network/autoenum-diff.sh`: the NEW-FINDINGS printer iterated only critical/high/medium/low, so a finding with any other severity (e.g. an operator `--severity-rules` `info` tier) counted toward the exit code but was never printed — a CI wrapper got exit 1 with no visible reason. Now prints canonical tiers first, then any other severity present.
- `aranumtoolkit/network/report.py`, `merge-results.py`: `generated_utc` (and the markdown "_Generated_" line) built the timestamp as `…isoformat() + "Z"`, yielding `…+00:00Z` — two timezone designators, which `datetime.fromisoformat()` rejects on every Python version, breaking any consumer that parses the field. Now emit a valid single-`Z` UTC timestamp via `strftime("%Y-%m-%dT%H:%M:%SZ")`.
- `aranumtoolkit/network/report.py`: the finding walker's "skip JSON/XML" comment described a filter that did not exist — every non-empty file (incl. `default-creds.json`, nxc `--jsonl`, nuclei `-json`, `_meta.json`) was line-scanned, so the broad LOW banner rule and CVE rules fired on JSON keys and double-counted findings against their sibling `.txt`. Added the missing `.json`/`.xml`/`.pem` suffix skip.
- `standalones/smtp/smtp-phish-send.sh`: success detection used `grep -qE '…\|…'`, but under ERE `\|` is a literal pipe, not alternation — so the pattern only matched a response literally containing `250 2.0.0 Ok|^250...`, which never occurs, and every successful send was reported as "Send may have failed." Now uses real alternation, case-insensitive, and drops the hard-coded `2.0.0` enhanced-status so Postfix/Exim/Sendmail variants all match (`^250 .*(ok|queued|accepted)`).
- `aranumtoolkit/network/enum-xmpp.sh` (new symlink → `enum-jabber.sh`): XMPP/Jabber servers were silently skipped on every scan. `nmap-parse.py` routes XMPP ports to category `xmpp`, but `auto-enum.sh` derives the dispatcher as `enum-${svc}.sh` and no `enum-xmpp.sh` existed, so every discovered XMPP host hit the "no dispatcher" fall-through even though `enum-jabber.sh` is name-agnostic and works. Fixed with a symlink mirroring the existing `enum-https.sh → enum-http.sh` convention; documented the divergent-name → symlink invariant in `auto-enum.sh`.
- `aranumtoolkit/network/auto-enum.sh`: the `openfire-admin` category (9090/9091, `manual`) now prints an actionable hint pointing at `standalones/jabber/openfire-cve-2023-32315.py` instead of the generic "no dispatcher" skip.
- `standalones/redis/redis-rce-ssh.sh`: `CONFIG SET dir` failure detection branched on `$?`, but `redis-cli` exits 0 even when the server returns `(error) ERR ...`, so a non-existent/unwritable candidate dir was never detected and produced a confusing later `SAVE failed` instead. Now branches on the reply text (`^OK`), consistent with the `MODULE LOAD`/`SAVE` checks elsewhere in the redis toolkit.

### Changed
- `Makefile`: `make lint` now shellchecks every tracked `.sh` via `git ls-files '*.sh'` instead of a hand-maintained per-directory glob list, so a new `standalones/<svc>/` directory can no longer silently escape linting (the `smoke.sh` syntax gate already used a dynamic find — this keeps the two on the same file set).
- `.github/workflows/ci.yml`: test across a Python matrix (3.9 / 3.11 / 3.13) instead of a single 3.11 interpreter, and added a `py_compile` sweep of every `.py` on each leg. The project claims a 3.9 floor but historically shipped a nested-f-string `SyntaxError` that only passed because CI ran a newer interpreter; the matrix + compile sweep close that gap. lint/smoke (Python-version-agnostic) run once on the 3.11 leg.
- `aranum.py`: `run … -report` now generates the report + dashboard **without** starting the blocking `http.server`, so the documented flow is usable non-interactively (scheduled/CI wrappers no longer hang). It prints the generated `file://…/index.html` path on completion. New `-serve`/`--serve` flag opts back into the auto-served view. (`aranum dashboard` and the standalone dashboard command are unchanged — they still serve by default.)

### Removed
- `standalones/graphql/gql.py`: removed the non-functional `diff --directive-bypass` flag. It injected only the `$gqlSkip: Boolean!` variable *declaration* and never threaded an actual `@skip(if:$gqlSkip)` directive onto any field, so (a) the intended authz-by-AST test never ran and (b) a declared-but-unused variable made any spec-compliant server reject the whole document — i.e. passing the flag actively broke the otherwise-working `diff`. Removed until it can be reimplemented correctly against the string-built document (tracked in REVIEW-004 §4).

### Security
- `standalones/redis/redis-rce-ssh.sh`: removed the per-directory `FLUSHALL ASYNC` from the `--write` path. It permanently wiped the target's entire keyspace (unrecoverable), was undisclosed in the dry-run, and directly contradicted both the subsystem README's "no data loss occurs" claim and CLAUDE.md §1 (no data destruction / OPSEC §9). The flush was not load-bearing — the newline-padded `KEY_BLOB` already keeps the pubkey a valid `authorized_keys` line regardless of preceding RDB bytes. Corrected the `standalones/redis/README.md` OPSEC note that falsely promised no data loss.

## [v0.32.0] — 2026-06-07

Repository restructure into `aranumtoolkit/` + `standalones/`, the unified `aranum.py`
CLI with session-based output, operator planner/queue, iterative second-pass enumeration,
bulk Linux/Windows privesc enumeration, the standalone HTML dashboard with the new
quick-win playbook wiki, and the TESTPLAN-001 security/robustness hardening pass. (Rolls
up all work since v0.31.0, which was changelogged but never tagged — now tagged
retroactively.)

### Added
- `wiki/` — quick-win pentesting playbooks (one concise Markdown page per service: triage one-liners, exploitation quick wins as command + 1-line *why*, gotchas, sources). 34 pages covering redis, memcached, mongo, elastic, couchdb, rabbitmq, cassandra, mysql, postgres, mssql, oracle, smb, ldap, kerberos, rdp, winrm, http, ajp, jmx, docker, kubernetes, ftp, ssh, telnet, smtp, dns, snmp, nfs, rsync, vnc, ipmi, mqtt, plus `linux`/`windows` host privilege-escalation. Each page cross-links the toolkit's own `enum-*.sh` dispatcher and any `standalones/` exploit helper.
- `aranumtoolkit/network/wiki.py` — stdlib Markdown→HTML renderer + page loader for the wiki.
- `aranumtoolkit/network/report-dashboard.py` — renders each wiki page to `wiki_<service>.html`, adds a "Wiki" nav section + index, and deep-links every per-service detail page to its quick-win playbook by service category (so "redis found" → one click to the Redis playbook). Findings' service aliases (e.g. `elastic`→elasticsearch, `linenum`→linux) resolve to the right page.

### Fixed
- `aranumtoolkit/tests/test_phase1_hardening.py`: the `run()` subprocess helper hardcoded `timeout=60`, so the enum-http alive-detection test (which passes `timeout=90`) raised `TypeError: multiple values for keyword 'timeout'` and turned the suite red. `run()` now uses `setdefault` so callers can override the timeout.

### Security
Hardening from the TESTPLAN-001 (07JUN2026) comprehensive functional test campaign.
All findings have a regression test (`aranumtoolkit/tests/test_phase1_hardening.py`,
`test_gql_hardening.py`, `test_creds_hardening.py`).
- `aranumtoolkit/network/merge-results.py`: reject `evidence_path` values that are absolute or contain `..` (and verify resolved containment) so a crafted/untrusted `findings.json` can no longer make merge read or copy a file from outside the source tree into the consolidated output (OPSEC §9).
- `aranumtoolkit/network/report.py`: `walk_findings` now resolves each scan file and skips any that escape the scan tree, so a symlink inside an untrusted scan dir can no longer leak host filesystem content into `findings.json`/dashboard (OPSEC §9).
- `aranumtoolkit/network/bulk-enum-linux.sh`, `bulk-enum-windows.py`: sanitize the per-host output directory name to a single safe path component, so a hostile/malformed targets line (e.g. `../../x`) can no longer `mkdir` outside the output dir (it could previously escape even under `--dry-run`).
- `aranumtoolkit/network/_lib.sh`: arity guard in `parse_common_args` — `--targets`/`--output` with a missing value now returns a clean usage error instead of aborting on the callers' `set -u` (affected all 61 `enum-*.sh` dispatchers).

### Fixed
- `aranumtoolkit/network/enum-http.sh`: gate the alive-URL list (and therefore nuclei/ffuf/product probes) on a real captured HTTP status line. httpx/PD can mark a connectable but non-HTTP port (e.g. ssh) "alive"; pointed at such a port the dispatcher previously launched the full nuclei run (600s budget). It now builds one canonical headers-confirmed alive list and skips web tooling when no URL returned HTTP — a non-HTTP target finishes in ~1s instead of timing out. (Found during the Docker-lab dispatcher phase.)
- `aranumtoolkit/network/nmap-parse.py`: fail loud (exit 2) on structurally-unparseable input (binary/non-XML/empty `.gnmap`/`.nmap`) instead of returning an empty inventory byte-identical to a clean scan; a genuinely empty but anchored scan still exits 0. XXE/DTD pre-scan now covers the whole file (not a 64KB prolog cap that a padded comment could bypass) and the refusal path returns exit 3; `portid` is range-checked (1–65535).
- `aranumtoolkit/network/plan.py`: an out-of-range or empty `--phase` filter now fails loud (exit 5, consistent with `--phase abc`) instead of silently planning zero tasks.
- `aranumtoolkit/network/report.py`: validate custom `--severity-rules` severities (unknown value → exit 2 instead of a later `KeyError` in bulk mode); cap line length before regex match to mitigate catastrophic backtracking from an operator rule; `--redact` now also masks bare (unbracketed) IPv6 and the discovered scan hostnames (validated via `ipaddress`, so MACs/hex strings are preserved).
- `standalones/graphql/gql.py`: `raw` without `--url` and seven unguarded file/JSON reads (`--ua-rotate`, `--arg @json/@file`, `raw --variables/--query-file`, `loop --values-file`, `suggest --corpus`) now exit 2 cleanly instead of an uncaught traceback; invalid `--arg` GraphQL identifiers are rejected; duplicate `--arg` warns; `apq-probe` no longer reports a false verdict (exit 0) against an unreachable host.
- `standalones/creds/default-creds-sweep.py`: `--threads 0` and malformed/missing catalog now exit 2 cleanly; IPv6 targets (`2001:db8::1`, `[::1]:8080`) are parsed correctly instead of silently producing a malformed URL that was swallowed as a no-op.
- `standalones/creds/spray-scheduler.py`: `--dry-run` no longer performs a real lockout `sleep`, preserving the dry-run safety guarantee.
- `aranumtoolkit/network/report.py`: replaced a same-quote nested f-string (finding-id line) that is a `SyntaxError` on Python 3.9–3.11 — the documented support floor. `report.py` (and `report-dashboard.py`, which imports it) failed to load on any interpreter below 3.12; the test suite only passed because it ran on 3.13.
- `aranumtoolkit/network/report-dashboard.py`: `build_index` now appends `report._AD_DEPTH_RULES` like `report.py:main` does, so AD-depth CRITICAL findings (Kerberoast/AS-REP, ESC1, `cpassword`, LAPS-readable, PwnKit, writable-pipe) appear on the dashboard instead of being silently dropped versus `findings.json`.
- `aranumtoolkit/network/nmap-parse.py`: catch `ElementTree.ParseError` on malformed/truncated XML (clean `error:` message + exit 2 instead of a traceback); skip `<port>` elements with a missing/non-numeric `portid` instead of crashing on `int(None)`.
- `aranumtoolkit/network/merge-results.py`, `aranum.py` (`queue`), and `aranumtoolkit/network/report.py` (`_load_rules`): guard `json.loads`/`re.compile` on operator-supplied `findings.json`, `queue.jsonl`, and severity-rule files — fail loud with a clear message (or skip a bad line) instead of stacktracing.
- `aranum.py`: reject session names containing path separators, `..`, or a leading dot so `--session-name` can never create directories outside `outputs/`.
- `aranumtoolkit/network/enum-smtp.sh`: removed a dead `echo "$EHLO_OUT"` reference (variable never assigned) that emitted an `unbound variable` line under `set -u`; STARTTLS detection now reads the EHLO capture file directly.
- `aranumtoolkit/network/_lib.sh`: added `nmap_bound_args()` helper emitting `--host-timeout`, `--script-timeout`, and `--max-retries` (all env-overridable); inserted `$(nmap_bound_args)` into the nmap scan invocations in `enum-ftp.sh`, `enum-smb.sh`, `enum-smtp.sh`, `enum-redis.sh`, `enum-mysql.sh`, `enum-mssql.sh`, `enum-postgres.sh`, `enum-rdp.sh`, `enum-snmp.sh`, `enum-ipmi.sh`, `enum-jmx.sh`, `enum-nfs.sh`, and `enum-kerberos.sh` to prevent unbounded hangs against tarpits and filtered hosts.

### Changed
- `.github/workflows/ci.yml`, `Makefile`, `CHANGELOG.md`, `aranumtoolkit/network/report-dashboard.py`: renamed the remaining user-facing `aratool` strings (CI workflow name, Makefile header, changelog title, generated dashboard brand/footer/title) to `aranum`. Functional internal identifiers (e.g. `/tmp/aratool-*` temp prefixes, the `aratool-probe` RADIUS account) were left unchanged.
- `aranumtoolkit/network/enum-netbios-ns.sh`: genericized the example subnet in the hints text from a real-looking `192.168.1.0/24` to the RFC 5737 documentation range `192.0.2.0/24`.

### Security
- `.gitignore`: ignore `AGENTS.md` / `**/AGENTS.md` so auto-generated agent memory context (which can embed engagement findings and target IPs) is never committed to the public repository.

### Added
- `aranumtoolkit/network/iterative-enum.sh` — second-pass enumeration that emits `/etc/hosts`-ready hostname mappings, HTTP source-code product fingerprints, SMB share spider/mount grep artifacts, low-rate default-credential checks, harvested usernames, and optional SSH stdin-piped filesystem scraping via `standalones/linux/juicy-files-hunt.sh`.
- `standalones/linux/juicy-files-hunt.sh` — read-only filesystem scraper for credential-like content, keyboard walks, service files, config files, cloud/kube profiles, history files, and high-value filenames. Intended for mounted shares or credentialed SSH sessions.
- `aranumtoolkit/network/enum-artifact.sh`, `aranumtoolkit/network/enum-platform.sh`, `aranumtoolkit/network/enum-storage.sh` — read-side dispatchers for artifact/container registries, Kubernetes-adjacent control planes, and storage fabrics/object stores.
- `aranumtoolkit/network/nmap-parse.py` categories `artifact`, `platform`, and `storage`, plus service metadata/planner priorities for those high-value operator pivots.
- `aranumtoolkit/network/plan.py`, `aranumtoolkit/network/service-metadata.json`, `aranumtoolkit/network/engagement-profiles.json` — operator-centric planner that turns nmap output into prioritized `plan.json`, `queue.jsonl`, and `guidance.json` artifacts without changing scan behavior. Metadata covers every `nmap-parse.py` service category and every `aranumtoolkit/network/enum-*.sh` dispatcher.
- `aranum.py` — top-level unified wrapper CLI for planner, auto-enum, iterative pivots, reports, dashboard, merge, queue viewing, and bulk Linux/Windows enum workflows.
- `aranum.py iter` — wrapper for the iterative second-pass workflow.
- `aranum.py dashboard` now wraps `report-dashboard.py` with scan-output auto-detection, a safe sibling output default, and a local report server by default; `aranum.py run <scan-stem> -report` chains enum, report, dashboard generation, and serving.
- `aranumtoolkit/network/merge-results.py` — merge multiple `findings.json` exports into one findings file with deduplication and evidence-path rewriting.
- `aranumtoolkit/network/report-dashboard.py` — new `inbox.html` and `guidance.html` pages plus `data.json` inbox/guidance payloads for operator triage.
- `aranumtoolkit/tests/test_planner.py`, `aranumtoolkit/tests/test_queue.py`, `aranumtoolkit/tests/test_structured_findings.py`, `aranumtoolkit/tests/test_unified_cli.py`, `aranumtoolkit/tests/test_merge_results.py` — coverage for planner metadata, queue sharding, structured finding fields, wrapper CLI, and merged reports.

### Changed
- `aranumtoolkit/network/enum-smb.sh` — adds `nxc smb --rid-brute` username harvesting and aggregates SMB/RPC usernames into `_users.lst` for Kerberos/AS-REP follow-up.
- `aranumtoolkit/network/enum-http.sh` — adds source-code product fingerprints from root HTML/header markers so noisy header-only web product guesses can be corroborated by DOM/asset regex evidence.
- `aranumtoolkit/network/enum-unknown.sh` — unknown-port handling now goes beyond baseline `nmap -sV -sC`: HTTP-like ports get targeted `http-*` NSE follow-up, TLS-like ports get `ssl-*`, and clear SSH/FTP/SMTP/Redis/VNC/RDP banners trigger matching NSE script sets. Defaults exclude `brute`, `dos`, and `external` categories unless the operator overrides the `ENUM_UNKNOWN_*_NSE` expressions.
- `aranumtoolkit/network/enum-http.sh` — expanded product detection for Nexus, Artifactory, Harbor, Docker Registry, Argo CD, Rancher, Portainer, Nomad, MinIO, Ceph/RADOSGW, Rubrik, Cohesity, PowerProtect, TeamCity, GitHub Enterprise, and Azure DevOps. Probes remain marker-gated and read-only.
- `aranumtoolkit/network/enum-backup.sh` — expanded backup coverage to Avamar/PowerProtect legacy ports and Rubrik/Cohesity/PowerProtect API fingerprints.
- `aranumtoolkit/network/auto-enum.sh` — added optional planner integration flags: `--profile`, `--phase`, `--plan-only`, `--queue`, and `--skip-low-priority`. Default execution remains the original service-bucket dispatcher flow when these flags are omitted.
- `aranumtoolkit/network/report.py` — `findings.json` now includes schema-v2 structured fields (`finding_id`, `title`, `confidence`, `priority`, `tags`, `next_actions`, `triage_status`) while preserving existing legacy fields.
- Repository layout — framework code now lives under `aranumtoolkit/`, self-contained helpers live under `standalones/`, and generated engagement output defaults to `outputs/<session>/{raw,inputs,reports}`.
- `README.md` and `USAGE.md` — documented planner/queue workflow, top-level unified CLI, session output layout, planner metadata files, dashboard inbox/guidance pages, and why aranum's HTTP product phase goes beyond `nmap -sC`.

### Enhanced

### Fixed
- `aranumtoolkit/network/report.py` and `aranumtoolkit/network/report-dashboard.py` — ignore generated dashboard directories when walking scan output so stale static HTML/CSS/JS is not re-ingested as fake services or hosts.
- `aranumtoolkit/network/enum-sip.sh` — require real SIP response evidence (`SIP/x.y`, supported methods, or user-enum data) before emitting a SIP finding. This removes the FP harness regression where nmap script-name text alone caused every wrong-service scenario to classify as SIP.
- `aranumtoolkit/network/report.py --redact` — redact target identifiers inside `evidence_path` as well as host and finding text; bracketed IPv6 targets are covered in addition to IPv4.
- `aranumtoolkit/network/_lib.sh` + curl-based dispatchers — replace string-split `curl_proxy_arg` callsites with array-based `curl_common_args`, preserving spaces/metacharacters in user-agent and proxy values while keeping shellcheck clean.
- `aranumtoolkit/network/*` nmap callsites — use shared `THROTTLE_NMAP_ARGS` array for throttle timing flags, avoiding unsafe empty-word expansion and shellcheck failures.
- `aranumtoolkit/tests/smoke.sh` — make the clean-tree gate CI-enforced while remaining a local-dev warning.

### Security

### Refactored

### Chore

---

## [v0.31.0] — 2026-05-23

**Codebase-review fix-up release.** Multi-area cleanup driven by `aranumtoolkit/docs/REVIEW-003-23MAY2026-codebase-audit.md`: critical-bug fixes (broken `deps-check.sh` + smoke harness, dispatcher race conditions, dead CLI flags), §9 hardening (OT/ICS confirmation gate closes the pipe-bypass), §8 sweeps (PowerShell `[CmdletBinding()]`, `Get-WmiObject` → `Get-CimInstance` for PS Core compat), build-system tightening (Makefile lint coverage now spans the privesc-enum dirs), and test-coverage expansion (39-dispatcher contract + gql.py CLI smoke).

No CLI-breaking changes. MINOR per CLAUDE.md §5: new tests, new robustness checks, new PS-Core compatibility surface, new doc cross-links.

### Added
- `LICENSE` — Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0), adopted from the `purplesploit` license text with project name rebranded to *Aranum*. Non-commercial use only; commercial use requires explicit maintainer permission.
- `aranumtoolkit/tests/test_dispatcher_contract.py` — fixture-based unit tests that exercise the entire `aranumtoolkit/network/enum-*.sh` dispatcher fleet (39 scripts) against the `parse_common_args` contract: empty targets → rc=0, `$OUT` created, `_hints.txt` produced for the post-Iteration-B fleet, refusal-with-rc=0 for E4 env-gated probes (ike/slp/radius). Also covers four `parse_common_args` rejection paths (unknown flag, missing flags, missing targets file). Catches regressions that the existing 14-dispatcher empty-targets smoke (smoke.sh §10b) would miss.
- `aranumtoolkit/tests/test_gql_cli.py` — CLI subcommand smoke tests for `standalones/graphql/gql.py`. Asserts every advertised subcommand (`introspect`, `ls`, `describe`, `call`, `loop`, `diff`, `raw`, `suggest`, `apq-probe`, `csrf-probe`) responds to `--help` with rc=0, and that `suggest` / `apq-probe` / `csrf-probe` degrade cleanly when the target is unreachable (no Python traceback leaked to stderr; expected marker present in output). Closes the gap noted in REVIEW T4 — `test_gql_internals.py` covered pure helpers but no CLI surface.
- `aranumtoolkit/tests/smoke.sh` §10b.2 — empty-targets smoke pass extended from 14 dispatchers to 39. New section covers Tier-2a (cassandra, consul, kafka, neo4j, solr, vault, zookeeper, influxdb), I-cluster (flexnet, hpc, monitoring, backup, ipp, print), Tier-1 legacy (dns/ftp/snmp/smb/ldap/ssh/...), and the E4 env-gated probes (ike/slp/radius — asserting their refusal rc=0 path). Three categories surfaced: `HINTS_REQUIRED` (must emit `_hints.txt` on empty input), `HINTS_OPTIONAL` (pre-convention or prerequisite-gated), `GATED` (refuse without env var).

### Changed
- `README.md` — header rebranded to `aranum`, license badge added, new upstream repo link (`https://github.com/aradex-io/aranum`), authorization & non-commercial notice added above the layout section.
- `README.md` (network table) — added rows for `enum-activemq.sh`, `enum-https.sh` (documented as a symlink → `enum-http.sh`), and `enum-unknown.sh`, which existed on disk but were absent from the README service table. Updated the Layout section to point operators at the per-subsystem READMEs (`standalones/activemq/README.md`, `standalones/redis/README.md`, `standalones/smtp/README.md`, `standalones/jabber/README.md`, `standalones/ot/README.md`) so the orphan helpers become discoverable from the top-level entry point.
- `aranumtoolkit/network/bulk-enum-windows.py --help` — added an explicit `TRANSPORT-VALIDATION CAVEAT (ADR-003)` epilog that surfaces ADR-003's "WHAT THIS ADR DOES NOT VALIDATE" warning. Previously this caveat lived only in the ADR file; operators running `--help` had no way to know the WinRM transport is unverified pre-engagement.
- `.gitignore` — added explicit patterns for `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx`. Previously only covered by `*.local` (if the operator named them `engagement.pem.local`), so a stray `engagement.pem` could have been staged accidentally.
- `standalones/jabber/openfire-cve-2023-32315.py cleanup` — returns rc=78 (sysexits.h `EX_CONFIG`) instead of rc=1 when hitting the documented scaffold path. rc=1 conflated "tool tried cleanup and the target rejected it" with "this code path is intentionally not implemented yet — use the manual procedure in standalones/jabber/README.md §Manual cleanup". Wrapper scripts can now branch on rc=78 to fall through to the manual procedure without treating it as a hard failure.

### Enhanced
- `standalones/windows/Get-AlwaysInstallElevated.ps1`, `standalones/windows/Get-ScheduledTasks.ps1`, `standalones/windows/Get-ServiceMisconfig.ps1`, `standalones/windows/Get-StoredCreds.ps1`, `standalones/windows/Get-TokenPrivileges.ps1`, `standalones/windows/Get-UnquotedServices.ps1`, `standalones/windows/Get-WritablePathDirs.ps1` — added `[CmdletBinding()] + param()` preamble per CLAUDE.md §8 (Verb-Noun cmdlets, advanced-function form). Bare scripts without `[CmdletBinding()]` fail to load under Constrained Language Mode (`__PSLockdownPolicy=4`) and lose common-parameter support (`-Verbose`, `-ErrorAction`, etc.). All 17 standalones/windows/*.ps1 now compliant.
- `standalones/windows/Get-ServiceMisconfig.ps1`, `standalones/windows/Get-UnquotedServices.ps1`, `standalones/windows/Invoke-PrivEscEnum.ps1` — replaced four `Get-WmiObject win32_service` callsites with `Get-CimInstance Win32_Service`. `Get-WmiObject` is **not available** in PowerShell Core 6+ / 7+, so the affected scripts crashed under any Windows host where the operator dropped a modern `pwsh` runtime, or when invoked via `Invoke-Command` from a `pwsh` initiator. CIM uses WSMan (or DCOM as a fallback) instead of pure DCOM and is the Microsoft-recommended replacement; property names on `Win32_Service` are identical so downstream `.PathName / .Name / .StartMode / .State / .StartName` references all keep working unchanged.

### Fixed
- `deps-check.sh` — defined missing `have()` helper at the top of the script. The Tier-2a / E4 / OT branches at lines 165+ called `have kcat`, `have nbtscan`, `have impacket-rpcdump`, etc., but `have()` is defined in `aranumtoolkit/network/_lib.sh` which the script never sources. Operators following the README's "first run `./deps-check.sh`" guidance saw `have: command not found` errors during the dispatcher-readiness phase. Also tightened `set -u` → `set -uo pipefail` per CLAUDE.md §8.
- `aranumtoolkit/tests/smoke.sh` — derived `REPO` from the script's own location instead of the hardcoded `/home/jay/Documents/cyber/dev/aratool` path that previously broke `make smoke` (and therefore `make test` and the CI `make smoke` step) on every machine except one developer's box. Harness now runs in any checkout location.
- `aranumtoolkit/network/enum-http.sh` — the CLI flags `--no-nuclei`, `--no-ffuf`, `--no-whatweb`, `--probe-only` are now actually honoured. The post-`parse_common_args` parsing loop that was supposed to set the corresponding env knobs was unreachable: `parse_common_args` rejects any flag outside `--targets` / `--output` with `unknown arg: ...` → rc=1, and the caller's `|| exit 1` exited before the loop ran. Only the env-var form (`NO_NUCLEI=1 enum-http.sh ...`) ever worked from the command line. The extension flags are now pre-filtered out of `$@` before `parse_common_args` runs, so both forms work and the dispatcher contract is preserved.
- `standalones/activemq/activemq-cve-2023-46604.py` — `--xml-file` write now uses `with open(...) as fp:` instead of a leaked-file-handle `open(args.xml_file, "w").write(cmd_xml)`. The previous form relied on CPython refcount-driven close timing; on an exception between `open()` and the implicit close, the partial XML would persist with the fd still attached to the process (and on PyPy it might never flush at all).

### Security
- `aranumtoolkit/network/enum-smb.sh` — moved NTLM-relay-candidate awk-staging from the fixed path `/tmp/relay_cand.tmp` to a per-run `mktemp` file. The prior fixed path was symlink-attackable by any local user (steering the awk append target) and raced across concurrent `auto-enum.sh -P` invocations or parallel `enum-smb.sh` runs against split target lists. The output (`$OUT/_relay_candidates.txt`) is unchanged.
- `standalones/ot/_lib.sh::ot_confirm_prompt` (§9 — OT/ICS confirmation hardening) — refuses non-TTY stdin (rc=2) before printing the warning, closing the `echo ICS-CONFIRMED | ot-enum.sh --ics-confirm ...` bypass. The whole point of a typed-confirmation control is "a human deliberately typed this"; piping defeats it. The escape hatch for genuinely-scripted operators (`OT_CONFIRMED=1 ./standalones/ot/enum-modbus.sh --targets ... --output ...` bypassing the orchestrator entirely) is unchanged and documented in ADR-005 D3.

### Refactored
- `aranumtoolkit/network/_lib.sh::parse_common_args` — rewrote the chained `[ -z A ] || [ -z B ] && { ...; }` guards as explicit `if … fi` blocks. The chained form parses correctly today (POSIX shell evaluates `(test||test) && action`) but the precedence is non-obvious; the explicit form makes the validation contract readable at a glance. All four contract paths verified (unknown arg, missing flags, missing file, happy).
- `aranumtoolkit/network/bulk-enum-windows.py` — removed a dead-code `if t.port == default_port and args.tls and t.port == 5986: pass` block in the targets-parsing loop. `default_port` is already set to 5986 when `--tls` is passed (lines 301-302), so the per-target check was a no-op with a misleading comment about "auto-port from --tls". Behaviour is unchanged.
- `standalones/redis/redis-rogue-master.py` — converted the magic `for _ in range(20)` handshake loop to `while cmd_count < MAX_HANDSHAKE_CMDS` (50) with a named constant and an explicit `else` branch that surfaces a hostile/buggy peer streaming non-PSYNC commands. The previous form silently exited rc=0 if 20 commands passed without PSYNC; the new form returns rc=3 with a stderr warning so the operator knows the payload was NOT delivered.

### Chore
- `Makefile lint` — extended shellcheck coverage to `standalones/linux/*.sh`, `standalones/ot/*.sh`, and `standalones/graphql/examples/*.sh`, which were previously not linted at all. Added `-e SC2046` (word-splitting from command substitution) because the dispatcher fleet intentionally relies on the `$(curl_proxy_arg)` / `$(curl_ua)` / `$(throttle_nmap_args)` helpers in `aranumtoolkit/network/_lib.sh` emitting 0-or-2 args via word-splitting; a focused exclusion is preferable to silencing the rule globally elsewhere. The proper array-based refactor of those helpers is tracked separately and planned for v0.32.0.
- Cleaned up five SC2034 unused-var warnings that the expanded lint surfaced:
  - `aranumtoolkit/network/enum-http.sh`: dropped the unused `ks_status` HTTP-status capture in the Keystone detector (the body check is shape-based, not status-based).
  - `aranumtoolkit/network/enum-radius.sh`: BlastRADIUS precondition probe discards stdout to `/dev/null` instead of into the unused `blast_code`; `blast_rc` is the load-bearing value.
  - `aranumtoolkit/tests/fp-harness.sh`: dropped the unused `Y` colour var and the dead `ajp_tp_pass=1` set in the AJP TP block.
  - `standalones/ot/_lib.sh`: marked `OT_THROTTLE_FLOOR_MS`, `OT_MAX_PARALLEL_DEFAULT`, `OT_MAX_PARALLEL_HARD` as `export` so shellcheck recognises the cross-file consumption from `standalones/ot/ot-enum.sh` and the per-proto dispatchers.
- Cleaned up four warnings the new `standalones/linux/*.sh` and `standalones/ot/*.sh` lint surfaced:
  - `standalones/linux/linenum-fast.sh`: added a `*)` default branch to the `getopts` `case` (SC2220), and the Baron-Samedit / CVE-2019-14287 case branch now uses bash's `;;&` fall-through so both warnings can fire on overlapping sudo versions (SC2221/SC2222). Also tightened `set -u` → `set -uo pipefail` per CLAUDE.md §8.

---

## [v0.30.1] — 2026-05-23

**Dashboard UX hardening.** Two operator-requested changes to the per-host workflow — no interface change, no new pages, PATCH per CLAUDE.md §5.

### Changed
- `aranumtoolkit/network/report-dashboard.py` per-host page (`host_<ip>.html`) — every port-row's findings panel now opens by default (`<details open>`). Operators land on the page and immediately see what's there without clicking each row. The evidence-files sub-list stays collapsed (less noise; click to reveal).
- `aranumtoolkit/network/report-dashboard.py` hosts page (`hosts.html`) — adds an **Expand all / Collapse all** toolbar above the table, plus a per-row chevron (▸) that expands just that host's port × service table inline as a hidden detail row beneath. Default state is compact (one row per host); click the chevron for one host, or hit "Expand all" to reveal every host's port detail without leaving the page.
- New column: **Ports** count alongside Findings count on the hosts table.

### Added
- Shared helper `_render_host_port_rows(model, host, details_open)` used by both the per-host page and the hosts-page inline-detail rows. Single source of truth for the port × service block layout.
- CSS for the new toolbar (`.toolbar`, `.btn`), expand chevron (`.expand-btn` + rotation on `.open`), and inline detail row pane (`.hostdetail`, `.hostdetail-pane` with a coloured left border).
- JS for the toolbar buttons and per-row toggle. The sort routine is updated to be pair-aware: when sorting the hosts table, each summary row is bundled with its immediately-following detail row so the two stay adjacent through any column sort. The global search filter also mirrors visibility of detail rows when the parent hostrow is hidden.

### Notes
- The per-host page's `<details>`-open default is purely declarative — every panel renders open. Operators who want a quieter view can click the panel summary to collapse. Browser preference for the `<details>` element does not persist across pages by design (matches operator expectation of a fresh start each navigation).
- The hosts-page expand-all duplicates every host's port × service table into hidden detail rows. For very large engagements (1000+ hosts) this approximately doubles the page size — still well within modern browser limits, but worth knowing.

---

## [v0.30.0] — 2026-05-23

**Port-centric dashboard rework.** Operator feedback: "I need to be able to look through everything quickly — what port a service was found on, what's there, what's open — without going three levels down in pages." This release adds a master inventory page and rebuilds the per-host page around an expandable port × service table.

### Added
- `aranumtoolkit/network/report-dashboard.py` — new master page `inventory.html` (top nav: Hosts → **Inventory** → Services). Wide flat table of every `(host, port, service)` triple in the engagement, with columns: Host · Port · Service · State · Findings count · Top-finding preview. Sortable, filterable via the global search box. Severity-state chip on every row (chip is `PROBED` for ports with no severity-tagged findings, otherwise the max severity colour). One scroll surfaces the entire engagement.
- Per-host page (`host_<ip>.html`) rebuilt — leads with a **Port × Service table**: every probed port on that host shown as one row, with a native `<details>`-element expander that opens an inline pane containing the full findings table + a collapsible list of evidence file paths. No JS, no extra page load — one click reveals everything for that port.
- Dashboard `index.html` — new "Noisiest ports" widget (top-N by finding count) and a "Ports probed / Ports with findings" row in the run summary. Hero subtitle now includes the port total. A `→ open the inventory` CTA links straight from the hero.

### Changed
- `data.json` — new `inventory[]` array with `host`/`port`/`service`/`state`/`n`/`sev`/`page` per entry, and a `n_ports` field under `summary`. Used by the embedded JS quick-jump and by external tooling.
- `aranumtoolkit/docs/examples/dashboard/fixture/` — added `_targets_<svc>.txt` files (`smb`, `http`, `vault`) matching the real `auto-enum.sh` output convention so the inventory has authoritative port data to render.

### Fixed
- `aranumtoolkit/network/report-dashboard.py` — re-attribution of `(dispatcher)`-bucketed findings to real hosts when the finding-line text contains an IPv4 belonging to a known engagement host. Previously, lines like `UNAUTH: Jenkins API exposed: http://10.0.0.20:8080` were attributed to a synthetic `(dispatcher)` host because they appeared in `_dispatcher.log` rather than under `$OUT/<svc>/<ip>/`. The re-attribution pass uses the union of per-host artifact directories and `_targets_*.txt` IPs as the known-host set.

### Port-discovery sources (in resolution order)
1. **`$OUTDIR/_targets_<svc>.txt`** — authoritative; exactly what `auto-enum.sh` dispatched.
2. **Per-host artifact filenames** — regex `_(\d{2,5})(?:_|\.)` matches `seal_https_8200.txt`, `jetdirect_9100_*`, `yarn_8088_info.json`, etc.
3. **Finding-line text** — explicit `host:port` or `://host:port` URLs.
4. **Scheme defaults** — when a line has `https://10.0.0.30/` with no port, it attributes to 443. Maps for `http`/`https`/`ssh`/`ftp`/`rsync`/`ldap`/`ldaps`.
5. **Service defaults** (`DEFAULT_PORTS` table, 55+ services) — last resort so an inventory row isn't blank even when none of the above produced a port.

### Notes
- The two existing dashboard pages from v0.29.0 (`coverage.html`, severity-filtered pages) remain — they're useful for severity-first workflows. The new pages are additions and a per-host rewrite, not a replacement.
- Inventory size scales as `Σ_hosts (ports_per_host)`. At 1000 hosts × 5 ports = 5000 rows the static page is still fluid in modern browsers; no pagination is added (operator feedback can iterate on this).
- Smoke section 10e adds one new check: `inventory.html` carries `data-port=` rows AND `data.json` has the `n_ports` summary field. Total 285 smoke pass.

---

## [v0.29.0] — 2026-05-23

**Standalone multi-page HTML dashboard.** New tool `aranumtoolkit/network/report-dashboard.py` consumes an `auto-enum.sh` `$OUTDIR` (or a `bulk-enum-*` tree) and emits a self-contained directory of HTML pages — no CDN, no build step, no server required. Open `index.html` in any browser, or serve briefly with `python3 -m http.server` for remote sharing.

### Added
- `aranumtoolkit/network/report-dashboard.py` — stdlib-only Python generator. Reuses `aranumtoolkit/network/report.py`'s `walk_findings` / `walk_findings_bulk` and severity rules as the data layer (no duplication). Embeds CSS + JS as module-level templates and writes them out to `assets/dashboard.css` / `assets/dashboard.js` at generation time.
- Generated pages: `index.html` (severity tiles + top hosts + top services + recent findings + run summary), `hosts.html` (sortable/filterable table), `host_<ip>.html` (per-host detail, severity-grouped), `services.html`, `service_<svc>.html`, `severity.html` + `severity_<sev>.html` for each of critical/high/medium/low/info, `timeline.html` (chronological from `run.log`), `coverage.html` (hosts × services dispatch matrix with severity-coloured cells), plus `data.json` for client-side search.
- Embedded CSS — GitHub Primer-inspired dark theme with light-mode toggle (CSS custom properties), severity-coloured chips and tiles (`color-mix` for transparency), responsive grid, sticky navbar + table headers, sortable column indicators, rotated header cells for the coverage matrix.
- Embedded JS — sortable tables (text/numeric/severity-aware), client-side filter on every `.filterable` table via the global search box, theme toggle persisted in `localStorage`, keyboard shortcuts (`/` focuses search, `Esc` clears), and a quick-jump syntax (`>host 10.0.0` / `>svc smb` Enter) backed by `data.json`.
- `aranumtoolkit/tests/smoke.sh` — new section 10e exercises the dashboard generator: verifies all top-level pages + `assets/` + `data.json` are produced, validates `data.json` schema (`generated_at`/`out_dir`/`summary`/`hosts`/`services`), confirms critical findings render on `severity_critical.html`, and asserts the coverage matrix is generated. 4 new smoke checks (total now 284 pass).
- Top-level `README.md` — new "Standalone dashboard (v0.29.0)" section with usage, page index, keyboard shortcuts, and the `--bulk` mode pointer.

**Notes:**
- Stdlib only — no Jinja2, no framework, no bundler. F-string templates with `html.escape()` for safety; deterministic output so smoke tests can byte-compare future renders.
- The `(dispatcher)` pseudo-host that `report.py` synthesises for top-level `_dispatcher.log` findings is rendered as a discrete host row — operators see it labelled "(dispatcher)" with a host page that links to the severity-classified findings whose origin file was outside any per-host subdirectory.
- IPv6 hosts are filename-safe: `safe_name()` replaces `:` and other non-alphanumerics with `-` (so `[2001:db8::5]` becomes `2001-db8--5`). The page title preserves the original literal.
- Default theme is dark; preference persists in `localStorage`. Operators wanting light-by-default can set `data-theme="light"` on `<html>` in `index.html` or just click the toggle.

---

## [v0.28.1] — 2026-05-23

**Second-tier evil-server FP class: shape mimicry.** Closes the v0.22.1-noted gap *"specifically-crafted evil servers could still FP — that requires deeper protocol semantics (e.g. validating the version field format)"*. New `evil-shape` harness scenario + Vault dispatcher third-evidence regex. PATCH per CLAUDE.md §5 (hardening + test infrastructure; no interface change).

### Fixed
- `aranumtoolkit/network/enum-vault.sh` — third-evidence shape-mimicry guard. After the existing `sealed`+`t`+`n` two-evidence check, the dispatcher now extracts the `version` field and, if non-empty, requires it to match `^[0-9]+\.[0-9]+\.[0-9]+([+\-][a-zA-Z0-9.+\-]*)?$` (semver with optional Enterprise suffix — accepts `1.18.3`, `1.18.3+ent`, `1.18.3+ent.hsm.fips1403`, `1.15.4-rc1`). If the field is present but does not match, the candidate is rejected with a `log` line and no `hit` is emitted. Empty version is still accepted (rare early-init state). The two existing FP scenarios (`evil-json`, `evil-banner`, `evil-product-hdrs`) continue to be rejected by the prior gates — the new check is additive.

### Added
- `aranumtoolkit/tests/fp-server.py` — new `evil_shape_handler` on `base+7` (port 19007). Routes `/v1/sys/seal-status` to a Vault-shape JSON payload with the correct `type=shamir` / `sealed=false` / `t=3` / `n=5` / `progress=0` / `initialized=true` AND all the expected metadata keys, but `"version":"NOT_A_REAL_VAULT_VERSION"` (bogus content in a correctly-shaped wrapper). All other paths return 404. The `fp-server.py` listener now binds eight consecutive ports (was seven).
- `aranumtoolkit/tests/fp-harness.sh` — `SCENARIO_NAMES[7]="evil-shape"`, `NUM_SCENARIOS=8`. FP sweep grows from 189 cells (27 × 7) to **216 cells** (27 × 8), all green. The `vault/evil-shape` cell explicitly emits 0 hits, confirming the new third-evidence check fires.

**Notes:**
- YARN and Splunk shape-mimicry hardening is deliberately deferred. Both dispatchers gate on port (`enum-hpc.sh` on 8088, `enum-monitoring.sh` on 8089) so testing them against a non-standard test-stub port would require introducing `HPC_EXTRA_YARN_PORT` / `MONITORING_EXTRA_SPLUNK_PORT` test-seam env vars (see `enum-print.sh` `PRINT_EXTRA_*_PORT` precedent). That work — including the matching `state` closed-enum + `hadoopVersion` semver + Splunk `version`/`build` regex checks — is a clean follow-up but is not gated by an ADR.
- The chosen Vault regex deliberately accepts a wide Enterprise-suffix grammar. False-negative risk against a real Vault: < 1% (HashiCorp has not changed the version-field format since 1.0). A specifically-crafted server that ALSO returns a syntactically valid semver string would still defeat this gate — that's the next tier of mimicry and would require cross-endpoint validation (e.g., follow up with `GET /v1/sys/health` and require both endpoints to return consistent product metadata).

---

## [v0.28.0] — 2026-05-23

**ROADMAP-001 I-I source/CI partial-gap closure.** 4 new product-detect blocks folded into `enum-http.sh` C.13 (blocks 16–19) covering Gerrit and the Atlassian stack — Jenkins was shipped in E3 (`v0.21.0`); these complete the I-I cluster. No new dispatchers; same two-evidence discipline; evil-product-hdrs FP cell preserved at 0 hits.

### Added
- `aranumtoolkit/network/enum-http.sh` block 16 — Gerrit. Probes `/config/server/version`; two-evidence requires the literal XSSI guard prefix `)]}'` (Gerrit's canonical anti-XSSI marker — unique to Gerrit REST endpoints) AND a quoted semver-like version string in the body. Extracts version after stripping the prefix.
- `aranumtoolkit/network/enum-http.sh` block 17 — Atlassian Confluence. Two routes: (a) header `X-Confluence-Request-Time` on `/` AND body contains `Confluence`; OR (b) `/server-info.action` returns `<version>X.Y.Z</version>`. Either path is sufficient; whichever fires first emits.
- `aranumtoolkit/network/enum-http.sh` block 18 — Atlassian Jira. Probes `/rest/api/2/serverInfo`; two-evidence requires ALL THREE of `"baseUrl":` + `"versionNumbers":` + `"deploymentType":` (closed schema unique to Jira). Emits `Source/CI Atlassian Jira detected:` PLUS `UNAUTH: Jira serverInfo exposed:` — this endpoint is unauth-by-design on most Jira installs.
- `aranumtoolkit/network/enum-http.sh` block 19 — Atlassian Bamboo. Probes `/rest/api/latest/info`; two-evidence requires `Bamboo` literal AND (`<version>X.Y.Z</version>` OR `"version":"X.Y.Z"`) AND (`<buildDate>` OR `"buildDate":`). XML / JSON content-negotiation tolerated.
- `aranumtoolkit/network/report.py` severity rules: HIGH on `UNAUTH: Jira serverInfo exposed:` (the canonical Atlassian recon entrypoint); MEDIUM on the 4 `Source/CI X detected:` lines.

**Notes:**
- Confluence and Bamboo have a long history of OGNL-injection RCE chains (CVE-2022-26134, CVE-2023-22515). The MEDIUM detection severity is *deliberate* — fingerprint alone doesn't confirm exploitability, and per ADR-005 D6 we don't ship CVE-lookup feeds. Operators can cross-reference version against vendor advisories.
- Jira's `/rest/api/2/serverInfo` being unauth is the historical default; modern Jira Cloud / hardened Jira Data Center installs may require auth on this path. When unauth, the detection AND the UNAUTH-escalation finding both fire; when auth-gated, neither fires (the JSON shape gate doesn't match a 401 response body).
- Together with the v0.21.0 Jenkins detector (E3), this completes the I-I cluster's high-priority targets. Gerrit's SSH 29418 port surface remains uncovered — separate dispatcher would be needed; deferred as low-yield (Gerrit fingerprint via the HTTP path covers most engagements).

---

## [v0.27.0] — 2026-05-23

**ROADMAP-001 I-E hypervisor partial-gap closure.** 4 new product-detect blocks folded into `enum-http.sh` C.13 (blocks 12–15) covering hypervisor and orchestration consoles that the earlier vCenter detector (E4) did not reach. No new dispatchers; same two-evidence discipline; evil-product-hdrs FP cell preserved at 0 hits.

### Added
- `aranumtoolkit/network/enum-http.sh` block 12 — VMware ESXi host (vs vCenter). Probes `/ui/`; distinguishes from already-shipped vCenter by title containing `VMware Host Client` (vCenter is `vSphere Client`). Detection-only.
- `aranumtoolkit/network/enum-http.sh` block 13 — Proxmox VE. Probes `/api2/json/version`; two-evidence requires HTTP 200 AND JSON envelope `"data":` AND all three of `"release":` + `"version":` + `"repoid":` keys. Emits `Hypervisor Proxmox VE detected:` PLUS `UNAUTH: Proxmox version API exposed:` (the endpoint returning data without an `Authorization` header is itself an unauth signal on newer installs).
- `aranumtoolkit/network/enum-http.sh` block 14 — Nutanix Prism. Probes `/console/` capturing headers with `-D`; two-evidence requires `Set-Cookie: NTNX_IGW_SESSION` header AND body containing `Nutanix` or `Prism`.
- `aranumtoolkit/network/enum-http.sh` block 15 — OpenStack Keystone. Probes `/v3`; two-evidence requires JSON envelope `"version":{` AND `"status":"stable"|"beta"|"deprecated"` AND `"rel":"self"` (the canonical Keystone API-discovery shape). Emits version id from `"id":"v3.x"`.
- `aranumtoolkit/network/report.py` severity rules: HIGH on `UNAUTH: Proxmox version API exposed:` (the unauth `/api2/json/version` is the recon entrypoint); MEDIUM on the four `Hypervisor X detected:` / `OpenStack Keystone detected:` lines (parity with BMC detection severity).

**Notes:**
- Default cred history for Nutanix Prism is `admin/Nutanix/4u` — surface to operator through whatever auth-testing tool they choose (`enum-http.sh` does not spray, by design).
- The ESXi vs vCenter distinction is load-bearing: the `vSphere Client` title means vCenter (orchestrator) and triggers the existing block 9 detector; the `VMware Host Client` title means an individual ESXi hypervisor host (typically managed by vCenter, but reachable on its own when port-scanned at 443). Both detectors can fire on the same target if the operator scans both the vCenter VM and the underlying ESXi hosts.

---

## [v0.26.0] — 2026-05-23

**ROADMAP-001 I-D BMC + I-J VPN closure.** 11 new product-detect probes folded into `enum-http.sh` C.13 covering 5 out-of-band BMC vendors and 6 SSL VPN concentrators. No new dispatcher files; no new safety controls; two-evidence discipline preserved against the v0.22.1 evil-product-hdrs FP cell.

### Added
- `aranumtoolkit/network/enum-http.sh` C.13 — new product detectors:
  - **I-D BMC consoles** (5 vendors):
    - HPE iLO — `Server: HP-iLO-*` header OR body matches `iLO [0-9]+` / `HP Integrated Lights-Out` / `HPE Integrated Lights-Out`.
    - Dell iDRAC — body matches `Integrated Dell Remote Access Controller` OR `"iDRAC"` JSON quotation OR `/restgui/start.html` returns 200.
    - Supermicro IPMI — body matches `ATEN International` / `Supermicro` / `SMC BMC` AND `/cgi/login.cgi` returns 200/302/401.
    - Lenovo XCC / IMM — body matches `Lenovo XClarity Controller` / `XClarity Controller` / `Integrated Management Module II` / `IBM Integrated Management Module`.
    - Cisco CIMC — body matches `Cisco Integrated Management Controller` / `CIMC Login`.
  - **I-J VPN concentrators** (6 vendors):
    - Cisco AnyConnect / ASA SSL VPN — `/+CSCOE+/logon.html` matches `AnyConnect` / `webvpn_logon` / `cisco_logon` / `CSCOE`.
    - Fortinet SSL VPN — `/remote/login` matches `FortiGate` / `Fortinet` / `fgt_lang` / `/sslvpn/` / `tos.cgi` (CVE-2022-42475 / CVE-2023-27997 reachability).
    - Palo Alto GlobalProtect — `/global-protect/login.esp` matches `GlobalProtect Portal` / `globalprotect` / `Palo Alto Networks` (CVE-2024-3400 reachability).
    - Pulse Secure / Ivanti Connect Secure — `/dana-na/auth/url_default/welcome.cgi` matches `Pulse Secure` / `Ivanti Connect Secure` / `dana-na` (CVE-2023-46805 + CVE-2024-21887 reachability).
    - Citrix NetScaler Gateway — `/vpn/index.html` matches `Citrix Gateway` / `NetScaler Gateway` / `NetScaler ADC` / `/logon/LogonPoint/` (CVE-2023-3519 / CVE-2023-4966 era).
    - SonicWall SMA / NetExtender — `/cgi-bin/welcome` matches `SonicWall` / `NetExtender` / `sma1000` / `sma100` (CVE-2024-40766 era).
- `aranumtoolkit/network/report.py` — severity rules:
  - MEDIUM: `BMC HPE iLO|Dell iDRAC|Supermicro IPMI|Lenovo XCC/IMM|Cisco CIMC detected:` (detection alone is engagement-meaningful given default-cred history, no UNAUTH evidence so not HIGH).
  - HIGH: `VPN Cisco AnyConnect/ASA SSL VPN|Fortinet SSL VPN|Palo Alto GlobalProtect|Pulse/Ivanti Connect Secure|Citrix NetScaler Gateway|SonicWall SMA/NetExtender detected:` (each vendor has ≥1 pre-auth CVE in 2023–2024 — fingerprint alone is high-yield).
- `aranumtoolkit/docs/ROADMAP-001-19MAY2026-thoroughness-execution.md` — reconciliation table updated to mark I-D, I-J shipped; Overall-status table gets new rows for v0.25.0 (I-C/I-F/I-G/I-H batch) and v0.26.0 (I-D/I-J). Closure summary at the bottom of iteration I documents remaining residual gaps (I-B / I-E partial / I-I partial) and notes none of them are gated by an ADR.

**Notes:**
- The evil-product-hdrs FP cell still passes 0 hits. Two-evidence discipline holds across all 11 new probes — each requires a vendor-specific body marker or vendor-specific resource-path response, not just header keywords. A keyword-stuffed `Server: HP-iLO` / `Server: Cisco` / `Server: FortiGate` header alone will not trigger any detector.
- VPN-vendor severity is HIGH because the fingerprint alone correlates 1:1 with a pre-auth CVE that has been weaponized in the last 24 months. BMC severity is MEDIUM because the relevant attacks (default creds, ipmiseed) are post-auth or out-of-band and require correlation with the existing IPMI 623/udp dispatcher.

---

## [v0.25.0] — 2026-05-23

**ROADMAP-001 I-C / I-F / I-G / I-H cluster closure.** Four new `aranumtoolkit/network/` dispatchers covering FlexNet license servers, HPC schedulers, monitoring/lab-data services, and backup infrastructure detection. None require new safety controls beyond CLAUDE.md §9 invariants — all are read-side, detection-grade probes.

### Added
- `aranumtoolkit/network/enum-flexnet.sh` (I-C) — FlexNet Publisher / FLEXlm license-server enumeration on 27000–27009. Two-evidence: banner must contain `lmgrd`/`FLEXlm`/`FLEXnet`/`5279`/`License server status` OR start with the legacy 0x2A protocol byte. If `lmutil` is available locally, runs `lmstat -a -c PORT@HOST` and reports feature count + active-user count + first 5 licensed product names. Characteristic of MATLAB/Cadence/Synopsys/Ansys/COMSOL/Mentor hosts.
- `aranumtoolkit/network/enum-hpc.sh` (I-F) — HPC scheduler enumeration:
  - Slurm 6817 / 6818 — nmap banner probe; reachability + role disclosure (slurmctld vs slurmd) only.
  - HTCondor 9618 — TCP connect + banner; matches `DC_*` / `CONDOR` / `shared_port` markers.
  - YARN 8088 — `curl /ws/v1/cluster/info`; two-evidence requires `"clusterInfo"` JSON key AND one of `hadoopVersion` / `resourceManagerVersion` / `state` / `startedOn`. On UNAUTH detect, also pulls `/ws/v1/cluster/apps?limit=20` for app inventory.
- `aranumtoolkit/network/enum-monitoring.sh` (I-G) — Zabbix + NRPE + Splunk:
  - Zabbix agent 10050 — stdlib-python framed ZBXD request for `agent.ping`/`agent.version`/`system.uname`/`agent.hostname`; two-evidence requires ZBXD framing AND at least one non-`ZBX_NOTSUPPORTED` value.
  - Zabbix server 10051 — nmap `zabbix-info` NSE if available.
  - Nagios NRPE 5666 — stdlib-python v2 `_NRPE_CHECK` probe with proper CRC32; two-evidence requires `rc=0` AND printable response matching `CHECK_NRPE` / `NRPE v…` / `Command not allowed` / `Could not read`.
  - Splunk mgmt API 8089 — `curl /services/info`; two-evidence requires Atom-feed XML envelope AND at least one of `version` / `build` / `licenseSignature` / `serverName` `<s:key>` element.
- `aranumtoolkit/network/enum-backup.sh` (I-H) — Backup-infrastructure detection (DETECT-ONLY at this tier):
  - Veeam B&R REST 9392 — `curl /api/v1/serverInfo`; two-evidence requires either `Server: Veeam` / `X-RestSvcSessionId` header OR `vbrVersion`/`patchLevel`/`serverName`/`name` JSON keys.
  - CommVault 8400 / 81 — `curl /SearchSvc/CVWebService.svc/`; matches `CVWebService`/`CommVault`/`CVSearchSvc`/`Commvault Systems`.
  - Veritas NetBackup 1556 — nmap banner; fingerprint match on `vnetd` / `pbx_exchange` / `bpcd`.
- `aranumtoolkit/network/nmap-parse.py` — 4 new SERVICE_MAP categories: `flexnet`, `hpc`, `monitoring`, `backup`.
- `aranumtoolkit/network/report.py` — severity rules:
  - HIGH: `FlexNet UNAUTH lmstat disclosure:`, `YARN UNAUTH app inventory:`, `YARN ResourceManager UNAUTH:`, `Zabbix agent UNAUTH metric query:`, `Splunk mgmt API UNAUTH:`, `Veeam B&R REST detected:`, `CommVault detected:`, `Veritas NetBackup detected:` (all 3 backup detections are HIGH because the detection itself is engagement-meaningful for a high-value lateral target).
  - MEDIUM: `FlexNet/FLEXlm license server reachable:`, `Zabbix server reachable:`, `Nagios NRPE reachable:`.
  - LOW: `HTCondor collector reachable:`, `Slurm scheduler reachable:` (banner-only reachability).
- `aranumtoolkit/tests/fp-harness.sh` — FP sweep grows to 27 dispatchers × 7 scenarios = 189 cells, all 0 hits.

**Notes:**
- Backup infrastructure detection emits HIGH severity even without exploit evidence. Rationale: backup servers hold credentials for every system they back up, and reaching them from a normal user VLAN is itself a segmentation finding regardless of patch posture. The `_hints.txt` warns operators to confirm engagement scope explicitly covers the backup tier before any follow-up.
- The NRPE probe sends a properly-CRC-checksummed v2 packet for `_NRPE_CHECK`. Modern hardened deployments compiled without `--enable-easy-args` will reject the probe — that is a feature, not a bug; CRC=0 acceptance is itself a hardening-state signal.
- The Zabbix-agent probe deliberately tests 4 read-side keys (`agent.ping`/`agent.version`/`system.uname`/`agent.hostname`) and requires the agent to answer at least one without `ZBX_NOTSUPPORTED`. This catches both legacy "wildcard accept" agents and modern agents with a permissive key list.

---

## [v0.24.0] — 2026-05-23

**Tier 4 OT/ICS read-side identification (T4 / ROADMAP-003).** New `standalones/ot/` directory with orchestrator + 7 read-side dispatchers covering Modbus, Siemens S7, EtherNet/IP, BACnet, OPC-UA, DNP3, and IEC 60870-5-104. Scope and safety controls land per [`ADR-005`](aranumtoolkit/docs/ADR-005-22MAY2026-ot-ics-safety-scope.md): hard write-side prohibition, double-gated typed confirmation, 500 ms throttle floor, no auto-routing.

### Added
- `standalones/ot/_lib.sh` — OT-specific safety helpers: `ot_require_confirmed` (refuses with rc=2 unless `OT_CONFIRMED=1`), `ot_throttle_sleep` (500 ms non-overridable floor), `ot_confirm_prompt` (typed `ICS-CONFIRMED` gate), `ot_clamp_parallel` (4-host ceiling), `ot_split_target` (`ip:port/proto` form).
- `standalones/ot/ot-enum.sh` — orchestrator. Requires `--ics-confirm` flag AND the typed `ICS-CONFIRMED` prompt. Groups targets by `proto` and dispatches to the matching `standalones/ot/enum-*.sh`. Exports `OT_CONFIRMED=1` only after a successful prompt. No auto-routing from `nmap-parse.py`.
- `standalones/ot/enum-modbus.sh` — Modbus TCP 502 read-side ID via `nmap modbus-discover` with `aggressive=false` (FC 17 / FC 43 read-only). Two-evidence: `mbap|modbus` service fingerprint AND a `Vendor:`/`Product code:`/`MajorMinorRevision:` disclosure line.
- `standalones/ot/enum-s7.sh` — Siemens S7comm 102 via `nmap s7-info` (SZL ID 0x11/0x1c). Two-evidence: `s7-info` NSE output AND a SZL-derived field (Module/Basic Firmware/Plant Identification/etc.).
- `standalones/ot/enum-enip.sh` — EtherNet/IP 44818 (TCP+UDP) via `nmap enip-info` (List Identity 0x0063). Two-evidence: `enip-info` NSE output AND a Vendor/Product Name/Serial Number field.
- `standalones/ot/enum-bacnet.sh` — BACnet/IP 47808/udp via `nmap bacnet-info` (Who-Is broadcast). Two-evidence: `bacnet-info` NSE output AND a Vendor Name/Model/Firmware/Location field.
- `standalones/ot/enum-opcua.sh` — OPC-UA 4840 via `nmap opcua-info` (GetEndpoints, no session). Two-evidence: `opcua-info` NSE output AND an EndpointUrl/ProductUri/SecurityPolicyUri field. `None`-policy advertisement emitted as a separate LOW-severity finding always accompanied by the full policy list.
- `standalones/ot/enum-dnp3.sh` — DNP3 20000 via `nmap dnp3-info` (link-status, function 9). Two-evidence: `dnp3-info` NSE output AND a Source/Destination/Master/Outstation field.
- `standalones/ot/enum-iec104.sh` — IEC 60870-5-104 2404 via stdlib socket (TESTFR (act) APDU, exactly 6 bytes outbound, 3 s timeout). Two-evidence: `rc=0` AND response starts with `0x68 0x04` (start byte + APCI length). `680483xxxxxx` is parsed as TESTFR confirmation; `6804xxxx...` framing-present.
- `aranumtoolkit/network/nmap-parse.py` — `ot-untouched` sentinel category routes ports 502/102/44818/47808/4840/20000/2404 for surface-area inventory. **There is no corresponding `enum-ot-untouched.sh`** — the routing is intentionally a dead end.
- `aranumtoolkit/network/auto-enum.sh` — special-case for `ot-untouched`: prints a hint pointing to ADR-005 + ROADMAP-003 + `standalones/ot/ot-enum.sh --ics-confirm` and counts the targets in the run log, then returns without probing.
- `aranumtoolkit/network/report.py` — LOW severity rules for `OT-ID …` lines and for the OPC-UA `None`-policy advertisement (per ADR-005 D6: situational awareness, no CVE-lookup).
- `aranumtoolkit/tests/fp-harness.sh` — 7 new OT env-gate cells verifying each `standalones/ot/enum-*.sh` refuses without `OT_CONFIRMED=1` (rc=2, 0 hits, refusal message present). ENV-GATE TEST block now runs 10 dispatchers (3 aggressive + 7 OT).
- `deps-check.sh` — T4 OT/ICS section reasserts `nmap` (NSE scripts) and `python3` (stdlib socket) as required; emits a runtime note pointing to ADR-005 and the `ot-enum.sh --ics-confirm` entrypoint.
- `standalones/ot/README.md` — opens with the ADR-005 safety section verbatim; dispatcher index; "if any of the above is unclear, do not run these tools" close.
- Top-level `README.md` — adds `standalones/ot/` row to layout tree; new "Tier 4 — OT/ICS read-side identification" subsection in the dispatcher table.

**Notes:**
- All 7 OT dispatchers are nmap-NSE-driven except `enum-iec104.sh`, which uses an inline python3 stdlib-socket probe because nmap has no first-party IEC-104 NSE script. The probe is exactly 6 bytes outbound — no protocol state is left on the device beyond a single TESTFR exchange.
- The `ot-untouched` sentinel category in `nmap-parse.py` is the load-bearing mechanism that keeps `auto-enum.sh` from ever invoking an OT dispatcher. Removing it (or adding a fallback `enum-ot-untouched.sh`) would break ADR-005 D1.
- Per ADR-005 D6, no CRITICAL or HIGH severity rules ship for OT findings. Future iterations may add MEDIUM for combined evidence (BACnet device with no security advertised AND firmware-rev disclosed); CVE-lookup feeds remain explicitly out of scope.
- The throttle floor (`OT_THROTTLE_FLOOR_MS=500`) ignores `ENUM_THROTTLE=aggressive`. This is intentional and load-bearing per ADR-005 D4.

---

## [v0.23.0] — 2026-05-22

**Network print services (ROADMAP-001 I-K).** New `enum-print.sh` dispatcher covers HP JetDirect / PJL (9100) and LPD (515) — the print-server gap from ROADMAP-001 iteration I that ROADMAP-002 did not reach. Two-evidence-guarded against the v0.22.1 evil-banner / evil-json / evil-product-hdrs scenarios.

### Added
- `aranumtoolkit/network/enum-print.sh` — JetDirect/PJL (9100): UEL-framed `@PJL INFO ID / PRODINFO / STATUS` probe with two-evidence guard requiring both the UEL framing bytes (`\x1b%-12345X`) AND a recognized `@PJL INFO …` block; LPD (515): RFC 1179 short-form queue probe (`\x04lp\n`) requiring a non-empty response AND one of the canonical Rank/Owner/Job column headers or the standard LPD error strings.
- `aranumtoolkit/network/nmap-parse.py` — `print` category routes ports 9100 and 515 with regex matching `^(jetdirect|hp-pdl-datastr|printer|lpd|spooler)`.
- `aranumtoolkit/network/report.py` — HIGH severity for `JetDirect / PJL UNAUTH:` (PJL filesystem dump and stored-job-name credential leak are established follow-ups); MEDIUM for `LPD reachable:` (default probe does not retrieve job content).
- `aranumtoolkit/tests/tp-server.py` — JetDirect stub on `base+15` (19025) with UEL-framed PJL response; LPD stub on `base+16` (19026) with RFC 1179 short-form queue dump.
- `aranumtoolkit/tests/fp-harness.sh` — JetDirect + LPD TP cells using `PRINT_EXTRA_JETDIRECT_PORT` / `PRINT_EXTRA_LPD_PORT` env-var test seams to point the dispatcher at non-privileged stub ports without changing production port lists.

**Notes:**
- The dispatcher uses production defaults `JETDIRECT_PORTS=(9100)` and `LPD_PORTS=(515)`. The two `PRINT_EXTRA_*_PORT` env vars are an additive test seam used only by `fp-harness.sh` — operators do not normally set them.
- PJL filesystem dump (`@PJL FSDIRLIST`) and PRET-based deeper exploitation are out of scope for the default probe — they live in `_hints.txt` as operator follow-ups.

---

## [v0.22.1] — 2026-05-22

**Cross-service FP harness expansion + Vault two-evidence fix.** No new dispatchers, no interface changes — PATCH per CLAUDE.md §5. The FP harness gained three "evil-server" scenarios (keyword-stuffed JSON, keyword-stuffed banner, vendor-header-stuffed HTTP/404) that close the v0.20.1-noted gap "specifically-crafted evil servers could still trigger FPs". The expansion caught one real FP in `enum-vault.sh`.

### Fixed
- `aranumtoolkit/network/enum-vault.sh` — seal-status detection required only the literal string `"sealed"` in the response body. A keyword-stuffed JSON server (misconfigured honeypot, debug endpoint, evil-json fp-server flavor) was sufficient to FP. Tightened to require all three of `"sealed":`, `"t":<digit>`, and `"n":<digit>` (Shamir threshold/shares — unique to Vault's seal-status payload). Also gated the `/v1/sys/init` claim-init finding on the seal-status confirmation.

### Added
- `aranumtoolkit/tests/fp-server.py` — three new flavors on ports `base+4` / `+5` / `+6`:
  - `evil-json` — HTTP/200 with a JSON body name-dropping every dispatcher's keywords (sealed / neo4j_version / consul / vault / cassandra / influxdb / solr / jenkins / grafana / vmware-vcenter / oracle-tns / ipmi / ...).
  - `evil-banner` — plain TCP banner with literal protocol words (ajp13 / Telnet / rsync / cassandra / ...) but no protocol behavior.
  - `evil-product-hdrs` — HTTP/404 with `Server: Jenkins`, `X-Powered-By: Solr`, `X-Grafana-Version`, `Set-Cookie: vault_token` headers; canonical product paths return 404.
- `aranumtoolkit/tests/fp-harness.sh` — FP sweep extended from 22 × 4 = 88 cells to 22 × 7 = 154 cells; new dedicated HTTP product-detect FP cell runs `enum-http.sh` against `evil-product-hdrs` and asserts zero `detected`/`UNAUTH:` hits (covers the dispatcher that the per-port sweep cannot cover due to different target shape).

**Notes:**
- The two-evidence anchor for Vault (`"t":` AND `"n":` keys) holds for every Vault seal type — shamir / awskms / gcpckms / azurekv / transit / ocikms / alicloudkms / seal / recovery. Verified against Vault source-code constants for the seal-status response shape.
- A specifically-crafted server that mimics a real Vault seal-status response (including Shamir `t`/`n` integers) could still FP — that requires deeper protocol semantics (e.g. validating the version field format against `^\d+\.\d+\.\d+`). Future harness expansion candidate. The current expansion stops at the "embedded keyword" class.

---

## [v0.22.0] — 2026-05-22

**Opt-in aggressive UDP probes + VMware vCenter detector (E4).** Three new dispatchers (IKE, SLP, RADIUS) covering UDP service-discovery surface with significant operational risk; disabled by default and double-gated (auto-enum flag + env var). Plus a vCenter detector folded into `enum-http.sh` C.13.

### Added
- `aranumtoolkit/network/enum-ike.sh` — IKE/IPsec UDP 500 main-mode probe; aggressive-mode hash harvest doubly-gated on `ENUM_IKE_AGGRESSIVE_MODE=1`.
- `aranumtoolkit/network/enum-slp.sh` — SLP UDP 427 discovery via nmap NSE; CVE-2023-29552 amplification flag.
- `aranumtoolkit/network/enum-radius.sh` — RADIUS UDP 1812/1813 reachability + BlastRADIUS (CVE-2024-3596) Message-Authenticator-enforcement precondition check.
- `aranumtoolkit/network/enum-http.sh` — VMware vCenter SDK (`/sdk/vimServiceVersions.xml`) + UI (`/ui/`) detection in C.13 product-detect block (9th product family).
- `aranumtoolkit/network/auto-enum.sh` — `--ike`, `--slp`, `--radius`, `--aggressive` flags. Aggressive services are stripped from the auto-derived service list unless explicitly opted in; opt-in also sets `ENUM_RUN_X=1` env vars so dispatchers double-gate against accidental manual invocation.
- `aranumtoolkit/network/nmap-parse.py` — SERVICE_MAP routes 3 new aggressive categories (`ike`, `slp`, `radius`).
- `aranumtoolkit/network/report.py` — 11 severity rules for E4 hit patterns (CRITICAL: PSK hash harvest, SLP amplification, RADIUS bogus-accept; HIGH: BlastRADIUS precondition, vCenter SDK; MEDIUM: SLP registry, vCenter UI; LOW: RADIUS reachable, IKE endpoint, IKE vendor).
- `aranumtoolkit/tests/tp-server.py` — vCenter SDK/UI TP stub on port 19024 (base+14).
- `aranumtoolkit/tests/fp-harness.sh` — FP sweep expanded to 22 dispatchers × 4 scenarios = 88 cells; new ENV-GATE TEST block verifies the 3 aggressive dispatchers refuse to run without their env var (0/3 expected failures); TP block adds vCenter (7 total TP checks).
- `deps-check.sh` — E4 OPT-IN AGGRESSIVE PROBES section checks `ike-scan` (required for `--ike`), `nmap` (confirmed for SLP NSE), `python3` (confirmed for RADIUS stdlib probe).

**Notes:**
- E4 dispatchers are AGGRESSIVE: IKE aggressive-mode is a known historical PSK-hash leak; SLP is a CVE-2023-29552 amplification surface (do not fire indiscriminately); RADIUS probes may interact with NAS lockout policies. The double-gate (auto-enum flag + ENUM_RUN_X env var) is intentional and load-bearing — do not weaken without operator request.
- `slptool` direct-target mode is unreliable across distros; the SLP dispatcher uses nmap NSE (`slp-discovery,slp-info`) instead.
- BlastRADIUS detection here is the precondition only (Message-Authenticator enforcement check). Full exploit requires nonce-grinding + on-path position.

---

## [v0.21.0] — 2026-05-22

**HTTP product detectors (E3).** `enum-http.sh` now fingerprints 8 common product families on live HTTP targets, emitting product+version findings only when product-specific markers are present.

### Added
- `aranumtoolkit/network/enum-http.sh` — C.13 product-fingerprint phase covering Tomcat Manager, Jenkins (including Groovy script console RCE check), GitLab, SonarQube, Grafana, Prometheus, Hadoop NameNode, Spark UI. Skippable via `NO_PRODUCT_DETECT=1`.
- `aranumtoolkit/network/report.py` — 12 severity rules for the product-detect hit patterns (CRITICAL for Tomcat-Manager-UNAUTH and Jenkins-Groovy-script-console; HIGH for the rest; MEDIUM for Spark).
- `aranumtoolkit/tests/tp-server.py` — Jenkins / Grafana / Prometheus TP stub servers on 19020-19022.
- `aranumtoolkit/tests/fp-harness.sh` — TP block exercises the three product-detect stubs end-to-end.

**Notes:**
- `enum-http.sh` is intentionally NOT added to the dispatcher FP sweep — it depends on optional external tools (httpx, whatweb, nuclei, ffuf, nikto) and its target shape differs (alive-URLs not raw ip:port). Per-product TP stubs cover the product-detect logic specifically.
- The product detectors carry forward v0.20.1's "two-evidence" discipline: every detector requires a product-specific marker (header pattern OR JSON-key combination OR exact body string), never just "HTTP 200 on the canonical path".

---

## [v0.20.2] — 2026-05-22

**CHANGELOG hygiene + AJP behavioral note.** No code changes — pure documentation cleanup.

### Changed
- `CHANGELOG.md` v0.20.1 — folded the non-standard `Known gaps` section into a `Notes:` paragraph under `Fixed`, per Keep a Changelog 1.1.0.
- `CHANGELOG.md` v0.20.1 — documented the AJP two-evidence guard's false-negative tail under tight timing.

---

## [v0.20.1] — 2026-05-22

**Dispatcher FP fixes + in-tree regression harness.** Three confirmed false-positive bugs in network dispatchers corrected; in-tree FP/TP harness added so this class of regression cannot reappear silently.

### Fixed
- `aranumtoolkit/network/enum-ajp.sh` — required two-evidence service fingerprint (nmap `ajp13` fingerprint line AND at least one `| ajp-*:` script-result line) before emitting AJP findings. Previously, `grep -qi 'AJP'` matched nmap's own NSE preamble ("NSE: Loading scripts: ajp-headers, …"), causing a false `UNAUTH:` hit on any open port.
- `aranumtoolkit/network/enum-telnet.sh` — required nmap telnet fingerprint OR IAC option-negotiation byte (0xFF 0xFB–0xFE) in the banner before emitting "Telnet open". Previously emitted a hit unconditionally after `nc` connected, regardless of protocol.
- `aranumtoolkit/network/enum-rsync.sh` — gated module parsing on `rsync` exit code 0 instead of regex-filtering error lines. Previously the regex `^(@|rsync:)` skipped `@RSYNCD:` and `rsync:` error lines but not `rsync error: …` lines (no colon immediately after "rsync"), so the token "rsync" was parsed as a module name.

### Added
- `aranumtoolkit/tests/fp-harness.sh` — in-tree regression harness: runs all 19 dispatchers × 4 wrong-service scenarios (HTTP-200, SSH-banner, accept-silent, TCP-echo) and 3 TP markers (rsync stub, telnet IAC stub, AJP fixture). Returns rc=0 iff 0 FPs and 0 TP regressions.
- `aranumtoolkit/tests/fp-server.py` — multi-flavor wrong-protocol server (HTTP-200, SSH-banner, accept-silent, TCP-echo); `--port-base` flag for collision avoidance.
- `aranumtoolkit/tests/tp-server.py` — true-positive stub servers: rsync daemon with full handshake + module list, telnet IAC option-negotiation; `--port-base` flag.
- `aranumtoolkit/tests/fixtures/ajp-real-nmap.txt` — canonical `nmap --script ajp-headers` output fixture used by the AJP TP check in `fp-harness.sh`.
- `aranumtoolkit/tests/smoke.sh` — section 13 runs `fp-harness.sh` as part of the smoke suite.

**Notes:**
- The AJP two-evidence guard is conservative — a real AJP service whose `ajp-*` nmap scripts time out (aggressive `--throttle` mode, lossy network, very busy backend) will be silently skipped. If AJP findings disappear after upgrade against a target you previously saw on v0.20.0, re-run with `--script-timeout 60` or higher.
- The FP harness scenarios use plain HTTP / SSH / echo / silent servers — cross-service false positives (e.g. an HTTP server returning JSON containing both "sealed" and "neo4j_version") are out of scope for the harness. The 4 scenarios cover the user-reported "open port, wrong service" class; specifically-crafted evil servers could still trigger FPs. Future expansion candidate.

---

## [v0.20.0] — 2026-05-22

**Iteration E2** of ROADMAP-002 — Tier 2a network enumeration dispatchers. Covers 11 SERVICE_MAP categories: high-yield infrastructure and data-store services.

### Added
- `aranumtoolkit/network/enum-ipp.sh` — IPP / CUPS (631) — printer enum + CVE-2024-47176 version hint.
- `aranumtoolkit/network/enum-zookeeper.sh` — Zookeeper (2181/2182) — 4LW enumeration.
- `aranumtoolkit/network/enum-cassandra.sh` — Cassandra (9042/9160) — cluster info, anonymous CQL.
- `aranumtoolkit/network/enum-kafka.sh` — Kafka (9092/9093) — anonymous broker metadata + topic list.
- `aranumtoolkit/network/enum-neo4j.sh` — Neo4j (7474/7687) — version + opt-in default-cred check (gated on ENUM_NEO4J_DEFAULT_CRED=1).
- `aranumtoolkit/network/enum-influxdb.sh` — InfluxDB (8086/8088) — version, unauth query API.
- `aranumtoolkit/network/enum-solr.sh` — Apache Solr (8983/8984) — cores, version + CVE-2019-17558 / CVE-2023-50386 hints.
- `aranumtoolkit/network/enum-consul.sh` — Consul (8500) — agent self, KV dump.
- `aranumtoolkit/network/enum-vault.sh` — Vault (8200) — seal-status, init-state probe.
- `aranumtoolkit/network/enum-msrpc.sh` — MSRPC endpoint mapper (135) — rpcdump / rpcclient / nmap msrpc-enum.
- `aranumtoolkit/network/enum-netbios-ns.sh` — NetBIOS-NS (137/udp) — name-table dump via nbtscan/nmblookup.
- `aranumtoolkit/network/nmap-parse.py` — SERVICE_MAP routes 11 new tier-2a categories.
- `aranumtoolkit/network/report.py` — severity rules for tier-2a dispatchers.

### Changed
- `deps-check.sh` — checks tier 2a tooling (kafkacat, cqlsh, nbtscan, impacket-rpcdump, etc.).
- `aranumtoolkit/tests/test_nmap_parse.py` — REQUIRED_CATEGORIES extended with the 11 new keys.

---

## [v0.19.0] — 2026-05-22

**Iteration E1** of ROADMAP-002 — Tier 1 network enumeration dispatchers. Covers 8 SERVICE_MAP categories that routed to targets but had no dispatcher scripts.

### Added
- `aranumtoolkit/network/enum-ajp.sh` — AJP / Tomcat (8009) — nmap ajp-headers/methods/auth/brute scripts + Ghostcat CVE-2020-1938 hints in _hints.txt. Flags `UNAUTH:` when ajp-auth output does not include `Authentication: Required`.
- `aranumtoolkit/network/enum-oracle.sh` — Oracle DB (1521/1522/1526) — TNS version, SID brute (oracle-sid-brute NSE), oracle-brute-stealth. Discovered SIDs written to sids_<port>.txt. Optional tnscmd10g version probe.
- `aranumtoolkit/network/enum-pop3.sh` — POP3 (110/995) — CAPA banner grab (nc for plain, openssl s_client for POP3S), plaintext-auth flag (USER present + STLS absent on port 110), optional ENUM_USER/ENUM_PASS probe via nc.
- `aranumtoolkit/network/enum-imap.sh` — IMAP (143/993) — CAPABILITY banner grab, STARTTLS flag (LOGIN present + STARTTLS absent on port 143), optional LOGIN cred probe via nc.
- `aranumtoolkit/network/enum-telnet.sh` — Telnet (23) — nc banner grab + optional nmap telnet-encryption/telnet-ntlm-info/banner. Device-family fingerprint regex (Cisco, HP iLO, Brother, Dell iDRAC, Juniper, Ubiquiti, DD-WRT). Per-family default-cred shortlist in _hints.txt — no auto-attempt performed.
- `aranumtoolkit/network/enum-rsync.sh` — rsync daemon (873) — anonymous module listing via rsync://. Per-module directory listing (up to 10 modules). Flags high-value modules (etc, home, root, backup, var, srv, www) exposed without auth.
- `aranumtoolkit/network/enum-mqtt.sh` — MQTT (1883/8883) — anonymous $SYS/# subscribe via mosquitto_sub (50-message/5-second cap). rc 0 and rc 27 (timeout-after-success) treated as success; rc 5 (auth required) and rc 14 (unreachable) produce no finding. Records broker version from $SYS topic.
- `aranumtoolkit/network/enum-sip.sh` — SIP (5060/5061) — nmap sip-methods/sip-enum-users (UDP + TCP). Vendor fingerprint from Server:/User-Agent: lines (Asterisk, FreePBX, Cisco CUCM, Avaya, Polycom). Optional svmap (SIPVicious) probe.
- `aranumtoolkit/network/report.py` — 8 explicit HIGH severity rules anchored on E1 dispatcher hit strings (AJP unauthenticated, Oracle TNS/SIDs, POP3 plaintext-auth/AUTH SUCCESS, IMAP plaintext-auth/AUTH SUCCESS, Telnet open/device, rsync HIGH-VALUE module, MQTT UNAUTH broker, SIP service). Rules inserted after generic UNAUTH rule to document intent.
- `aranumtoolkit/docs/ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md` — Opus-authored plan mapping E1-E4 iteration scope.

### Changed
- `deps-check.sh` — added E1 TIER-1 DISPATCHERS section: rsync (required), mosquitto_sub (recommended), tnscmd10g (optional), svmap/sipvicious (optional), kafkacat/kcat (optional, reserved for Tier 2a).

---

## [v0.18.0] — 2026-05-20

**Iteration D2** of ROADMAP-001 — Linux CVE checks + creds enhancements. Second half of bundled-D per the option-2 sequencing. Closes REVIEW-001 §2.8 and §2.9.

### Added
- **D2.1 — 6 Linux CVE / privesc-surface check scripts:**
  - `standalones/linux/pwnkit-check.sh` — CVE-2021-4034 (polkit `pkexec` memory-corruption local privesc); flags polkit < 0.120.
  - `standalones/linux/looney-check.sh` — CVE-2023-4911 (glibc `GLIBC_TUNABLES`); flags glibc 2.34-2.38; lists candidate setuid binaries.
  - `standalones/linux/overlayfs-check.sh` — CVE-2023-0386 (overlayfs uid/gid mapping); flags Ubuntu HWE 5.15.0-{60..86} / 6.2.0-{20..32}; checks userns + overlayfs prerequisites.
  - `standalones/linux/io-uring-check.sh` — io_uring availability + restrictions across `/proc/sys/kernel/io_uring_disabled` + empirical `io_uring_setup()` reachability via python ctypes. HIGH on user-reachable surface (multi-CVE history).
  - `standalones/linux/namespaces-check.sh` — unprivileged user-namespace creation (precondition for CVE-2022-0185 / CVE-2023-32233 / etc.). `unshare -rU -- /bin/true` is the empirical test.
  - `standalones/linux/apt-source-check.sh` — apt-get writable config / hooks (`/etc/apt/apt.conf.d`, `sources.list.d`, etc.). Root runs scripts from these dirs on `apt-get install/update` — operator-write to any of them is a privesc path. Debian/Ubuntu only.
  - All 6 no-deps, run as unprivileged user, exit 0 on safe state. `bash -n` + `shellcheck -S warning` clean.
- **D2.2 — `standalones/creds/spray-scheduler.py`:** lockout-policy-aware wrapper around any external spray tool (nxc, kerbrute, default-creds-sweep.py, etc.). Per-principal attempt counting with sliding window: max `--threshold N` attempts per user within `--interval M` minutes (defaults 3/30 mirror common AD default). When threshold hit, sleeps until the oldest recent attempt ages out. Persistent state under `.spray-state.json` for resume after Ctrl-C. `--dry-run` does NOT mutate state (otherwise dry-run would lock out the planned set).
- **D2.2 — `standalones/creds/hash-format.py`:** converts captured authentication hashes from Responder / nxc smb / impacket GetNPUsers / impacket GetUserSPNs output into hashcat- and john-ready files. Detects: NetNTLMv2 (mode 5600), NetNTLMv1 (5500), Kerberos AS-REP (18200), Kerberos TGS-REP RC4 (13100). Writes per-type `hashcat-*.txt` + `john-*.txt` + `_index.tsv`.

### Enhanced
- **D2.3 `aranumtoolkit/network/report.py`:** `_AD_DEPTH_RULES` extended with seven new severity rules anchored on the D2.1 script output strings — CRITICAL on `polkit < 0.120 — PwnKit vulnerable`, `glibc 2.34-2.38 — Looney`, Ubuntu HWE CVE-2023-0386 hits, apt writable config / sources.list; HIGH on io_uring user-reachable surface and `unshare -rU succeeded`.
- **D2.3 README** — Linux Scripts table extended with 6 new rows for D2.1; new "Credential helpers" section listing `default-creds-sweep.py` (pre-existing) + the two D2.2 additions.
- **D2.3 `aranumtoolkit/tests/smoke.sh`** — section 11i (D2.1 syntax + real-data run on this host) + section 11j (D2.2 hash-format synthetic-Responder NTLMv2+ASREP extraction + spray-scheduler 9-attempt dry-run with no spurious lockout sleep).

### Real-data validation (this release)
The 6 D2.1 scripts all ran against this Fedora 6.19 attacker box with the expected verdicts:
- pwnkit-check: polkit 126 → patched (correct: Fedora 42 ships polkit 126)
- looney-check: glibc 2.41 → outside vulnerable window 2.34-2.38 (correct)
- overlayfs-check: kernel 6.19.14-104.fc42.x86_64 → outside Ubuntu HWE ranges (correct: this is Fedora)
- io-uring-check: io_uring reachable → HIGH (verbatim — `/proc/sys/kernel/io_uring_disabled=0`)
- namespaces-check: `unshare -rU` succeeded → HIGH (verbatim — Fedora ships unprivileged userns enabled)
- apt-source-check: apt-get not present → not applicable (correct: not Debian/Ubuntu)

report.py against the stitched output (treating as a bulk-enum host) correctly classified the io_uring + namespaces findings as HIGH. The D2.3 severity rules are anchored on real string outputs from this run, not synthetic guesses.

D2.2 helpers validated against synthetic Responder dump (2 NTLMv2 + 1 AS-REP + 1 TGS-REP correctly extracted; `_index.tsv` tabulates each) and 3×3 spray dry-run (9 [DRY] lines emitted, no lockout sleep triggered after the dry-run-vs-state fix).

## [v0.17.0] — 2026-05-20

**Iteration D1** of ROADMAP-001 — Windows/AD remote depth + Windows local AD scripts. First half of the bundled D (per the option-2 sequencing the operator chose); D2 (Linux CVE checks + creds enhancements) follows as v0.18.0. Per [ADR-004](aranumtoolkit/docs/ADR-004-20MAY2026-ad-depth-tool-deps.md).

### Added
- **D1.0 [ADR-004](aranumtoolkit/docs/ADR-004-20MAY2026-ad-depth-tool-deps.md):** records the seven AD-tool integration decisions — bloodhound-python is the BloodHound ingestor; Certipy for AD CS ESC1-11; graceful skip-when-tool-missing is mandatory (every optional integration checks `command -v` and emits a one-line install hint); never auto-escalate to admin; coerce probes are detection-only with operator-gated next-step hints; raw tool output preserved + report.py rules parse signals; Windows PS1 scripts ship standalone (not folded into Invoke-PrivEscEnum).
- **D1.4 Eight Windows AD-depth PowerShell scripts** under `standalones/windows/`:
  - `Get-LAPSPassword.ps1` — reads `ms-Mcs-AdmPwd` / `msLAPS-Password` / `msLAPS-EncryptedPassword` for every computer object the current user can see. Cleartext readable → CRITICAL; encrypted blob → HIGH (DPAPI extraction needed).
  - `Get-ADCSMisconfig.ps1` — pure-ADSI ESC1 / ESC2 / ESC4 detection. The no-deps Linux-attacker fallback for when Certipy can't reach the target box. Output format mirrors Certipy so `report.py` rules pick up either source uniformly.
  - `Get-GPPCPassword.ps1` — SYSVOL + GP-History sweep for `cpassword=` matches across the six canonical GPP XML files (Groups, Services, ScheduledTasks, DataSources, Printers, Drives). Includes the openssl decryption one-liner since the AES key is public.
  - `Get-DPAPIBlobs.ps1` — enumerates DPAPI master keys, credential vaults, Chrome/Edge/Firefox stores, RDP saved creds, Outlook PST/OST. **Paths only — no decryption attempted** (per CLAUDE.md §9 invariant 1).
  - `Get-NamedPipes.ps1` — ACL audit of every named pipe; flags pipes writable to current user / Everyone / Authenticated Users. Combined with SeImpersonate on the local user, these are impersonation primitives if the server runs as SYSTEM.
  - `Get-PrintNightmare.ps1` — CVE-2021-34527 / CVE-2021-1675 mitigation-state check across Spooler service status + `RestrictDriverInstallationToAdministrators` + `NoWarningNoElevationOnInstall` + `DisableWebPnPDownload`.
  - `Get-PetitPotamSignals.ps1` — NTLM-relay/coercion-signal audit for this host across SMB+LDAP signing, channel binding, and the four coerce-vector services (EFS / DfsR / Dfs / Spooler). Includes the operator-next-step commands for the attacker-box-side `impacket-ntlmrelayx` + `petitpotam.py` / `dfscoerce.py` / `printerbug.py` chains.
  - `Test-CoercedAuth.ps1` — local-only precondition check for PrintSpoofer / RoguePotato / GodPotato chains: SE* token-privilege ENABLED state + Spooler status + DCOM reachability + WebDAV redirector status. Never fires the actual coercion (per REVIEW-001 §2.7 design note).
  - All 8 syntax-validated via `pwsh [Parser]::ParseFile` AST check.
- **D1.6 aranumtoolkit/tests/fixtures/ad-signals/** — six synthetic AD-output fixtures (certipy-esc1, bloodhound-zip, gpp-cpassword, laps-readable, delegation-uncons, pn-exploitable) anchoring the D1.5 severity-rule classifications.
- **D1.6 aranumtoolkit/tests/test_ad_signals.py** — 7 stdlib-`unittest` tests across the per-fixture severity-count assertions plus end-to-end report.py CLI integration against a synthesised auto-enum layout containing the Certipy fixture.
- **D1.6 aranumtoolkit/tests/smoke.sh** sections 11g (AD-signal fixture classifications) and 11h (pwsh AST parse on every standalones/windows/Get-*.ps1 + Test-CoercedAuth.ps1, skipped gracefully when pwsh absent).

### Enhanced
- **D1.1 `aranumtoolkit/network/enum-smb.sh`:** PetitPotam coerce next-step hint (`_petitpotam_hint.txt`) emitted when relay-candidate hosts exist AND `--dc-ip` is set; detects whether `petitpotam.py` is on PATH and adjusts the hint accordingly. Shadow Credentials viability hint (`_shadow_creds_hint.txt`) with pywhisker + certipy follow-up commands when `--user` + `--dc-ip` are present. Neither hint auto-fires; per ADR-004 D5, coerce probes are detection-only.
- **D1.2 `aranumtoolkit/network/enum-ldap.sh`:** four new sections — bloodhound-python full graph collection (Default method, no Session — opt-in via manual re-run); Certipy `find` for AD CS ESC1-11 (text+JSON output, CRITICAL on any ESC* finding); Kerberos delegation enumeration via single ldapsearch query per host (unconstrained / constrained / RBCD; HIGH on non-zero unconstrained count); pre-2000 computer-account candidate listing (workstation-trust-account UAC flag) with a "DO NOT spray without authz" hint file.
- **D1.3 `aranumtoolkit/network/enum-kerberos.sh`:** bulk Kerberoast mode — `GetUserSPNs.py -request -outputfile` pulls every kerberoastable account in one pass (`_kerberoast_hashcat.txt`, hashcat -m 13100); AS-REP roast cross-linked from upstream dispatchers' user output (harvested from nxc rid-brute results + ldap users.txt + legacy `_users.lst`); writes `_asrep_hashcat.txt` (hashcat -m 18200). Both honour `ENUM_THROTTLE` from G.7.
- **D1.5 `aranumtoolkit/network/report.py`:** new `_AD_DEPTH_RULES` layered on top of default + operator rules — CRITICAL on Certipy `ESC[1-11] (Vulnerable)`, `GPP cpassword=` matches, `READABLE (LAPSv1/v2)` hits, kerberoastable / AS-REP-roastable bulk-capture lines, `lsarpc anonymous reachable on DC`, PrintNightmare exploitable config, SeImpersonate + Spooler → PrintSpoofer chain viable. HIGH on `BLOODHOUND_ZIP:` signal, LAPS encrypted-blob, unconstrained / RBCD delegation, PetitPotam coerce chain availability, writable named pipes, SeImpersonate + DCOM → RoguePotato candidate.
- **D1.7 `README.md`:** Windows Scripts table extended with 8 new rows for the D1.4 PS1 files; Dependencies gains an "AD depth (D1)" bullet cross-linking to ADR-004 D3.
- **D1.7 `deps-check.sh`:** new "AD DEPTH (iteration D1 — optional)" section checks bloodhound-python, bloodhound.py, certipy, certipy-ad, petitpotam.py, and pwsh.

### Real-data validation (this release)
On a Fedora attacker box with no domain controller available, the new dispatchers all handle missing AD tooling per ADR-004 D3:
- `enum-ldap.sh` against localhost:389 with full env (`ENUM_USER`/`ENUM_PASS`/`ENUM_DOMAIN`/`ENUM_DC_IP`) → "[skip] bloodhound-python not installed" + "[skip] certipy not installed"; ldapsearch sections silently no-op (`have ldapsearch` returns false); existing impacket GetUserSPNs/GetNPUsers paths still attempt their normal work. `ldap dispatcher done.` rc=0.
- `enum-smb.sh` against localhost with `ENUM_DC_IP=10.0.0.1` → produces `_petitpotam_signal.txt` + `_shadow_creds_hint.txt` (D1.1) alongside the pre-existing artifacts; relay-candidates list empty so PetitPotam hint correctly not emitted.
- `enum-kerberos.sh` against localhost:88 → "[skip] AS-REP cross-link: no users harvested from smb/ldap dispatchers yet" (D1.3 cross-link logic works when given an empty upstream user set).
- 8 PS1 scripts: AST-parsed via `pwsh -NoProfile [Parser]::ParseFile` — all 8 OK. Functional behaviour against real AD remains engagement-time validation per ADR-004 "DOES NOT VALIDATE".

## [v0.16.0] — 2026-05-20

**Iteration K** of ROADMAP-001 — Windows side of bulk-enum, completing the post-foothold orchestration story across both platforms. Per [ADR-003](aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md).

A single `$OUT` directory can now hold output from BOTH `bulk-enum-linux.sh` (J, v0.15.0) and `bulk-enum-windows.py` (K). `report.py` auto-detects the mixed layout and emits ONE per-host verdict table covering the whole estate, sorted worst-first with an `os` column.

### Added
- **K.0 [ADR-003](aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md):** records the eight Windows-bulk-enum design decisions — WinRM-only default transport (`pywinrm`, no fallback parade); `--use-smb-admin` opt-in only, gated like the G.8 exploit flags (implementation deferred with explicit reason); output layout identical to ADR-002 D5 (filename swap only); Python orchestrator (pywinrm is canonical); `ThreadPoolExecutor` concurrency model; `--throttle` parity with the SSH side; explicit auth-method negotiation with no auto-fallback; read-only by default. Includes an explicit "WHAT THIS ADR DOES NOT VALIDATE" section flagging that the WinRM transport is unverified pre-engagement on this codebase's CI, with the operator's first-run verification checklist.
- **K.1 `aranumtoolkit/network/bulk-enum-windows.py`:** Python orchestrator using `pywinrm`. Flag parity with `bulk-enum-linux.sh`: `--targets`/`--user`/`--pass`/`--port`/`--connect-timeout`/`--script`/`--output`/`--parallel` (cap 16)/`--throttle`/`--dry-run`/`--resume`. New: `--auth {ntlm,basic,kerberos,credssp}` (default ntlm), `--tls` (HTTPS:5986 with cert-validation=ignore by default), `--use-smb-admin` (per ADR-003 D2, documented but rc=126'd with the reason). Arg-validation refusals at rc=2: basic-over-HTTP (clear-text password), `--use-smb-admin` without `--pass`, `-P > 16`, pywinrm missing on a non-dry-run. IPv6 endpoint URLs bracketed correctly. Output to `$OUT/<host>/{winenum.txt, winenum.err, _meta.json, .done}`, with `run.log` + `hosts.txt` + `_summary.tsv`.
- **K.2 `aranumtoolkit/network/report.py` Windows rules + mixed-OS verdicts:** `_BULK_RULES_WIN` anchored on what `standalones/windows/Invoke-PrivEscEnum.ps1` actually prints (formatting from its Section/Sub/Hit functions is stable across runs). CRITICAL: `AlwaysInstallElevated ENABLED`, `Se{Impersonate,AssignPrimaryToken,Debug,Tcb,CreateToken,LoadDriver}Privilege (ENABLED)` (literal `\(ENABLED\)` parens, no re.I — anchors away from the disabled-hint false positive), `WRITABLE BINARY:` (service binary the user can overwrite), `DefaultPassword=` (AutoLogon disclosure), membership in Domain/Enterprise/Schema Admins / Administrators / Backup/Server Operators / Hyper-V Administrators, GPP cpassword XML files, Unattend/sysprep on disk. HIGH: `Se{Backup,Restore,TakeOwnership,ManageVolume,Security}Privilege (ENABLED)`, unquoted service path with spaces under Program Files, writable PATH directory, Account/Print Operators / DnsAdmins membership, scheduled task running as SYSTEM / NETWORK SERVICE / Administrators, SCCM naa-credential path. MEDIUM: `Se*Privilege (disabled — operator can still enable)`, Remote Desktop / Remote Management Users membership, password/secret/api_key/token patterns in user files, EOL Windows (7 / Server 2008 / 2012). Layout detector (`_is_bulk_enum_dir`) and walker (`walk_findings_bulk`) extended: a subdir with `_meta.json` and EITHER `linenum.txt` OR `winenum.txt` qualifies; rules selected per file type. `_per_host_verdicts` gains an `os` field per host (`linux` / `windows` / `mixed` if both surfaces produce findings). Per-host verdict table in `report.md` / `report.html` gains an OS column.
- **K.3 fixtures + unit + smoke:**
  - `aranumtoolkit/tests/fixtures/bulk-enum/win-{svc-imperson,backup-op,old-rdp}/` — three Windows fixtures anchoring CRITICAL / HIGH / MEDIUM verdict tiers. Named with lowercase hyphenated tokens to avoid colliding with the default `\bCRITICAL\b` severity rule (initial naming using "WIN-CRITICAL" was false-positiving on the host name itself — fixed during fixture testing).
  - `aranumtoolkit/tests/test_bulk_enum_report.py` extended to cover all 7 fixtures + an `EXPECTED_OS` map and a regression test that disabled-hint Se* privileges do not false-positive critical.
  - `aranumtoolkit/tests/test_bulk_enum_windows.py` (new): 14 stdlib-`unittest` tests covering `parse_spec`, WinRM endpoint URL construction (IPv6 bracketing, HTTPS scheme), and end-to-end orchestrator behaviour via mocked `winrm.Session.run_ps` — dry-run produces per-host dirs + run.log, `--throttle` precedence, the four arg-validation refusals, and a mocked-Session non-dry-run that writes winenum.txt + `_meta.json` correctly.
  - `aranumtoolkit/tests/smoke.sh` section 11e extended for the Windows fixtures (now copies winenum.txt alongside linenum.txt); new section 11f exercises bulk-enum-windows.py --dry-run + arg-validation paths.

### Enhanced
- **K.4 top-level `README.md`:** new Windows subsection of the bulk-enum quickstart — WinRM HTTP / HTTPS / Kerberos flows, the mixed-estate single-`$OUT` pattern (one `report.py` rolls both sides up), the "Remote Management Users" auth-reach caveat, the `--use-smb-admin` documented-but-deferred status, and the explicit "WHAT THIS DOES NOT VALIDATE" callout per ADR-003. Network table gets a `bulk-enum-windows.py` row.
- **K.4 `deps-check.sh`:** pywinrm Python-package check added (same shape as the iteration-H stdlib check + defusedxml). Reports installed version or pip-install hint when absent.
- IPv6 bracketing fix in `bulk-enum-linux.sh` (caught by the advisor's review of v0.15.0): the ssh destination spec now brackets bare IPv6 hosts (`user@[2001:db8::1]` instead of `user@2001:db8::1`) — older OpenSSH otherwise treats the trailing `:N` of the v6 address as a port. Mirrors A.5's `ldap_url()` pattern from the network dispatchers.

### Real-data validation (this release)
`nmap -sV --top-ports 1000 -oA localhost-scan 127.0.0.1` → `nmap-parse.py` produced 4 open ports across http/standalones/redis/jmx categories → `auto-enum.sh --only redis,unknown` executed dispatchers end-to-end → `report.py` emitted `findings.json` (`mode=auto-enum`) + `report.md` + `report.html` from 7 findings on 127.0.0.1. `bulk-enum-linux.sh` against localhost (no local sshd) produced the expected rc=255 + populated `_meta.json` + `linenum.err` per host, and `report.py` then correctly detected bulk-enum layout (`mode=bulk-enum`).

## [v0.15.0] — 2026-05-20

**Iteration J** of ROADMAP-001 — bulk local-enum at scale (Linux). Fills the remote→local handoff gap: with low-privilege credentials on a 50-500 host network, run `standalones/linux/linenum-fast.sh` against every target in parallel via SSH stdin-pipe (no on-disk artifact on the victim) and roll up per-host CRITICAL/HIGH/MEDIUM/LOW verdicts via `report.py`. Per [ADR-002](aranumtoolkit/docs/ADR-002-20MAY2026-bulk-enum-design.md).

### Added
- **J.0 [ADR-002](aranumtoolkit/docs/ADR-002-20MAY2026-bulk-enum-design.md):** records the seven design decisions for bulk-enum — stdin-pipe transport vs scp (no on-disk artifact, one round-trip per host, atomic semantics, output channel = input channel); no bundler (linenum-fast.sh is already the aggregator); per-engagement `known_hosts` silo (`$OUT/known_hosts` with `StrictHostKeyChecking=accept-new`, prevents cross-engagement trust contamination); `--throttle` parity with `auto-enum.sh`; verdict logic in `report.py` not the scanner; Windows orchestration deferred to v0.16.0 (iteration K — needs ADR-003); 50-500 host scale tuning (default parallel=4, capped at 16; `BatchMode=yes`, `ConnectTimeout=10`, `ServerAliveInterval=15`).
- **J.1 `aranumtoolkit/network/bulk-enum-linux.sh`:** orchestrator with full flag parity to `auto-enum.sh` (`--targets`, `--user`, `--key`, `--pass` via sshpass, `--port`, `--connect-timeout`, `--ssh-opt` (repeatable), `--parallel` capped at 16, `--throttle`, `--dry-run`, `--resume`). Per-engagement `known_hosts` written at `$OUT/known_hosts`. Each target gets `$OUT/<host>/{linenum.txt, linenum.err, _meta.json, .done}`. Run.log centralized journal + `_summary.tsv` post-run + failure tally listing each failed host. xargs-based parallel dispatch. Subshell-safe via persisted `.ssh_extra_opts` file (avoids env-var serialization gymnastics).
- **J.3 fixtures + tests:**
  - `aranumtoolkit/tests/fixtures/bulk-enum/` — four synthetic per-host directories anchoring each verdict tier (web01=CRITICAL via NOPASSWD sudo; db02=CRITICAL via cap_setuid + perl SUID; app03=HIGH via writable systemd + cred-in-history; old04=MEDIUM via non-gtfobin SUID + old kernel). README documents the fixture contract.
  - `aranumtoolkit/tests/test_bulk_enum_report.py` — 9 stdlib `unittest` tests: layout detection (bulk vs auto-enum vs empty), walker output shape (every required field, evidence_path relative), per-host verdict assignment (anchored on fixture expectations), end-to-end CLI run (findings.json mode + per_host worst-first ordering, report.md + report.html written, HTML contains the per-host verdict surface).
  - `aranumtoolkit/tests/smoke.sh` sections **11d + 11e**: bulk-enum-linux.sh dry-run path (target-file parsing for bare host vs user@host:port, run.log + known_hosts + hosts.txt artifacts, throttle precedence operator-`-P`-wins, `-P 64` parallel-cap-at-16 refusal); report.py against fixtures (rc=0, all three outputs written, verdict per fixture, HTML contains the per-host surface).

### Enhanced
- **J.2 `aranumtoolkit/network/report.py` bulk-enum mode:** auto-detects bulk-enum output layout (via `_is_bulk_enum_dir()` — checks for `_meta.json` + `linenum.txt` markers) and runs the appropriate walker. No new CLI flag; `python3 aranumtoolkit/network/report.py $OUT` works for either layout. `findings.json` gains a `mode` field (`"auto-enum"` or `"bulk-enum"`) so downstream consumers can branch. In bulk mode: a `per_host` section is added with each host's `verdict` (max severity across findings) + per-tier finding counts, sorted worst-first. `report.md` and `report.html` add a "Per-host privesc verdict (bulk-enum)" table BEFORE the service breakdown (operator's first question is "which hosts should I focus on?"). New severity rules anchored on `linenum-fast.sh` output: CRITICAL on NOPASSWD / `(ALL:ALL) ALL` / dangerous capabilities (cap_setuid / cap_dac_read_search / cap_sys_admin / cap_sys_ptrace / cap_sys_module / cap_chown / cap_net_admin with `+ep`) / SUID matching one of 47 known GTFOBins / world-writable /etc/{passwd,shadow,sudoers} / `Privileged: true` container / `LD_PRELOAD` or `LD_LIBRARY_PATH` in sudo `env_keep`; HIGH on sudo version matching known-CVE ranges / `cap_net_raw`/`cap_kill`/`cap_sys_rawio` with `+ep` / writable systemd or cron / `no_root_squash` in NFS exports / `docker.sock` readable / password/api_key/token=value patterns in history; MEDIUM on non-gtfobin SUID / Linux kernel 2.x/3.x/4.x/5.x ≤ 5.15. HTML adds `.verdict-{critical,high,medium,low}` CSS classes for operator extension.
- **J.4 top-level `README.md`:** new "Bulk local-enum across many hosts (iteration J)" section — quickstart for standard / `--throttle` / `--resume` / `--dry-run` flows, output-tree layout, per-engagement `known_hosts` silo explanation, `report.py` verdict reference, Windows-on-K (v0.16.0) callout. `bulk-enum-linux.sh` row added to the Network Enumeration table. Optional dependencies updated.
- **J.4 `deps-check.sh`:** `sshpass` added under OPTIONAL (only required for `--pass` auth; ssh-agent / `--key` are preferred).

## [v0.14.0] — 2026-05-20

**Iteration G** of ROADMAP-001 — tests + hardening.

### Added
- **G.1 service banner fixtures:** `aranumtoolkit/tests/fixtures/services/` — five synthetic nmap-XML fixtures exercising routing for every category in `SERVICE_MAP` (`all-services.xml`), IPv6 bracketing semantics (`ipv6-host.xml`), the documented dual-routing of openfire-admin on 9090 vs the generic http category (`openfire-vs-http-collision.xml`), closed/filtered port filtering (`closed-and-filtered.xml`), and the unknown-bucket fallthrough (`unknown-service.xml`). All synthetic — no real-target captures.
- **G.2 nmap-parse unit tests:** `aranumtoolkit/tests/test_nmap_parse.py` — 19 stdlib-`unittest` tests across `SERVICE_MAP` completeness, `categorize()` precedence (the openfire/http collision regression case is explicit), full XML-routing through `dispatch()`, IPv6 bracketed-target output, closed-port exclusion, XXE / billion-laughs rejection (anchored on the A.2 hardening), the `--list-categories` / `--unknown` / `--json` CLI surface, and XML-vs-gnmap parser parity. `aranumtoolkit/tests/__init__.py` added so `python3 -m unittest tests.test_nmap_parse` resolves the module.
- **G.3 gql.py pure-function tests:** `aranumtoolkit/tests/test_gql_internals.py` — 28 stdlib-`unittest` tests across seven internal functions chosen for testability without HTTP: `cache_key` (the A.3 identity-expansion fix — distinct cookies / job-tokens / PATs produce distinct cache files; anon path stable), `_check_range_size` (the A.4 bound check — `LOOP_HARD_CAP` boundary, inverted-range exit code, `--allow-huge` bypass), `type_str` (NON_NULL / LIST / nested `[String!]!` reconstruction), `unwrap` (wrapper stripping), `type_by_name` (schema lookup hit / miss / None-input), `parse_kv_args` (only the first `=` splits — base64 values survive; bad input exits 2), and `build_selection` (auto-selection generation for scalar / object / unknown / required-arg-field-skipped cases). Cache dir redirected via `GQL_CACHE_DIR` so tests don't pollute `standalones/graphql/.cache/`.
- **G.4 `Makefile`:** convenience targets `test` (lint + unittest + smoke), `lint` (shellcheck), `unittest` (`unittest discover`), `smoke` (`aranumtoolkit/tests/smoke.sh`), `deps-check`, `clean`, `help`. `make help` is the default target.
- **G.5 GitHub Actions CI:** `.github/workflows/ci.yml` — on push + PR to `main`. Installs Python 3.11 + shellcheck (apt) + defusedxml, then runs `make lint && make unittest && make smoke`. `fetch-tags: true` so the smoke test's `git tag` presence check works on CI.

### Enhanced
- **G.7 `--throttle` mode for sensitive environments:** `aranumtoolkit/network/auto-enum.sh --throttle` sets gentle defaults for OT/legacy/lab targets — `ENUM_PARALLEL=1`, `NUCLEI_RATE=20`, `NO_FFUF=1`, `NO_NIKTO=1`, and exports `ENUM_THROTTLE=1` so dispatchers can opt in. **Operator CLI args win over `--throttle` defaults** — `--throttle -P 8` keeps `-P 8` and prints a "operator-explicit; --throttle did not override" line so the precedence is visible. `--throttle --dry-run` previews the effective environment without scanning (the smoke-test interface). `aranumtoolkit/network/_lib.sh`: new helpers `throttle_delay()` (returns the inter-host pause in seconds, default 1, override via `ENUM_THROTTLE_DELAY`), `throttle_sleep()` (no-op when off), and `throttle_nmap_args()` (returns `-T2` under throttle, empty otherwise — use as `nmap $(throttle_nmap_args) ...`).
- `aranumtoolkit/tests/smoke.sh`: extended with throttle-precedence stanza (11b) and write-gate dry-run assertions for every helper that gained a gate in G.8 (11c).
- `deps-check.sh`: added `shellcheck` under OPTIONAL — install via `pip install shellcheck-py` or distro package.

### Security
- **G.6 shellcheck-clean baseline:** every `.sh` file now passes `shellcheck -S warning -e SC1091`. Library files (`aranumtoolkit/network/_lib.sh`, `standalones/activemq/_activemq_lib.sh`, `standalones/redis/_redis_lib.sh`, `standalones/smtp/_smtp_lib.sh`) carry a `# shellcheck shell=bash` directive so the lint scope is unambiguous. Genuine bugs fixed: `SC2069` redirect-order in `aranumtoolkit/network/enum-smtp.sh` and `standalones/smtp/smtp-quickwin.sh` (the `2>&1` was before the file redirect, so stderr leaked); `SC2155` declare+assign masking return values in `aranumtoolkit/network/auto-enum.sh` and `standalones/smtp/smtp-user-enum.sh`; missing `|| exit` after `cd` in `aranumtoolkit/tests/smoke.sh`. Two unused colour vars (`G`, `C`) dropped from `aranumtoolkit/network/autoenum-diff.sh`. Intentional state vars (`REACHABLE`, `AUTH_REQUIRED`, `REDIS_VERSION`, `RCMD_RC`) in `_redis_lib.sh` and word-splitting `$(curl_auth)` callsites in `_activemq_lib.sh`/`activemq-quickwin.sh` carry targeted `# shellcheck disable=…` directives with reasons. Three parsed-but-unwired flags (`MAX_MSGS`, `PASS_LIST`, `KEEPALIVE`) annotated with TODO reasons rather than silently dropped.
- **G.8 write-gate audit + fixes:** every exploitation helper now honours CLAUDE.md §9 invariant 1 (default = enumeration; mutation requires an explicit gate flag). Audit findings + remediation captured in [REVIEW-002](aranumtoolkit/docs/REVIEW-002-20MAY2026-write-gate-audit.md). Six helpers were in violation at audit start and were fixed in this iteration:
  - `standalones/activemq/activemq-cve-2023-46604.py`: added `--exploit` gate (previously default-fired the OpenWire RCE chain on first invocation).
  - `standalones/activemq/activemq-jolokia-rce.sh`: added `--exploit` gate (previously default-loaded the MBean and ran the command).
  - `standalones/redis/redis-rce-module.sh`: added `--exploit` gate (previously default-chained CONFIG SET + REPLICAOF + MODULE LOAD).
  - `standalones/redis/redis-rce-ssh.sh`: added `--write` gate (previously default-dropped `authorized_keys` via CONFIG SET + SAVE). Gate name is `--write` rather than `--exploit` because the primitive is a file write, not an RCE.
  - `standalones/smtp/smtp-phish-send.sh`: added `--send` gate (previously default-delivered the spoofed message).
  - `standalones/smtp/smtp-smuggling-test.py`: added `--send` gate (previously default-transmitted DATA payloads including the smuggled second-message).
  Every gate prints a dry-run summary and exits 0 when omitted — no env-var bypass. Per-tool READMEs updated to show the new gate flag in the quickstart examples.

---

## [v0.13.0] — 2026-05-19

**Iteration E** of ROADMAP-001 — reporting + ergonomics.

### Added
- `aranumtoolkit/network/report.py` (E.1+E.8+E.9): walks an auto-enum output tree and emits `findings.json` (machine-readable, severity-tagged), `report.md` (Markdown summary + per-host CRITICAL/HIGH detail), and `report.html` (single-file HTML, embedded CSS, no external deps). Severity heuristics anchored on the literal markers dispatchers emit. `--redact` produces a stable `<TARGET-N>` mapping for shareable output. `--severity-rules FILE` lets operators add custom JSON-line rules. Stdlib-only.
- `aranumtoolkit/network/autoenum-diff.sh` (E.2): compares two output trees via their `findings.json`. Surfaces NEW hosts, NEW (host, service) pairs, NEW findings (grouped by severity), and DROPPED findings. Auto-runs `report.py --findings-only` when `findings.json` is missing in either tree. Exit 1 iff any new findings — CI-loop friendly.

### Enhanced
- `aranumtoolkit/network/auto-enum.sh` (E.3+E.4+E.10): central `run.log` under `$OUTDIR` capturing timestamp + auth-presence flags + per-tool versions + per-dispatch begin/end with elapsed seconds and rc. New `--resume` flag honors per-service `.done` markers from prior runs (skip-and-log). Final summary now reports `OK=N FAIL=N SKIP=N` and lists the failed dispatchers; closing hint points at `report.py`.
- `aranumtoolkit/network/_lib.sh` (E.5+E.6): new `curl_ua()`, `curl_proxy_arg()`, `curl_extra_args()` helpers. `ENUM_USER_AGENT` env honored (defaults to the same Chrome-stable string `gql.py` adopted in F.8 — consistent suite fingerprint). `ENUM_PROXY` parallels `GQL_PROXY` for explicit `-x` override; curl's native `*_PROXY` env honor remains the no-config default.
- `aranumtoolkit/network/enum-http.sh`: per-URL header probe now sets `-A "$(curl_ua)"`. Other curl callsites can adopt incrementally.
- `deps-check.sh` (E.7): new `version_floor()` helper using `sort -V`. Floors applied to `nxc`, `netexec`, `kerbrute`, `nuclei`, `ffuf`, `httpx`, `redis-cli`, `mongosh`, `impacket`. Output uses `>=` (green) / `<` (red — upgrade) / `?` (unparseable, manual check).

---

## [v0.12.0] — 2026-05-19

**Iteration F** of ROADMAP-001 — GraphQL depth probes + transport-layer extras.

### Added
- `standalones/graphql/gql.py suggest` (F.1): field-name harvest from "Did you mean X?" error messages. Walks a 32-guess built-in corpus or `--corpus FILE`. Useful when introspection is disabled — many resolvers still leak schema structure via suggestion errors.
- `standalones/graphql/gql.py apq-probe` (F.3): two-step Apollo Persisted Queries enforcement check. Confirms APQ is implemented, then sends body + forged `sha256Hash` — if server returns data, persisted-query whitelist is bypassable (CRITICAL).
- `standalones/graphql/gql.py csrf-probe` (F.5): `GET /graphql?query={__typename}`. Spec-compliant servers reject (400/405). Servers that accept GET combined with cookie auth = one img/iframe away from arbitrary-query CSRF.

### Enhanced
- `standalones/graphql/gql.py call --batch N` (F.2): send the same body in a JSON array of length N. Tests batched-body gateways for per-request authz / shared-resolver state leakage.
- `standalones/graphql/gql.py call --alias-dos-check --confirm` (F.6): DETECT-ONLY latency growth measurement with N=1,2,4,…,16 aliases of `__typename`. Super-linear growth = missing alias normalization = DoS-amplification surface. Refuses to run without `--confirm`.
- `standalones/graphql/gql.py diff --directive-bypass` (F.4): wraps every field in `@skip(if:$gqlSkip)`; reference profile sets it `false`, others `true`. Detects authz checks that key on AST-presence rather than resolver-execution.
- `standalones/graphql/gql.py raw --batch N` (F.2): same batched-POST semantics for the literal-query subcommand.
- `standalones/graphql/gql.py --proxy URL` (F.7): HTTP/HTTPS/SOCKS proxy via urllib's `ProxyHandler`. Env fallback `GQL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`. SOCKS via `socks5h://` requires PySocks (not a hard dependency).
- `standalones/graphql/gql.py --user-agent / --ua-rotate / GQL_UA` (F.8): default User-Agent changed from `gql.py/1.0` to a Chrome-stable string. `--user-agent gql` re-enables legacy UA; `--user-agent <literal>` overrides; `--ua-rotate FILE` picks a random UA per request.

### Refactored
- `standalones/graphql/gql.py`: `http_post()` now uses `_opener()` (builds urllib opener with proxy + TLS context); `http_get()` added for the CSRF probe. All existing subcommands inherit the new transport behavior unchanged.
- `aranumtoolkit/tests/smoke.sh`: extended with `v0.12.0` tag check + suggest/apq-probe/csrf-probe smoke against unreachable target.
- `aranumtoolkit/docs/ROADMAP-001-...`: iteration F marked complete (tag v0.12.0). Overall iteration table reordered to match real ship order (A→H→B→C→F, with E/G/D/I still ⬜). Iteration I added as placeholder for the new user milestone (engineering/science facility internal-pentest protocols — industrial/OT, remote-support, license servers, BMC, hypervisor mgmt, HPC schedulers, lab data services, backup, source/CI, VPN concentrators, print). 40+ candidate protocols listed; ADR-002 required before any code lands.

---

## [v0.11.0] — 2026-05-19

**Iteration C** of ROADMAP-001 — P1 service coverage + HTTP-depth bug-class checks + SMB/SSH extras. Fifteen sub-items shipped (C.0–C.14).

### Added
- `aranumtoolkit/network/enum-vnc.sh` (C.1): nmap `vnc-info`/`vnc-title`/`realvnc-auth-bypass` (CVE-2006-2369 raises CRITICAL) + raw RFB banner.
- `aranumtoolkit/network/enum-jmx.sh` (C.2): nmap `rmi-dumpregistry`/`rmi-vuln-classloader` across 1099/9999/9010/11099/7199 + JRMI handshake probe. Hints document mjet/ysoserial/msf follow-ups; never auto-run.
- `aranumtoolkit/network/enum-rabbitmq.sh` (C.3): mgmt-API probe with default `guest:guest` and optional `ENUM_USER`/`ENUM_PASS`. Pulls users/vhosts/exchanges/queues/connections/permissions on auth.
- `aranumtoolkit/network/enum-memcached.sh` (C.4): `stats` / `stats slabs` / `stats items` / `stats sizes` / `stats settings` + cachedump enumeration of first 5 slabs × 50 keys. Memcrashed amplification warning in hints.
- `aranumtoolkit/network/enum-couchdb.sh` (C.5): `_all_dbs`/`_users/_all_docs`/`_config`/`_membership`/`_node/_local/_config`. Version-range signal for CVE-2017-12635 (pre-1.7.0 / pre-2.1.1).
- `aranumtoolkit/network/enum-etcd.sh` (C.6): `/version`/`/v2/keys/?recursive=true`/`/metrics` across HTTP and HTTPS. Unauth v2 keys response = full k8s control-plane secret-store read = CRITICAL.
- `aranumtoolkit/network/nmap-parse.py` (C.0): four new categories — `rabbitmq` (5672/15672/5671/15671), `memcached` (11211), `couchdb` (5984/6984), `etcd` (2379/2380). `vnc` (5800/5900-5902) and `jmx` (1099/9999/9010/11099) were already present.

### Enhanced
- `aranumtoolkit/network/enum-http.sh` (C.7–C.12): six new probes gated on at-least-one-live-URL —
  - **C.7 JWT extraction**: greps response bodies for the three-part `eyJ...` shape, decodes header, raises err() on `alg=none`, hit() on HS* (hashcat -m 16500). `_jwts.txt` aggregates findings.
  - **C.8 CORS misconfig**: `Origin: https://attacker.example.invalid` reflected back + `Access-Control-Allow-Credentials: true` = CRITICAL.
  - **C.9 exposed VCS/sensitive paths**: `.git/HEAD`, `.git/config`, `.svn/entries`, `.svn/wc.db`, `.hg/store`, `.DS_Store`, `.env*`, `web.config`, `wp-config.php.bak`, `config.json`, `server-status`, `server-info`.
  - **C.10 vhost-fuzz seed**: aggregates collected SAN domains into `_all_sans.txt`; hints document the ffuf command.
  - **C.11 cert+SAN collection**: `openssl s_client -showcerts` per HTTPS URL; per-URL SANs feed C.10.
  - **C.12 high-value path micro-wordlist**: `/api/swagger.json`, `/swagger.json`, `/openapi.json`, `/actuator/health`/`env`/`heapdump`, `/wp-json/wp/v2/users`, `/admin`, `/phpmyadmin/`, `/manager/html` (folded into C.9's HEAD sweep).
- `aranumtoolkit/network/enum-smb.sh` (C.13): parses existing nmap-smb-vuln output for "signing enabled but not required" / "enabled: false"; aggregates relay candidates to `_relay_candidates.txt` and raises CRITICAL with host count. PetitPotam signal via rpcclient `\pipe\lsarpc` anonymous reachability when `ENUM_DC_IP` is set. Does NOT run impacket coerce tools.
- `aranumtoolkit/network/enum-ssh.sh` (C.14): parses `auth_methods.txt` from phase 3 — `publickey` advertised AND no `password`/`keyboard-interactive` → `_key_only_<port>.txt` (refuse spray hint). Parses OpenSSH version from `banner.txt`; < 7.7 raises CVE-2018-15473 candidate signal.

### Refactored
- `aranumtoolkit/tests/smoke.sh` extended to cover all 13 new dispatchers + `v0.11.0` tag check.
- `README.md` network table extended with six new C.0-C.6 dispatcher rows.

---

## [v0.10.0] — 2026-05-19

**Iteration B** of ROADMAP-001 — P0 service-coverage expansion. Adds 7 new network dispatchers + 2 new nmap-parse categories. Auto-routed by `auto-enum.sh` based on the new categories. Version is `v0.10.0` (not the originally-reserved `v0.3.0`) because semver requires monotonic increase and iteration H already shipped at `v0.9.0`; the roadmap's iteration→tag mapping is corrected to reflect actual chronology.

### Added
- `aranumtoolkit/network/enum-postgres.sh` (B.1): trust-auth probe (no-pwd attempts as `postgres`/`admin`/`app`) + `nxc postgres` cred check + `psql` authenticated recon dumping `pg_roles` + database list + version. Hints cover post-auth escalation: `COPY ... TO PROGRAM`, untrusted PL languages, `lo_import`/`lo_export`, `dblink`.
- `aranumtoolkit/network/enum-mysql.sh` (B.2): anonymous + root-no-pwd probes (`root`/`admin`/`mysql`) + `nxc mysql` + auth recon dumping `mysql.user`, `secure_file_priv`, `local_infile`, `SHOW GRANTS`. Hints cover `INTO OUTFILE`, UDF RCE, `LOAD DATA LOCAL INFILE`.
- `aranumtoolkit/network/enum-mongo.sh` (B.3): `mongosh`-preferred-or-`mongo`-legacy unauthenticated `listDatabases` probe + per-database collection enumeration (capped at 10 dbs × 50 collections each). IPv6-aware connection-URI construction (per MongoDB URI spec). Auth recon via `usersInfo` + `rolesInfo`. nmap mongodb-info/mongodb-databases NSE.
- `aranumtoolkit/network/enum-elastic.sh` (B.4): `curl`-based probes of `_cluster/health`, `_cluster/state`, `_cat/indices?v`, `_cat/nodes?v`, `_security/user`. Cred-leak sweep via `_search?q=password*|passwd*|secret*|api_key*|token*` with hit-count parsing. Kibana 5601 `/api/status` detection. TLS-insecure by default (engagement targets).
- `aranumtoolkit/network/enum-docker.sh` (B.5): **CRITICAL when triggered.** Remote Docker daemon API probe — `/version`, `/info`, `/containers/json`, `/images/json`, `/networks`, `/volumes` against 2375 (plaintext — dangerous) and 2376 (TLS). Unauth 2375 success raises an `err()`-tagged alert with the explicit "host-equivalent RCE via `docker run -v /:/mnt --privileged`" warning text. **Never invokes `docker run`** — the operator decides.
- `aranumtoolkit/network/enum-kubernetes.sh` (B.6): TLS apiserver 6443 + insecure apiserver 8080 (raises CRITICAL when present — deprecated, full cluster control) + kubelet 10250 (`/pods`, `/stats/summary`, `/metrics`, `/healthz`) + readonly kubelet 10255 + kube-proxy 10256. Optional `K8S_TOKEN` env for operator-supplied Bearer token. Captures apiserver `gitVersion`.
- `aranumtoolkit/network/enum-ipmi.sh` (B.7): `nmap -sU -p623` with `ipmi-version`, `ipmi-cipher-zero`, `ipmi-brute` NSE scripts. Cipher-0 hits raise CRITICAL alert via parsed nmap output. Hints document the manual `msfconsole auxiliary/scanner/ipmi/ipmi_dumphashes` and `ipmitool sol activate` follow-ups — never auto-executes msf.
- `aranumtoolkit/network/nmap-parse.py` (B.8): two new categories — `docker` (ports 2375, 2376) and `kubernetes` (6443, 8080, 10250, 10255, 10256). Both use the canonical never-match regex `a^` because nmap fingerprints them as generic `http`/`ssl/http`; the dispatchers handle product detection. Synthetic-XML routing verified: `docker → {2375}`, `kubernetes → {6443, 10250}`, no false positives on port 80.

### Refactored
- ROADMAP-001: iteration B marked complete; tag-mapping note added clarifying that iteration ordering (H before B) determined actual tag order (`v0.9.0` then `v0.10.0`), not the original aspirational mapping.

---

## [v0.9.0] — 2026-05-19

**Iteration H** of ROADMAP-001 — Jabber/XMPP pentesting tooling per [ADR-001](aranumtoolkit/docs/ADR-001-19MAY2026-jabber-scope.md). Iteration H jumps the version from v0.2.0 to v0.9.0 to match the roadmap's tag plan (B–G iterations are not yet shipped; their tag slots are reserved).

### Added
- `standalones/jabber/README.md`: complete tool index + workflow for iteration H. Opens with safety summary (read first), documents the `--cleanup`-before-`--exploit` discipline for the OpenFire CVE helper, walks the typical workflow (discover → enum-jabber → user-enum → validate → optional Openfire detect/exploit/cleanup), gives the JSP plugin manifest template, and explicitly lists what the iteration does NOT do and why (no spray, no XEP-0077 conflict-probe, no Cisco UC, no bundled webshell, no Openfire persistence variant). (ROADMAP-001 H.7)
- `deps-check.sh`: new `JABBER / XMPP` section verifying `nc`, `openssl`, and the Python stdlib modules the standalones/jabber/ helpers depend on (`socket`, `ssl`, `base64`, `hashlib`, `hmac`, `urllib.request`, `xml.etree.ElementTree`). No new external deps required by iteration H. (ROADMAP-001 H.8)
- `README.md`: layout tree updated to reflect every top-level dir (was missing `standalones/graphql/`, `standalones/activemq/`, `standalones/redis/`, `standalones/smtp/`, `standalones/creds/`, `aranumtoolkit/docs/`). New `standalones/jabber/` row added. New `enum-jabber.sh` row added under network dispatchers. New "Jabber / XMPP (iteration H)" section with the four standalones/jabber/ tool descriptions and ADR pointer. (ROADMAP-001 H.9)
- `standalones/jabber/jabber-admin-api-probe.sh`: read-only detection of exposed Ejabberd / Prosody admin surfaces — Ejabberd HTTP commands API at `/api/status` over ports 5280/5281/80/8088 (HEAD-classified: 200/400/405 = EXPOSED, 401/403 = auth-required, 404 = module not enabled), Prosody `mod_admin_telnet` banner probe on TCP 5582, Prosody `mod_admin_web` at `/admin/` on 5280/5281. Sends only HTTP HEAD/GET and a single TCP banner read. Per-finding evidence files written to `--out` dir; one-line INFO/HIT/MISS per probe to stdout. Wired into `enum-jabber.sh` as phase 7 (de-duped per host so multi-port targets don't re-probe). (ROADMAP-001 H.6)
- `standalones/jabber/openfire-cve-2023-32315.py`: detect / exploit / cleanup helper for the Openfire admin-console auth-bypass path traversal (per ADR-001 D3). **Default behavior (`detect`)** probes `/setup/setup-/%u002e%u002e/log.jsp`, classifies VULNERABLE / NOT_VULNERABLE / UNKNOWN based on HTTP status + admin-console markup, and prints the server version banner. **No state change.** **`exploit`** prompts the operator to type the target FQDN/IP literally (no `--yes-i-mean-it` short-circuit), then performs the DWR-based `userService.createUser` call via the bypass, then multipart-uploads an operator-supplied JSP-plugin JAR (`--plugin-jar`), then prints the resulting webshell URL and writes a log file for `cleanup`. **`cleanup`** consumes the log and reverses the changes via the legitimate admin interface. Cleanup is currently a **scaffold** with documented manual procedure — the legitimate-login-then-delete flow varies enough by Openfire version that we will not ship untested removal code. Stdlib-only (per ADR-001 D4). The full chain is written per the public CVE advisory PoC pattern and explicitly flagged REQUIRES_LAB_VERIFICATION against a known-vulnerable Openfire 4.7.4 container before any engagement use. (ROADMAP-001 H.5)
- `standalones/jabber/jabber-validate.py`: stdlib-only single-credential XMPP SASL validation (per ADR-001 D2 — no spray). Tries mechanisms in order (default: `scram-sha-256,scram-sha-1,plain`), only those advertised by the server, with the stream re-opened between each failed attempt (the SASL state machine treats `<failure/>` as terminal). SCRAM-SHA-1 and SCRAM-SHA-256 implemented inline via stdlib `hashlib.pbkdf2_hmac` + `hmac` — verified against the RFC 5802 §5 reference vector byte-for-byte. Reads password from `--password` or `JABBER_PASSWORD` env. Exit codes: 0 = AUTH_OK, 1 = AUTH_FAIL (with reason), 2 = pre-auth protocol/connect error. (ROADMAP-001 H.4)
- `standalones/jabber/jabber-user-enum.py`: stdlib-only XMPP user enumerator using the SASL PLAIN response differential (read-only — no account creation). For each candidate username, opens a stream, optionally negotiates STARTTLS, attempts SASL PLAIN with a deliberately bogus password, and classifies the `<failure/>` XML per RFC 6120 §6.5 — `<not-authorized/>` → USER_EXISTS, `<account-disabled/>` → EXISTS_DISABLED, `<credentials-expired/>` → EXISTS_EXPIRED, `<invalid-authzid/>` → INVALID_FORMAT, etc. Per-user response time recorded as a timing-side-channel fallback for servers that return identical `<not-authorized/>` for every name. Per-user JSONL output via `--out`, summary table at end. Deliberately does NOT use the XEP-0077 IBR conflict-error trick (it creates accounts when the conflict path doesn't fire — violates ADR-001 D2). (ROADMAP-001 H.3)
- `aranumtoolkit/network/enum-jabber.sh`: XMPP/Jabber enumeration dispatcher, auto-routed from the `xmpp` category. Seven phases — raw TCP banner, STARTTLS feature probe + cert/SANs collection (extracts domain from cert SAN when `ENUM_XMPP_DOMAIN` not set), SASL-mechanism inventory, XEP-0077 in-band-registration advertisement check (no actual register call), server `disco#info` + `disco#items`, MUC discovery on `conference.<domain>`, BOSH/WebSocket endpoint detection on 5280/5281. All probes are read-only; tools gracefully no-op when `nc`/`openssl`/`curl` absent. Output per-host per-port under `$OUT/<ip>_<port>/`. (ROADMAP-001 H.2)
- `aranumtoolkit/network/nmap-parse.py`: two new service categories — `xmpp` (ports 5222/5223/5269/5280/5281/5298/7777; service-name regex matching `xmpp`/`jabber`/`xmpp-client`/`xmpp-server`) and `openfire-admin` (ports 9090/9091, port-only — uses the canonical never-match regex `a^` so HTTP service names on other ports don't accidentally tag as openfire-admin). Verified: 9090 routes to both `http` (intentional overlap) and `openfire-admin`; port 80 does NOT route to `openfire-admin`. (ROADMAP-001 H.1)
- `aranumtoolkit/docs/ADR-001-19MAY2026-jabber-scope.md`: Architecture Decision Record locking in scope for iteration H (Jabber/XMPP tooling). Records four decisions: XMPP-only surface (Cisco UC, SIP/voice, modern team chat deferred), no spray (enum + single-cred validation only), OpenFire CVE-2023-32315 ships as detect-default / `--exploit` full-chain / `--cleanup` reverse with typed-FQDN confirm, stdlib-only Python.
- `aranumtoolkit/docs/ROADMAP-001-...`: iteration H placeholder replaced with full per-item plan (H.1–H.9), commit cadence, and acceptance criteria all bound to ADR-001.

### Refactored
- ROADMAP-001 iteration A marked complete (tag `v0.2.0` shipped); iteration H marked complete (all nine sub-items, this release).

---

## [v0.2.0] — 2026-05-19

**Iteration A** of ROADMAP-001 — bug fixes from REVIEW-001 §3 (5 of 10 items addressed; the remaining 5 are lower-severity tracked items not blocking later iterations) plus the governance artifacts that established the repo's commit/changelog/versioning discipline.

### Security
- `aranumtoolkit/network/_lib.sh` + `aranumtoolkit/network/enum-{smb,ldap,mssql,winrm,rdp}.sh`: replaced shell-string credential concatenation (`NXC_ARGS+=" -u $ENUM_USER"`) with bash arrays via new `nxc_creds_array` helper. Closes the shell-injection footgun where credentials containing quotes, spaces, or shell metacharacters could break tooling or — given a hostile credential — execute arbitrary commands. Verified end-to-end with a payload-style credential (`al'ice"bob; rm -rf /tmp/X`) — no shell expansion, no rm execution. (REVIEW-001 §3.1)
- `aranumtoolkit/network/nmap-parse.py`: hardened XML parsing against XXE / billion-laughs. Prefers `defusedxml.ElementTree` when installed; falls back to stdlib with a regex pre-scan of the prolog that rejects `<!ENTITY` declarations and `SYSTEM`/`PUBLIC` external references inside DOCTYPE. Benign nmap output (which always emits `<!DOCTYPE nmaprun>` with no internal subset) parses byte-identically. Verified: `aranumtoolkit/tests/fixtures/malicious_xxe.xml` and `aranumtoolkit/tests/fixtures/billion_laughs.xml` rejected under both backends with clean stderr messages. (REVIEW-001 §3.2)

### Fixed
- `aranumtoolkit/network/enum-ldap.sh`: IPv6 LDAP server addresses are now bracketed in the `ldap://` URL via new `ldap_url()` helper. Previously `ldap://2001:db8::1` would be parsed ambiguously by `ldapsearch`'s URL handler. v4 callsites unchanged. (REVIEW-001 §3.6)
- `standalones/graphql/gql.py`: `cache_key()` now includes `Cookie` and `JOB-TOKEN` headers (in addition to `PRIVATE-TOKEN` and `Authorization`) in the per-identity cache hash. Two cookie-based or job-token-based sessions against the same URL no longer collide on a single cache file. Anonymous calls still share a single cache entry. (REVIEW-001 §3.3)

### Enhanced
- `standalones/graphql/gql.py`: added `--insecure` / `-k` flag and `GQL_INSECURE=1` env var to bypass TLS certificate verification (mirrors `curl -k`). Default behavior (verify) unchanged. Affects every subcommand that hits the network (`introspect`, `ls`, `describe`, `call`, `loop`, `diff`, `raw`).
- `standalones/graphql/gql.py loop`: `--range` and `--gid-range` now materialize values lazily via generators. A new `LOOP_HARD_CAP = 1_000_000` ceiling refuses unbounded sweeps (the prior code would build a 10-billion-element Python list and OOM before the first request fired). Pass `--allow-huge` to override. Inverted ranges (hi < lo) now produce a clean error instead of a silent zero-iteration loop. Verified: 2M-element generator stays under 25 MB RSS for partial consumption. (REVIEW-001 §3.4)

### Added
- `aranumtoolkit/network/_lib.sh`: `nxc_creds_array <ARRAY_NAME>` helper using bash namerefs (4.3+) to populate credential argv safely.
- `aranumtoolkit/network/_lib.sh`: `ldap_url <ip> [port] [scheme]` helper to construct LDAP URLs that respect IPv6 bracketing.
- `aranumtoolkit/tests/fixtures/malicious_xxe.xml` + `aranumtoolkit/tests/fixtures/billion_laughs.xml`: regression fixtures for `nmap-parse.py` XML hardening.
- `deps-check.sh`: detect `defusedxml` Python package; lists `pip3 install defusedxml` under install hints.
- `CLAUDE.md`: agent mandates covering scope, model split (Opus plan / Sonnet execute), commit format, semver, changelog discipline, code style, safety invariants.
- `CHANGELOG.md`: this file.
- `.gitignore`: excludes `__pycache__/`, `.cache/`, `enum-results/`, `*.so`, local secrets.
- `aranumtoolkit/docs/REVIEW-001-19MAY2026-thoroughness-audit.md`: collection-wide audit identifying coverage gaps and hardening opportunities.
- `aranumtoolkit/docs/ROADMAP-001-19MAY2026-thoroughness-execution.md`: living, dated execution plan sequencing all REVIEW-001 items across 7 iterations (A–G) tied to MINOR release tags `v0.2.0`–`v0.8.0`. Iteration H (Jabber/XMPP/comp pentesting) added 2026-05-19 as user-requested milestone targeting `v0.9.0`.

### Refactored
- Repo re-initialized as a standalone git repository (was previously untracked).

---

## [v0.1.0] — 2026-05-19

Initial inventory of the toolkit (pre-versioning baseline). Documented in `README.md`. No formal release tag was cut; this entry exists so future releases have a numeric anchor.

### Added
- `standalones/windows/` — PowerShell privesc enumeration (services, tasks, tokens, registry, creds, AlwaysInstallElevated, writable PATH dirs) plus `enum.bat` no-PS fallback.
- `standalones/linux/` — bash privesc enumeration (SUID, sudo, capabilities, cron, containers, writable files, group, creds hunt) and `linenum-fast.sh` one-shot.
- `aranumtoolkit/network/` — `nmap-parse.py` (XML/gnmap/nmap → JSON inventory), `auto-enum.sh` orchestrator, and per-service dispatchers for SMB, LDAP, Kerberos, WinRM, RDP, MSSQL, HTTP(S), SSH, FTP, SNMP, NFS, DNS, Redis, SMTP, ActiveMQ, plus an `enum-unknown.sh` catch-all.
- `standalones/graphql/gql.py` — stdlib-only GraphQL toolkit (introspect / ls / describe / call / loop / diff / raw), GitLab catalog fallback when introspection is disabled.
- `standalones/redis/` — quickwin, lateral, RCE-via-SSH-key, RCE-via-module, rogue-master scripts and Redis module source.
- `standalones/activemq/` — CVE-2023-46604 PoC, Jolokia RCE, queue dump, quickwin.
- `standalones/smtp/` — quickwin, user enumeration, relay test, SMTP smuggling test, SPF/DMARC check, phishing send.
- `standalones/creds/` — default-credentials sweep (JSON catalog of vendor defaults).
- `deps-check.sh` — verify presence of required / recommended / optional tools.
