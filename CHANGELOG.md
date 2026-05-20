# Changelog

All notable changes to **aratool** will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See `CLAUDE.md` §6 for the entry style guide.

## [Unreleased]

### Security
- `network/_lib.sh` + `network/enum-{smb,ldap,mssql,winrm,rdp}.sh`: replaced shell-string credential concatenation (`NXC_ARGS+=" -u $ENUM_USER"`) with bash arrays via new `nxc_creds_array` helper. Closes the shell-injection footgun where credentials containing quotes, spaces, or shell metacharacters could break tooling or — given a hostile credential — execute arbitrary commands. Verified end-to-end with a payload-style credential (`al'ice"bob; rm -rf /tmp/X`) — no shell expansion, no rm execution. (REVIEW-001 §3.1)

### Fixed
- `network/enum-ldap.sh`: IPv6 LDAP server addresses are now bracketed in the `ldap://` URL via new `ldap_url()` helper. Previously `ldap://2001:db8::1` would be parsed ambiguously by `ldapsearch`'s URL handler. v4 callsites unchanged. (REVIEW-001 §3.6)

### Added
- `network/_lib.sh`: `nxc_creds_array <ARRAY_NAME>` helper using bash namerefs (4.3+) to populate credential argv safely.
- `network/_lib.sh`: `ldap_url <ip> [port] [scheme]` helper to construct LDAP URLs that respect IPv6 bracketing.

### Enhanced
- `graphql/gql.py`: added `--insecure` / `-k` flag and `GQL_INSECURE=1` env var to bypass TLS certificate verification (mirrors `curl -k`). Default behavior (verify) unchanged. Affects every subcommand that hits the network (`introspect`, `ls`, `describe`, `call`, `loop`, `diff`, `raw`).

### Added
- `CLAUDE.md`: agent mandates covering scope, model split (Opus plan / Sonnet execute), commit format, semver, changelog discipline, code style, safety invariants.
- `CHANGELOG.md`: this file.
- `.gitignore`: excludes `__pycache__/`, `.cache/`, `enum-results/`, `*.so`, local secrets.
- `docs/REVIEW-001-19MAY2026-thoroughness-audit.md`: collection-wide audit identifying coverage gaps and hardening opportunities.
- `docs/ROADMAP-001-19MAY2026-thoroughness-execution.md`: living, dated execution plan sequencing all REVIEW-001 items across 7 iterations (A–G) tied to MINOR release tags `v0.2.0`–`v0.8.0`.

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
