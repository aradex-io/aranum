---
service: squid
title: Squid / open proxy
ports: 3128, 8080
aliases: squid-http, forward-proxy
---

# Squid / open proxy — quick wins

**When you see it:** 3128/tcp open and `curl -x http://H:3128 http://example.com/` returns `200` with a
`Via: ... squid` / `X-Cache` header → an **open forward proxy**. That's a pivot into whatever network
the proxy can reach.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
curl -sI -x http://H:3128 http://example.com/ | head    # 200 + Via/X-Cache = open
curl -s  -x http://H:3128 http://example.com/ -o /dev/null -w '%{http_code}\n'
```

## Quick wins

### Confirm open forward proxy
```sh
curl -s -x http://H:3128 http://example.com/ | head
```
*Why:* a benign external URL that comes back through the proxy (200 + `Via: squid`) proves it forwards
for you. `Access Denied`/`X-Squid-Error`/403 = ACL-restricted — present but locked down.

### Pivot to internal resources — **sensitive**
```sh
curl -s -x http://H:3128 http://INTERNAL-HOST/         # reach RFC1918 / internal-only hosts
curl -s -x http://H:3128 http://169.254.169.254/latest/meta-data/   # cloud metadata, if reachable
```
*Why:* the proxy resolves and fetches from *its* network position — internal web apps, admin panels,
and cloud metadata endpoints you can't reach directly. Treat any internal fetch as sensitive; scope and
log it, get sign-off before ranging.

### cachemgr config leak
```sh
curl -s -x http://H:3128 http://H/squid-internal-mgr/menu
curl -s -x http://H:3128 http://H/squid-internal-mgr/config
```
*Why:* the Squid cache manager can expose the running config, peers, and ACLs if not restricted —
maps the internal topology behind the proxy.

## aranum helpers
- `aranumtoolkit/network/enum-squid.sh` — dispatcher (proxies a request to `ENUM_PROXY_TEST_URL` (default `http://example.com/`); `200`/`Via: squid`/`X-Cache` = open pivot, `Access Denied`/403 = ACL-restricted).

## Gotchas
- Set `ENUM_PROXY_TEST_URL` to a host **you control/trust** — the probe egresses through the target.
- ACL-restricted proxies still often allow `CONNECT` to specific ports, or leak via `cachemgr` — check both.
- 8080 is shared by many services (Tomcat, generic HTTP); confirm it's actually Squid via the `Via`/`Server` header before treating it as a proxy.

## Sources
- HackTricks `3128-pentesting-squid`; Squid cachemgr docs; aranum `enum-squid.sh` header.
