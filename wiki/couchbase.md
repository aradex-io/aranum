---
service: couchbase
title: Couchbase
ports: 8091
aliases: couchbase-mgmt, couchbase-console
---

# Couchbase — quick wins

**When you see it:** 8091/tcp open and `GET /pools` returns JSON with `implementationVersion` /
`"pools"` (no 401) → the management REST API is **unauthenticated**, leaking version and cluster
topology. The web console default `Administrator:password` is a common finish.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
curl -s http://H:8091/pools                    # version + "pools" array (200, no 401 = unauth)
curl -s http://H:8091/pools/default            # cluster topology: nodes, RAM, services
curl -s http://H:8091/pools/default/buckets    # bucket names + settings
```

## Quick wins

### Unauth mgmt API — version + topology
```sh
curl -s http://H:8091/pools | python3 -m json.tool
curl -s http://H:8091/pools/default | python3 -m json.tool
```
*Why:* `/pools` and `/pools/default` disclose Couchbase version, node addresses, RAM quotas, and which
services (data/query/index) run where — patch-level tell + full cluster map, no auth.

### Bucket enumeration → data ports
```sh
curl -s http://H:8091/pools/default/buckets | python3 -m json.tool | grep -E '"name"|saslPassword'
```
*Why:* lists buckets and their settings. From here the data path opens up — memcached (11210) and N1QL
(8093) may allow anonymous reads against the named buckets.

### Default console creds
```sh
curl -s -u Administrator:password http://H:8091/pools/default/buckets
```
*Why:* the admin account is created at setup; `Administrator:password` is a frequent leftover. A 200
(not 401) with creds = full cluster admin over the REST API and console.

## aranum helpers
- `aranumtoolkit/network/enum-couchbase.sh` — dispatcher (unauth `GET /pools`, `/pools/default`, `/pools/default/buckets`; flags version via `implementationVersion` when `/pools` is reachable).

## Gotchas
- A `401` on `/pools` means RBAC/auth is enforced — try `Administrator:password` and other setup defaults, then move on.
- Data lives on other ports: 11210 (KV/memcached), 8093 (N1QL/query), 18091 (TLS mgmt) — 8091 is just the control plane.
- Newer Couchbase forces a strong admin password at init, so defaults mostly land on older or lab clusters.

## Sources
- HackTricks Couchbase notes; Couchbase REST API (`/pools`) docs; aranum `enum-couchbase.sh` header.
