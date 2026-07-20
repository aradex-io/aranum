---
service: rethinkdb
title: RethinkDB
ports: 28015, 8080
aliases: rethinkdb-driver, rethinkdb-admin
---

# RethinkDB — quick wins

**When you see it:** the admin UI on 8080 loads with no login, or the driver port 28015 answers the
V0_4 handshake with `SUCCESS` → **no auth**. Either one is full read/write over the whole cluster (the
web Data Explorer runs arbitrary ReQL).

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
curl -s http://H:8080/ | grep -i rethinkdb     # admin UI served with no auth
# driver handshake (28015): V0_4 magic → "SUCCESS" means auth disabled
python3 -c 'import socket,struct; s=socket.create_connection(("H",28015),5); s.sendall(struct.pack("<I",0x34c2bdc3)); print(s.recv(256))'
```

## Quick wins

### Unauth admin UI → Data Explorer
```sh
# browse to http://H:8080/  →  Data Explorer tab
r.db_list()
r.db('DBNAME').table_list()
```
*Why:* the console with no login gives the Data Explorer, which runs arbitrary ReQL — list databases,
read every table, and write/drop at will. Full data compromise from a browser.

### Driver-port access (28015)
```sh
python3 -c 'import socket,struct; s=socket.create_connection(("H",28015),5); s.sendall(struct.pack("<I",0x34c2bdc3)); print(s.recv(256))'
# SUCCESS → connect with any RethinkDB client and: r.db_list().run(conn)
```
*Why:* a `SUCCESS` handshake means the driver accepts unauthenticated connections — any client
(`rethinkdb` Python/JS driver) can then read and write every table programmatically.

## aranum helpers
- `aranumtoolkit/network/enum-rethinkdb.sh` — dispatcher (driver-port V0_4 handshake on 28015/29015 → flags on `SUCCESS`; admin UI probe on 8080 → flags when the page contains `RethinkDB`).

## Gotchas
- Newer RethinkDB (2.3+) supports an admin password / user accounts — a handshake that doesn't return `SUCCESS`, or a UI that prompts for login, means auth is on.
- 28015 = client driver, 29015 = intra-cluster; a leaked 29015 lets a rogue node join the cluster.
- The admin UI is often bound to loopback in hardened setups — reachable 8080 usually means it was deliberately exposed.

## Sources
- HackTricks `28015-29015-pentesting-rethinkdb`; RethinkDB security / driver-protocol docs; aranum `enum-rethinkdb.sh` header.
