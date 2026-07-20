---
service: zookeeper
title: Apache ZooKeeper
ports: 2181, 2182, 2888, 3888
aliases: zookeeper
---

# ZooKeeper — quick wins

**When you see it:** 2181/tcp open and the `ruok` four-letter word returns `imok` → an
unauthenticated ZooKeeper. The 4LW commands leak config, environment, and connected clients,
and the znode tree (read with `zkCli`) stores the coordination data for Kafka, HBase, Solr,
and friends — frequently including connection strings and credentials.

> Authorized testing only. Triage is read-only. Writing/deleting znodes (marked ✏️) can
> disrupt the dependent cluster (Kafka/HBase brokers rely on this data) — read only unless
> sign-off explicitly covers znode mutation.

## Triage (read-only)
```sh
echo ruok | nc -w3 H 2181                 # "imok" = alive + 4LW enabled
echo stat | nc -w3 H 2181                 # version, clients, mode (leader/follower)
echo envi | nc -w3 H 2181                 # java + OS environment
echo conf | nc -w3 H 2181                 # server config (dataDir, tickTime, ports)
```

## Quick wins

### Four-letter-word recon
```sh
for c in ruok stat conf envi mntr cons dump wchp; do echo "== $c =="; echo $c | nc -w3 H 2181; done
```
*Why:* the 4LW set (when not restricted by `4lw.commands.whitelist`) discloses version,
config, environment, connected clients (`cons`), and outstanding sessions/ephemerals
(`dump`) — a complete picture of the ensemble and its consumers with zero auth.

### Walk the znode tree
```sh
zkCli.sh -server H:2181 ls /                 # top-level znodes
zkCli.sh -server H:2181 ls /kafka/brokers/ids
zkCli.sh -server H:2181 get /PATH            # read a znode's data
```
*Why:* the znode tree holds the coordination state for whatever uses it — `/kafka` broker
lists, `/hbase` master info, `/solr` cluster state — often with connection strings, and
sometimes SASL/JAAS credentials, stored in plaintext.

### Credential / connection-string hunting
```sh
zkCli.sh -server H:2181 ls -R / 2>/dev/null | grep -Ei "cred|user|pass|conn|jdbc|auth"
```
*Why:* application configs stashed in znodes routinely contain DB connection strings and
service credentials — grep the recursive listing, then `get` the promising paths.

## aranum helpers
- `aranumtoolkit/network/enum-zookeeper.sh` — dispatcher (4LW `ruok`/`mntr`/`srvr`/`conf`; flags `imok` reachability and config exposure).

## Gotchas
- ZooKeeper 3.5+ ships a `4lw.commands.whitelist` (default allows only `srvr`) — a hardened server answers `srvr` but not `envi`/`conf`/`dump`; `ruok`/`imok` still confirm reachability.
- `zkCli.sh` ships with ZooKeeper; `pip install kazoo` or `nc`-scripting works when it isn't installed locally.
- znodes are the live brain of Kafka/HBase/Solr clusters — a careless `delete`/`set` can knock brokers offline; treat writes as destructive.
- ZooKeeper auth (SASL/`DigestAuthenticationProvider`) is opt-in and often absent — read access with no creds is the common state.

## Sources
- ZooKeeper admin guide (four-letter words, `4lw.commands.whitelist`); HackTricks `2181-pentesting-zookeeper`; Kafka/ZooKeeper znode layout docs.
