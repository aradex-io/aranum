---
service: kafka
title: Apache Kafka
ports: 9092, 9093
aliases: kafka-broker
---

# Kafka — quick wins

**When you see it:** 9092/tcp open and `kcat -L -b H:9092` returns broker metadata without
auth → a `PLAINTEXT` listener with no SASL. You can list every topic and consume messages —
Kafka topics carry inter-service events, PII, and sometimes credentials in the payloads.

> Authorized testing only. Triage is read-only. Consuming (`kcat -C`) reads messages; steps
> marked ✏️ produce to a topic — get sign-off before publishing.

## Triage (read-only)
```sh
kcat -L -b H:9092                          # broker + topic/partition metadata (no auth = open)
kcat -L -J -b H:9092                        # same, JSON
kcat -L -b H:9093 -X security.protocol=SSL  # TLS listener variant
nmap -sV -p 9092,9093 H
```

## Quick wins

### List topics and partitions
```sh
kcat -L -b H:9092 | grep -E "topic|broker"
```
*Why:* the metadata request needs no auth on a `PLAINTEXT` listener and reveals every topic,
partition count, and broker in the cluster — the map of what data flows through and which
other brokers to target.

### Consume messages from a topic
```sh
kcat -C -b H:9092 -t TOPIC -o beginning -c 50 -e
```
*Why:* `-o beginning -c 50` reads the first 50 messages of a topic; event streams frequently
contain user records, auth tokens passed between services, and internal API payloads.

### Produce / inject a message ✏️
```sh
echo '{"test":"aranum"}' | kcat -P -b H:9092 -t TOPIC
```
*Why:* if the listener allows writes, you can inject events that downstream consumers act on —
a data-integrity / logic-abuse primitive. Do this only with explicit sign-off.

### Check SASL mechanism on a secured listener
```sh
kcat -L -b H:9092 -X security.protocol=SASL_PLAINTEXT -X sasl.mechanism=PLAIN \
     -X sasl.username=test -X sasl.password=test
```
*Why:* the auth error names the required SASL mechanism (PLAIN/SCRAM/GSSAPI) → tells you
whether a credential spray or Kerberos ticket is the way in.

## aranum helpers
- `aranumtoolkit/network/enum-kafka.sh` — dispatcher (`kcat`/`kafkacat` broker metadata, topic count, TLS variant for 9093).

## Gotchas
- `kcat` (formerly `kafkacat`) is required — the dispatcher no-ops without it.
- Advertised listeners matter: the broker may return internal hostnames in metadata that don't resolve from your position — map them via `/etc/hosts` or target the advertised IP.
- A broker can expose PLAINTEXT (9092) and SSL/SASL_SSL (9093) simultaneously — always test the plaintext port first.
- ZooKeeper (2181) often backs older Kafka clusters and stores config/ACLs unauthenticated — see `wiki/zookeeper.md`.

## Sources
- `kcat` (edenhill) README; HackTricks `9092-pentesting-kafka`; Apache Kafka protocol/security docs.
