#!/usr/bin/env bash
# enum-mqtt.sh — MQTT broker enumeration (ports 1883, 8883).
#
# MQTT brokers without authentication allow any client to subscribe to
# ALL topics ("#") including $SYS/# which exposes broker version, connected
# client counts, and operational statistics. Permissive ACLs mean attackers
# can also publish to operational OT/IoT topics.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "mqtt: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have mosquitto_sub; then
    miss "mosquitto_sub not installed — mqtt dispatcher cannot probe (install: mosquitto-clients)"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- subscribe to $SYS/# ----------
    rc=0
    if [ "$port" = "8883" ]; then
        # MQTT over TLS
        timeout 8 mosquitto_sub \
            -h "$ip" -p "$port" \
            -t '$SYS/#' -W 5 -C 50 \
            --tls-version tlsv1.2 --insecure \
            > "$OUT/$ip/sys_topics_${port}.txt" 2>&1 || rc=$?
    else
        # Plain MQTT
        timeout 8 mosquitto_sub \
            -h "$ip" -p "$port" \
            -t '$SYS/#' -W 5 -C 50 \
            > "$OUT/$ip/sys_topics_${port}.txt" 2>&1 || rc=$?
    fi

    # rc 0 = normal exit (got messages + time ran out cleanly)
    # rc 27 = timeout-after-success (mosquitto_sub internal timeout hit — treat as success)
    # rc 5 = auth required
    # rc 14 = host unreachable / connection refused
    if { [ "$rc" -eq 0 ] || [ "$rc" -eq 27 ]; } && \
       [ -s "$OUT/$ip/sys_topics_${port}.txt" ]; then
        hit "MQTT UNAUTH broker: $ip:$port"

        # ---------- record broker version if available ----------
        if grep -q '\$SYS/broker/version' "$OUT/$ip/sys_topics_${port}.txt" 2>/dev/null; then
            version_line=$(grep '\$SYS/broker/version' "$OUT/$ip/sys_topics_${port}.txt" | head -1)
            hit "MQTT broker version: $ip:$port — $version_line"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
MQTT follow-ups:
  * Subscribe to all topics (full traffic capture):
    mosquitto_sub -h <ip> -p 1883 -t '#' -v
  * WARNING: do NOT publish to operational topics without explicit operator
    authorization. Publishing to an OT/ICS control topic (e.g. a setpoint
    or relay command) can cause physical harm.
  * Publish to a test topic (authorized lab only):
    mosquitto_pub -h <ip> -p 1883 -t 'test/aranum' -m 'probe'
  * Interesting $SYS topics: $SYS/broker/clients/connected,
    $SYS/broker/messages/received, $SYS/broker/subscriptions/count
  * Check broker ACL config: if no auth + no ACL -> any client reads/writes
    any topic. Flag as critical in OT/ICS environments.
  * MQTT over TLS (8883): check cert validity + cipher suite via
    openssl s_client -connect <ip>:8883
EOF

log "mqtt dispatcher done."
