#!/usr/bin/env bash
# enum-kafka.sh — Apache Kafka broker enumeration.
#
# Kafka listeners: 9092 (PLAINTEXT), 9093 (SSL/TLS).
# Unauthenticated brokers expose full topic metadata, partition assignments,
# consumer group offsets, and broker configs to any client with network access.
# kafkacat / kcat is the standard swiss-army tool for Kafka enumeration.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "kafka: $(wc -l < "$TARGETS") targets -> $OUT"

cat > "$OUT/_hints.txt" <<'EOF'
Kafka follow-ups:
  * Consume messages from a topic (last 50 messages):
      kcat -C -b <ip>:<port> -t <topic> -c 50
  * Full metadata as JSON (includes configs):
      kcat -L -J -b <ip>:<port>
  * List consumer groups (requires kafka-consumer-groups.sh or kcat):
      kcat -L -b <ip>:<port> | grep 'consumer'
  * TLS listener (9093) — add:
      -X security.protocol=ssl -X enable.ssl.certificate.verification=false
  * Sensitive topics to look for: __consumer_offsets, connect-*, _schemas
    (Schema Registry), transaction state, application-specific names.
  * If SASL is configured, kcat returns auth errors — note the SASL mechanism
    from the error message (PLAIN, SCRAM-SHA-256, GSSAPI).
EOF

# Detect available tool — Debian/Ubuntu ship 'kafkacat', Fedora ships 'kcat'
KCAT=""
if have kcat; then
    KCAT="kcat"
elif have kafkacat; then
    KCAT="kafkacat"
else
    miss "neither kcat nor kafkacat installed — kafka dispatcher cannot probe"
    log "kafka dispatcher done."
    exit 0
fi
log "kafka: using $KCAT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- broker metadata ----------
    if [ "$port" = "9093" ]; then
        # TLS listener — disable cert verification for enumeration
        timeout 10 "$KCAT" -L -b "$ip:$port" \
            -X security.protocol=ssl \
            -X enable.ssl.certificate.verification=false \
            > "$OUT/$ip/metadata_${port}.txt" 2>&1 || true
    else
        timeout 10 "$KCAT" -L -b "$ip:$port" \
            > "$OUT/$ip/metadata_${port}.txt" 2>&1 || true
    fi

    # ---------- parse results ----------
    meta_file="$OUT/$ip/metadata_${port}.txt"
    if grep -q 'Metadata for all topics' "$meta_file" 2>/dev/null \
        && grep -q ' topic ' "$meta_file" 2>/dev/null; then
        hit "Kafka UNAUTH broker: $ip:$port"
        topic_count=$(grep -c ' topic ' "$meta_file" 2>/dev/null || echo 0)
        if [ "$topic_count" -ge 1 ]; then
            hit "Kafka topics exposed: $ip:$port — $topic_count topics"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

log "kafka dispatcher done."
