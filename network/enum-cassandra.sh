#!/usr/bin/env bash
# enum-cassandra.sh — Apache Cassandra enumeration.
#
# Cassandra native transport (CQL) on 9042; Thrift legacy on 9160.
# Unauthenticated CQL access is the default in many configurations — any
# client can read all keyspaces without credentials.
# Default credential: cassandra / cassandra.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "cassandra: $(wc -l < "$TARGETS") targets -> $OUT"

cat > "$OUT/_hints.txt" <<'EOF'
Cassandra follow-ups:
  * List all keyspaces (CQL):
      DESCRIBE KEYSPACES;
  * List tables in a keyspace:
      DESCRIBE TABLES;   -- (after USE <keyspace>)
  * Sample table data:
      SELECT * FROM <keyspace>.<table> LIMIT 50;
  * Default cred shortlist: cassandra/cassandra
  * cassandra-brute nmap script runs automatically above — check
    cassandra_<port>.txt for credential results.
  * Thrift port 9160 (legacy): use cassandra-py or thrift clients;
    mostly deprecated in Cassandra 4.x.
EOF

if ! have nmap; then
    miss "nmap not installed — cassandra dispatcher cannot probe"
    log "cassandra dispatcher done."
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- nmap scripts ----------
    nmap -sT -p "$port" \
        --script cassandra-info,cassandra-brute \
        --script-timeout 30 \
        $(throttle_nmap_args) \
        "$ip" \
        -oN "$OUT/$ip/cassandra_${port}.txt" 2>/dev/null || true

    # ---------- parse cluster info ----------
    if grep -qi 'cluster:' "$OUT/$ip/cassandra_${port}.txt" 2>/dev/null; then
        cluster=$(grep -i 'cluster:' "$OUT/$ip/cassandra_${port}.txt" \
            | head -1 | sed 's/.*cluster:[[:space:]]*//' | tr -d '\r')
        hit "Cassandra cluster info exposed: $ip:$port — $cluster"
    fi

    # ---------- cqlsh anonymous query (optional) ----------
    if have cqlsh; then
        timeout 8 cqlsh "$ip" "$port" \
            -e "SELECT cluster_name, release_version FROM system.local;" \
            > "$OUT/$ip/cqlsh_version_${port}.txt" 2>&1 || true

        if [ -s "$OUT/$ip/cqlsh_version_${port}.txt" ] \
            && ! grep -qi 'AuthenticationFailed\|Connection error\|Unable to connect' \
                "$OUT/$ip/cqlsh_version_${port}.txt" 2>/dev/null \
            && grep -q '|' "$OUT/$ip/cqlsh_version_${port}.txt" 2>/dev/null; then
            hit "Cassandra UNAUTH CQL: $ip:$port"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

log "cassandra dispatcher done."
