#!/usr/bin/env bash
# enum-zookeeper.sh — Apache ZooKeeper enumeration.
#
# ZooKeeper 4-letter word (4LW) commands expose cluster internals unauthenticated.
# ZK 3.5+ requires `4lw.commands.whitelist=*` in zoo.cfg to enable them.
# Common uses: Kafka, HBase, Storm, Hadoop coordination.
# Service discovery paths often leak microservice registries, Kafka broker lists,
# and HBase master addresses.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "zookeeper: $(wc -l < "$TARGETS") targets -> $OUT"

cat > "$OUT/_hints.txt" <<'EOF'
Zookeeper 4LW follow-ups:
  * ACL audit — connect with zkCli.sh then:
      get /
      getAcl /<znode>
  * Common HIGH-VALUE paths:
      /services      — microservice registry (Consul-on-ZK, Finagle, etc.)
      /kafka         — Kafka broker coordinates, topic configs, consumer offsets
      /hbase         — HBase master address, region server assignments
      /storm         — Storm nimbus + supervisor assignments
  * If 4LW is blocked (empty responses) but ruok=imok, the ZK node is
    reachable but whitelist is restricted — try /admin HTTP endpoint
    (default: http://<ip>:8080/commands) which ZK 3.5+ also exposes.
EOF

if ! have nc; then
    miss "nc not installed — zookeeper dispatcher cannot probe"
    log "zookeeper dispatcher done."
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- 4-letter word commands ----------
    for cmd in ruok mntr srvr conf stat wchs dump cons; do
        printf '%s' "$cmd" | timeout 5 nc -nv -w 3 "$ip" "$port" \
            > "$OUT/$ip/zk_${cmd}_${port}.txt" 2>/dev/null || true
    done

    # ---------- analyse results ----------
    if grep -q 'imok' "$OUT/$ip/zk_ruok_${port}.txt" 2>/dev/null; then
        hit "Zookeeper reachable: $ip:$port (ruok=imok)"
    fi

    mntr_file="$OUT/$ip/zk_mntr_${port}.txt"
    if [ -s "$mntr_file" ] && grep -q 'zk_' "$mntr_file" 2>/dev/null; then
        hit "Zookeeper 4LW exposed: $ip:$port — 4lw.commands.whitelist=*"
    fi

    conf_file="$OUT/$ip/zk_conf_${port}.txt"
    if grep -q 'dataDir' "$conf_file" 2>/dev/null; then
        hit "Zookeeper config exposed (HIGH-VALUE): $ip:$port"
    fi

    throttle_sleep
done < "$TARGETS"

log "zookeeper dispatcher done."
