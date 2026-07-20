#!/usr/bin/env bash
# enum-couchbase.sh — Couchbase (8091 mgmt) unauth info.
# READ-ONLY: GET /pools + /pools/default leak version/topology when unauth.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "couchbase: $(wc -l < "$TARGETS") targets -> $OUT"
have curl || { miss "curl not installed — couchbase dispatcher cannot probe"; exit 0; }
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"; mkdir -p "$OUT/${ip}_${port}"
    d="$OUT/${ip}_${port}"
    for ep in pools pools/default pools/default/buckets; do
        curl -ks --connect-timeout 6 --max-time 12 "http://$h:$port/$ep" > "$d/${ep//\//_}.json" 2>/dev/null || true
    done
    if grep -qiE 'implementationVersion|clusterCompatibility|"pools"' "$d/pools.json" 2>/dev/null; then
        ver=$(grep -oE '"implementationVersion":"[^"]+"' "$d/pools.json" | head -1)
        crit "UNAUTH Couchbase mgmt: $ip:$port — /pools reachable ($ver)"
    fi
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

Couchbase follow-ups:
  * Unauth /pools/default/buckets lists buckets; the memcached/N1QL ports (11210/
    8093) may allow anonymous data access. Default admin cred is set at setup —
    try Administrator:password on the console.
EOF
log "couchbase dispatcher done."
