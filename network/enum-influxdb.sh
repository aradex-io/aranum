#!/usr/bin/env bash
# enum-influxdb.sh — InfluxDB time-series database enumeration.
#
# InfluxDB HTTP API:
#   8086 — primary HTTP API (InfluxDB 1.x and 2.x)
#   8088 — RPC service port (InfluxDB 1.x backup/restore)
#
# InfluxDB 1.x without authentication enabled accepts any query — all
# databases, measurements, and time-series data are world-readable.
#
# Notable CVE:
#   CVE-2019-20933 — JWT authentication bypass in InfluxDB 1.x when
#   shared_secret is unset. Unsigned JWT tokens accepted as valid.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "influxdb: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

if ! have curl; then
    miss "curl not installed — influxdb dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- ping (version header) ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        -D - "http://$ip:$port/ping" -o /dev/null \
        > "$OUT/$ip/ping_${port}.txt" 2>&1 || true

    if grep -qi 'X-Influxdb-Version:' "$OUT/$ip/ping_${port}.txt" 2>/dev/null; then
        version=$(grep -i 'X-Influxdb-Version:' "$OUT/$ip/ping_${port}.txt" \
            | head -1 | sed 's/.*X-Influxdb-Version:[[:space:]]*//' | tr -d '\r')
        hit "InfluxDB reachable: $ip:$port — $version"
    fi

    # ---------- unauth query API ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        "http://$ip:$port/query?q=SHOW+DATABASES&pretty=true" \
        > "$OUT/$ip/databases_${port}.txt" 2>&1 || true

    if grep -q '"results"' "$OUT/$ip/databases_${port}.txt" 2>/dev/null \
        && grep -q '"series"' "$OUT/$ip/databases_${port}.txt" 2>/dev/null; then
        hit "InfluxDB UNAUTH query API: $ip:$port"
    fi

    # ---------- debug vars (runtime stats) ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        "http://$ip:$port/debug/vars" \
        > "$OUT/$ip/debug_vars_${port}.txt" 2>&1 || true

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
InfluxDB follow-ups:
  * List measurements in a database:
      curl "http://<ip>:8086/query?db=<dbname>&q=SHOW+MEASUREMENTS"
  * Dump all data from a measurement:
      curl "http://<ip>:8086/query?db=<db>&q=SELECT+*+FROM+<measurement>+LIMIT+50"
  * CVE-2019-20933 JWT bypass (InfluxDB 1.x with shared_secret unset):
      Use an unsigned JWT token (alg=none) — many older InfluxDB deployments
      accept it, granting full read/write access.
  * debug/vars endpoint leaks Go runtime stats, goroutine counts, build info.
  * InfluxDB 2.x (port 8086) uses token auth by default — check /api/v2/setup
    to determine if initial setup is complete.
EOF

log "influxdb dispatcher done."
