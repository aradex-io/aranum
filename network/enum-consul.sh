#!/usr/bin/env bash
# enum-consul.sh — HashiCorp Consul enumeration.
#
# Consul HTTP API on port 8500 (plaintext) / 8501 (TLS).
# Without ACLs, the entire KV store, service catalog, and agent config
# are accessible unauthenticated — common in internal Kubernetes deployments.
# KV store often contains TLS certs, application secrets, DB credentials.
#
# Notable CVE:
#   CVE-2020-7955 — mTLS bypass via hostname handling in Consul service mesh.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "consul: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

if ! have curl; then
    miss "curl not installed — consul dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # Use HTTPS for port 8501, HTTP otherwise
    scheme="http"
    [ "$port" = "8501" ] && scheme="https"
    base="${scheme}://${ip}:${port}"

    # ---------- agent self ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        "$base/v1/agent/self" \
        > "$OUT/$ip/agent_self_${port}.txt" 2>&1 || true

    if grep -q '"Config"' "$OUT/$ip/agent_self_${port}.txt" 2>/dev/null; then
        hit "Consul UNAUTH agent API: $ip:$port"
        version=$(grep -oE '"Version"\s*:\s*"[^"]*"' \
            "$OUT/$ip/agent_self_${port}.txt" | head -1 \
            | grep -oE '"[^"]*"$' | tr -d '"')
        [ -n "$version" ] && log "  Consul version: $version"
    fi

    # ---------- KV dump ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        "$base/v1/kv/?recurse" \
        > "$OUT/$ip/kv_dump_${port}.txt" 2>&1 || true

    kv_first=$(head -c 1 "$OUT/$ip/kv_dump_${port}.txt" 2>/dev/null || true)
    if [ "$kv_first" = "[" ]; then
        hit "Consul UNAUTH KV dump (HIGH-VALUE): $ip:$port"
    fi

    # ---------- service catalog ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        "$base/v1/catalog/services" \
        > "$OUT/$ip/catalog_services_${port}.txt" 2>&1 || true

    # ---------- ACL state probe ----------
    curl -ks "${CURL_ARGS[@]}" --max-time 8 \
        "$base/v1/acl/list" \
        > "$OUT/$ip/acl_list_${port}.txt" 2>&1 || true

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Consul follow-ups:
  * Read a specific KV entry (raw value):
      curl http://<ip>:8500/v1/kv/<key>?raw
  * Recurse from a prefix:
      curl "http://<ip>:8500/v1/kv/<prefix>?recurse"
  * KV values are base64-encoded in the JSON response — decode with:
      python3 -c "import base64,json,sys; [print(base64.b64decode(k['Value']).decode(errors='replace')) for k in json.load(sys.stdin)]"
  * Service catalog:
      curl http://<ip>:8500/v1/catalog/services
      curl http://<ip>:8500/v1/catalog/service/<name>
  * CVE-2020-7955 — mTLS bypass via crafted SNI in service mesh.
  * If ACL token required, check KV dump for bootstrap-token or mgmt-token keys.
EOF

log "consul dispatcher done."
