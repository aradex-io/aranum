#!/usr/bin/env bash
# enum-neo4j.sh — Neo4j graph database enumeration.
#
# Neo4j exposes:
#   7474 — HTTP REST API / Browser UI
#   7687 — Bolt binary protocol
#
# SAFETY: Default-credential check is GATED on ENUM_NEO4J_DEFAULT_CRED=1.
# Neo4j may lock accounts on repeated auth failures if lockout policy is set.
# Default is OFF — do not attempt without explicit operator opt-in.
#
# Notable CVE:
#   CVE-2021-34371 — Jexl RCE via Neo4j Browser (pre-4.4).
#   APOC plugin: apoc.load.json() for SSRF, apoc.export.* for file write.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "neo4j: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — neo4j dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- HTTP API (7474) ----------
    if [ "$port" = "7474" ]; then
        curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
            "http://$ip:$port/" \
            > "$OUT/$ip/root_${port}.txt" 2>&1 || true

        if grep -q '"neo4j_version"' "$OUT/$ip/root_${port}.txt" 2>/dev/null; then
            version=$(grep -oE '"neo4j_version"\s*:\s*"[^"]*"' \
                "$OUT/$ip/root_${port}.txt" | head -1 \
                | grep -oE '"[^"]*"$' | tr -d '"')
            hit "Neo4j HTTP API: $ip:$port — $version"
        fi

        # Unauth check via /db/data/
        curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
            "http://$ip:$port/db/data/" \
            > "$OUT/$ip/db_data_${port}.txt" 2>&1 || true

        if grep -q '"extensions"' "$OUT/$ip/db_data_${port}.txt" 2>/dev/null \
            && ! grep -qi 'unauthorized\|authentication\|forbidden' \
                "$OUT/$ip/db_data_${port}.txt" 2>/dev/null; then
            hit "Neo4j UNAUTH HTTP API: $ip:$port"
        fi

        # ---------- Default credential check (GATED) ----------
        if [ "${ENUM_NEO4J_DEFAULT_CRED:-0}" = "1" ]; then
            curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
                -u "neo4j:neo4j" \
                "http://$ip:$port/db/data/" \
                > "$OUT/$ip/default_cred_${port}.txt" 2>&1 || true

            if grep -q '"extensions"' "$OUT/$ip/default_cred_${port}.txt" 2>/dev/null \
                && ! grep -qi 'unauthorized\|authentication\|forbidden' \
                    "$OUT/$ip/default_cred_${port}.txt" 2>/dev/null; then
                hit "Neo4j DEFAULT CRED (neo4j/neo4j) WORKED: $ip:$port"
            fi
        else
            printf 'ENUM_NEO4J_DEFAULT_CRED unset — default-cred attempt skipped\n' \
                > "$OUT/$ip/default_cred_skipped.txt"
        fi
    fi

    # ---------- Bolt banner (7687) — banner only, no handshake ----------
    if [ "$port" = "7687" ]; then
        timeout 5 nc -nv -w 3 "$ip" "$port" < /dev/null \
            > "$OUT/$ip/bolt_banner_${port}.txt" 2>&1 || true
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Neo4j follow-ups:
  * Default cred check is OFF by default (would lock the account on failure
    if lockout policy is set). Re-run with:
      ENUM_NEO4J_DEFAULT_CRED=1 ./auto-enum.sh ...
  * APOC plugin enabled -> CALL apoc.load.json(...) for SSRF, apoc.export.*
    for arbitrary file write inside the import dir.
  * CVE-2021-34371 — Jexl RCE via Neo4j Browser (pre-4.4).
  * Cypher unauth: run queries via /db/data/cypher (old) or /db/neo4j/tx
    (4.x+). Example: {"query": "MATCH (n) RETURN n LIMIT 10"}
  * List all labels: MATCH (n) RETURN DISTINCT labels(n) LIMIT 50
  * List all relationship types: CALL db.relationshipTypes()
EOF

log "neo4j dispatcher done."
