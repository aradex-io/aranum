#!/usr/bin/env bash
# enum-elastic.sh — Elasticsearch + Kibana enumeration.
#
# Common findings:
#   * Unauth /_cluster/state, /_cat/indices, /_search?q=password*
#   * Snapshot/restore RCE chain (CVE-2014-3120 era + variants)
#   * Kibana 5601 default-no-auth in lab installs leaked to prod
#
# Phases:
#   1. /_cluster/health + /_cluster/state (unauth)
#   2. /_cat/indices?v (size + doc count per index)
#   3. /_search?q=password* — credential leak signal
#   4. Kibana 5601 alive check
#   5. Authenticated recon if creds present
#
# READ-ONLY. No PUT/POST/DELETE.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "elastic: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — elastic dispatcher cannot probe"
    exit 0
fi

# Build URL list — try both http and https on each port.
URLS=$(mktemp)
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    case "$port" in
        9200|9300) printf "http://%s:%s\nhttps://%s:%s\n" "$h" "$port" "$h" "$port" ;;
        5601)      printf "http://%s:%s\nhttps://%s:%s\n" "$h" "$port" "$h" "$port" ;;
        *)         printf "http://%s:%s\nhttps://%s:%s\n" "$h" "$port" "$h" "$port" ;;
    esac
done < "$TARGETS" | sort -u > "$URLS"

while read -r url; do
    [ -z "$url" ] && continue
    safe=$(echo "$url" | sed 's|[:/]|_|g')
    out_dir="$OUT/$safe"; mkdir -p "$out_dir"

    # Auth header if creds present
    AUTH=()
    [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && AUTH=(-u "${ENUM_USER}:${ENUM_PASS}")

    # ---------- alive check + version ----------
    code=$(curl -ksI "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                -o /dev/null -w '%{http_code}' "$url/" 2>/dev/null)
    [ "$code" = "000" ] && continue
    curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 10 "$url/" \
        > "$out_dir/root.json" 2>/dev/null || true

    # ---------- ES probes (9200ish endpoints) ----------
    for path in "_cluster/health" "_cluster/state" "_cat/indices?v" \
                "_cat/nodes?v" "_security/user" "_xpack/security"; do
        safe_p=$(echo "$path" | sed 's|[/?&]|_|g')
        full="$url/$path"
        code=$(curl -ksI "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                    -o /dev/null -w '%{http_code}' "$full" 2>/dev/null)
        [ "$code" = "000" ] && continue
        if [ "$code" = "200" ]; then
            curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 15 "$full" \
                > "$out_dir/${safe_p}.txt" 2>/dev/null || true
            case "$path" in
                "_cluster/state"|"_cat/indices?v")
                    if [ -z "${ENUM_USER:-}" ]; then
                        hit "UNAUTH ${url} -> ${path}"
                    fi ;;
            esac
        fi
    done

    # ---------- credential-grep _search ----------
    for q in "password" "passwd" "secret" "api_key" "token"; do
        code=$(curl -ksI "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                    -o /dev/null -w '%{http_code}' "$url/_search?q=$q*&size=5" 2>/dev/null)
        if [ "$code" = "200" ]; then
            curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 15 \
                "$url/_search?q=$q*&size=5" \
                > "$out_dir/search_${q}.json" 2>/dev/null || true
            hits=$(python3 -c "
import json
try:
    d=json.load(open('$out_dir/search_${q}.json'))
    print(d.get('hits',{}).get('total',{}).get('value', d.get('hits',{}).get('total','?')))
except Exception: print('?')" 2>/dev/null)
            [ "$hits" != "0" ] && [ "$hits" != "?" ] && \
                hit "POTENTIAL CRED LEAK at $url/_search?q=$q* -> $hits hits"
        fi
    done

    # ---------- Kibana detection ----------
    body=$(curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                "$url/api/status" 2>/dev/null)
    if echo "$body" | grep -qi 'kibana\|elasticsearch'; then
        echo "$body" > "$out_dir/kibana_status.json"
        hit "KIBANA API responds at $url/api/status"
    fi
done < "$URLS"

rm -f "$URLS"

cat > "$OUT/_hints.txt" <<'EOF'
Elasticsearch hints:
  * If _cluster/state or _cat/indices is unauth -> full data inventory.
  * _search?q=password* / token* / api_key* is the cheap credential-leak sweep.
  * _snapshot/_register + restore was the historical RCE path; modern X-Pack
    blocks the local-FS repository. Worth checking what registered repos exist.
  * Kibana 5601 with default kibana_system/kibanaserver and a writable
    saved-objects API = vector for cross-account dashboard injection.
EOF

log "elastic dispatcher done."
