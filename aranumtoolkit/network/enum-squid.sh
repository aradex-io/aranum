#!/usr/bin/env bash
# enum-squid.sh — Squid / open forward proxy (3128, 8080) test.
# READ-ONLY: a CONNECT/absolute-URI request through the proxy to a benign
# controllable host confirms open-proxy = internal pivot. Uses --proxy-target.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
# operator supplies a reachable external URL they control/trust; default is a
# well-known noop endpoint. Set ENUM_PROXY_TEST_URL to override.
TEST_URL="${ENUM_PROXY_TEST_URL:-http://example.com/}"
log "squid: $(wc -l < "$TARGETS") targets -> $OUT (test url: $TEST_URL)"
have curl || { miss "curl not installed — squid dispatcher cannot probe"; exit 0; }
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; mkdir -p "$OUT/$ip"
    out="$OUT/$ip/squid_${port}.txt"
    code=$(curl -s -o "$out" -w '%{http_code}' --connect-timeout 6 --max-time 15 \
           -x "http://$ip:$port" "$TEST_URL" 2>/dev/null)
    hdr=$(head -1 "$out" 2>/dev/null)
    printf 'proxy=%s:%s test_url=%s http_code=%s\nfirst_line=%s\n' "$ip" "$port" "$TEST_URL" "$code" "$hdr" >> "$out"
    if [ "$code" = "200" ] || grep -qiE 'via:.*squid|X-Cache' "$out" 2>/dev/null; then
        crit "OPEN PROXY: $ip:$port forwarded a request to $TEST_URL — internal pivot"
    elif grep -qiE 'Access Denied|X-Squid-Error|403' "$out" 2>/dev/null; then
        hit "Squid present but ACL-restricted at $ip:$port"
    fi
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

Squid / open-proxy follow-ups:
  * If open: curl -x http://<ip>:<port> http://<internal-host>/ to reach the
    internal network. cachemgr (`curl -x ... http://<ip>/squid-internal-mgr/`)
    may leak config/peers.
EOF
log "squid dispatcher done."
