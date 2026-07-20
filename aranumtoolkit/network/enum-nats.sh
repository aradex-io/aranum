#!/usr/bin/env bash
# enum-nats.sh — NATS messaging server enumeration.
#
# NATS (cloud-native message bus) frequently ships unauthenticated. The 8222
# monitoring endpoint's /varz leaks the FULL server config — including cluster
# routes and, when set, auth tokens/user lists — and 4222 returns a JSON INFO
# banner on raw connect. Both are read-only probes.
#
# READ-ONLY: GET on monitoring endpoints + a single INFO banner read. No publish.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "nats: $(wc -l < "$TARGETS") targets -> $OUT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"

    # 8222 (and TLS 8443-style variants) — HTTP monitoring endpoints.
    if have curl; then
        for scheme in http https; do
            base="${scheme}://${h}:${port}"
            code=$(curl -ksI --connect-timeout 5 --max-time 10 \
                        -o /dev/null -w '%{http_code}' "$base/varz" 2>/dev/null)
            [ "$code" = "000" ] && continue
            if [ "$code" = "200" ]; then
                for ep in varz connz routez subsz; do
                    curl -ks --connect-timeout 5 --max-time 10 "$base/$ep" \
                        > "$out_dir/${ep}_${scheme}.json" 2>/dev/null || true
                done
                if [ -s "$out_dir/varz_${scheme}.json" ] && grep -qi '"server_id"\|"version"' "$out_dir/varz_${scheme}.json"; then
                    err "CRITICAL: UNAUTH NATS monitoring $base/varz — full server config exposed"
                    # Surface whether auth is required at all.
                    if grep -qi '"auth_required":[[:space:]]*false' "$out_dir/varz_${scheme}.json"; then
                        err "CRITICAL: NATS auth_required=false on $h:$port — anonymous publish/subscribe"
                    fi
                fi
            fi
        done
    fi

    # 4222 client port — raw INFO banner (JSON) on connect (stdlib socket, no publish).
    if [ "$port" = "4222" ] && have python3; then
        python3 - "$ip" "$port" > "$out_dir/info_banner.txt" 2>/dev/null <<'PY' || true
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((ip, port), timeout=5)
    s.settimeout(5)
    data = s.recv(4096)
    sys.stdout.write(data.decode("ascii", "replace"))
    s.close()
except Exception:
    pass
PY
        if grep -qi '^INFO ' "$out_dir/info_banner.txt" 2>/dev/null; then
            hit "NATS INFO banner on $h:$port"
            grep -qi '"auth_required":[[:space:]]*false' "$out_dir/info_banner.txt" \
                && err "CRITICAL: NATS auth_required=false on $h:$port — anonymous access"
        fi
    fi
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
NATS follow-ups:
  * 8222 /varz exposes the complete server configuration (cluster routes,
    max_payload, and any configured auth). /connz + /routez enumerate live
    clients and cluster peers.
  * auth_required=false means anonymous SUB ">" receives every message on the
    bus and anonymous PUB can inject. Confirm with the `nats` CLI:
      nats --server nats://<ip>:4222 sub ">"
  * If tokens/creds appear in /varz, reuse them against the cluster routes.
EOF

log "nats dispatcher done."
