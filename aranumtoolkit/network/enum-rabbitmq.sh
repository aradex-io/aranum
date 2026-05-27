#!/usr/bin/env bash
# enum-rabbitmq.sh — RabbitMQ management API enumeration.
#
# guest/guest is the historical default; bound to 127.0.0.1 by default since
# ~3.6 but routinely re-exposed by misconfig. The mgmt API (15672) reveals
# users, vhosts, queues, exchanges, and (if admin) bindings/policies.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "rabbitmq: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — rabbitmq dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"
    scheme="http"; [ "$port" = "15671" ] && scheme="https"
    base="${scheme}://${h}:${port}"

    # ---------- 1. Default guest/guest probe ----------
    code=$(curl -ksI -u 'guest:guest' --connect-timeout 5 --max-time 10 \
                -o /dev/null -w '%{http_code}' "$base/api/overview" 2>/dev/null)
    [ "$code" = "000" ] && continue
    if [ "$code" = "200" ]; then
        err "CRITICAL: RabbitMQ $base/api/overview returns 200 with guest/guest"
        for ep in api/overview api/users api/vhosts api/exchanges api/queues \
                  api/connections api/channels api/permissions; do
            safe=$(echo "$ep" | sed 's|/|_|g')
            curl -ks -u 'guest:guest' --connect-timeout 5 --max-time 15 \
                "$base/$ep" > "$out_dir/guest_${safe}.json" 2>/dev/null || true
        done
    fi

    # ---------- 2. Auth probe with operator-supplied creds ----------
    if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
        code=$(curl -ksI -u "${ENUM_USER}:${ENUM_PASS}" \
                    --connect-timeout 5 --max-time 10 \
                    -o /dev/null -w '%{http_code}' "$base/api/overview" 2>/dev/null)
        if [ "$code" = "200" ]; then
            hit "RabbitMQ AUTH OK: $base with ${ENUM_USER}"
            for ep in api/overview api/users api/vhosts api/exchanges api/queues; do
                safe=$(echo "$ep" | sed 's|/|_|g')
                curl -ks -u "${ENUM_USER}:${ENUM_PASS}" \
                    --connect-timeout 5 --max-time 15 \
                    "$base/$ep" > "$out_dir/auth_${safe}.json" 2>/dev/null || true
            done
        fi
    fi
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
RabbitMQ follow-ups:
  * guest/guest: depends on management plugin permissions. If you can read
    /api/users hashes (hashes are not reversible directly but enable targeted
    cred-spray against other systems).
  * If you have admin role, /api/exchanges/<vhost>/<exchange>/publish lets you
    inject messages — useful for downstream consumer compromise.
  * AMQP port 5672 binary protocol is separate from mgmt — direct AMQP cred
    spray possible with rabbitmqctl or pika-based scripts (not bundled here).
EOF

log "rabbitmq dispatcher done."
