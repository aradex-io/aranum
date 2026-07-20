#!/usr/bin/env bash
# enum-redis.sh — Redis enumeration: reachability class, version→CVE, TLS, Sentinel.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "redis: $(wc -l < "$TARGETS") targets -> $OUT"

# Raw Redis command over /dev/tcp (portable; no nc/redis-cli dependency).
raw_redis() {
    local ip="$1" port="$2" cmd="$3"
    exec 3<>"/dev/tcp/$ip/$port" 2>/dev/null || return 1
    printf '%b\r\n' "$cmd" >&3
    timeout 5 cat <&3 2>/dev/null
    exec 3>&- 3<&- 2>/dev/null || true
}

# Emit CVE-2022-0543 (Debian/Ubuntu Lua sandbox escape → unauth RCE) signal.
cve_2022_0543() {
    local info="$1" ip="$2" port="$3"
    local os ver
    os=$(grep -oiE '^os:[^\r]*' "$info" 2>/dev/null | head -1)
    ver=$(grep -oiE 'redis_version:[0-9.]+' "$info" 2>/dev/null | head -1)
    if printf '%s' "$os" | grep -qiE 'debian|ubuntu'; then
        crit "CVE-2022-0543 candidate: $ip:$port ($ver on ${os#os:}) — Debian/Ubuntu Lua sandbox escape (unauth RCE)"
    fi
}

classify() {
    local ip="$1" port="$2" info="$3"
    if grep -qiE 'redis_version:' "$info" 2>/dev/null; then
        local ver role
        ver=$(grep -oiE 'redis_version:[0-9.]+' "$info" | head -1)
        role=$(grep -oiE '^role:[a-z]+' "$info" | head -1)
        crit "UNAUTH Redis $ip:$port — $ver ${role:-role:?} (no auth required)"
        cve_2022_0543 "$info" "$ip" "$port"
    elif grep -qiE 'NOAUTH|Authentication required' "$info" 2>/dev/null; then
        hit "Redis at $ip:$port requires AUTH (NOAUTH) — spray or move on"
    elif grep -qiE 'WRONGPASS|no permission|NOPERM|ACL' "$info" 2>/dev/null; then
        hit "Redis at $ip:$port is ACL-restricted for this identity"
    fi
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    info="$OUT/$ip/info_${port}.txt"

    if have redis-cli; then
        redis-cli -h "$ip" -p "$port" -t 5 INFO > "$info" 2>&1 || true
        # TLS retry for rediss / stunnel'd instances that return garbage to plaintext.
        if ! grep -qiE 'redis_version:|NOAUTH' "$info" 2>/dev/null; then
            redis-cli -h "$ip" -p "$port" --tls -t 5 INFO > "$OUT/$ip/info_tls_${port}.txt" 2>&1 || true
            if grep -qiE 'redis_version:' "$OUT/$ip/info_tls_${port}.txt" 2>/dev/null; then
                info="$OUT/$ip/info_tls_${port}.txt"; hit "Redis $ip:$port is TLS (rediss)"
            fi
        fi
        redis-cli -h "$ip" -p "$port" -t 5 CLIENT LIST >> "$OUT/$ip/clients_${port}.txt" 2>&1 || true
    else
        miss "redis-cli not installed — using /dev/tcp"
        raw_redis "$ip" "$port" "INFO" > "$info" 2>/dev/null || true
    fi
    classify "$ip" "$port" "$info"

    # Sentinel (26379) — expose the monitored master topology.
    if [ "$port" = "26379" ]; then
        sent="$OUT/$ip/sentinel_${port}.txt"
        if have redis-cli; then redis-cli -h "$ip" -p "$port" -t 5 SENTINEL masters > "$sent" 2>&1 || true
        else raw_redis "$ip" "$port" "SENTINEL masters" > "$sent" 2>/dev/null || true; fi
        grep -qiE 'name|ip|master' "$sent" 2>/dev/null && hit "Redis Sentinel $ip:$port — master topology in $sent"
    fi
done < "$TARGETS"

# nmap redis-info against each discovered redis port (not hardcoded 6379).
if have nmap; then
    ports=$(awk -F: '{print ($2==""?"6379":$2)}' "$TARGETS" 2>/dev/null | sort -u | paste -sd, -)
    IPS=$(ips_only "$TARGETS")
    # shellcheck disable=SC2086
    nmap -Pn $(nmap_bound_args) -p"${ports:-6379}" --script redis-info -iL <(echo "$IPS") \
        -oA "$OUT/nmap-redis" >/dev/null 2>&1 || true
fi

cat > "$OUT/_hints.txt" <<'EOF'
Redis follow-ups:
  * UNAUTH + writable filesystem (dir=/var/lib/redis dbfilename=dump.rdb): cron or
    authorized_keys write, or MODULE LOAD RCE — see standalones/redis/ helpers.
  * Modern 7.x blocks MODULE LOAD; the Lua/EVAL path (redis-rce-lua.sh) is the live
    RCE surface. CVE-2022-0543 (Debian/Ubuntu) is unauth Lua-sandbox-escape RCE.
  * NOAUTH wall: spray with standalones/redis/redis-quickwin.sh --passlist.
  * Sentinel (26379) leaks the real master IP/port even when the master is filtered.
EOF

log "redis dispatcher done."
