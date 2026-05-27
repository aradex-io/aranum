#!/usr/bin/env bash
# enum-memcached.sh — Memcached enumeration.
#
# Memcached has NO native auth. Bound to 0.0.0.0 = anyone reads all cached
# data. Historically: session tokens, user profiles, render-cache snippets
# containing PII. Also: famous UDP amplification DDoS vector (Memcrashed).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "memcached: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nc; then
    miss "nc not installed — memcached dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- stats ----------
    printf 'stats\r\nquit\r\n' | timeout 5 nc -nv -w 3 "$ip" "$port" 2>/dev/null \
        > "$OUT/$ip/stats_${port}.txt" || true
    if grep -q 'STAT version' "$OUT/$ip/stats_${port}.txt" 2>/dev/null; then
        ver=$(grep 'STAT version' "$OUT/$ip/stats_${port}.txt" | head -1 | awk '{print $3}' | tr -d '\r')
        hit "UNAUTH: $ip:$port responding to stats — version $ver"
    else
        continue
    fi

    # ---------- stats items / slabs (key inventory) ----------
    for cmd in 'stats slabs' 'stats items' 'stats sizes' 'stats settings'; do
        safe=$(echo "$cmd" | tr ' ' '_')
        printf '%s\r\nquit\r\n' "$cmd" | timeout 5 nc -nv -w 3 "$ip" "$port" 2>/dev/null \
            > "$OUT/$ip/${safe}_${port}.txt" || true
    done

    # ---------- enumerate up to first 50 keys from up to first 5 slabs ----------
    # 'stats cachedump <slab_id> <limit>' is the canonical key-enumeration cmd
    if [ -s "$OUT/$ip/stats_items_${port}.txt" ]; then
        slabs=$(grep -oE 'STAT items:[0-9]+' "$OUT/$ip/stats_items_${port}.txt" \
                | awk -F: '{print $2}' | sort -un | head -5)
        for slab in $slabs; do
            printf 'stats cachedump %s 50\r\nquit\r\n' "$slab" | \
                timeout 5 nc -nv -w 3 "$ip" "$port" 2>/dev/null \
                > "$OUT/$ip/keys_slab${slab}_${port}.txt" || true
        done
    fi
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Memcached follow-ups:
  * Cached keys often include session tokens, render-cache HTML containing
    auth cookies, or unsalted user profile structs. Triage by key naming.
  * Read a specific key: printf 'get <key>\r\n' | nc <ip> 11211
  * UDP 11211 reachable from internet -> Memcrashed amplification (do NOT
    test against arbitrary internet hosts; the amplification factor means
    you're DoS'ing the spoofed victim, not memcached).
  * Modern memcached 1.5.6+ supports SASL — check if `version` response
    indicates >=1.5.6 and the operator wants to confirm SASL config.
EOF

log "memcached dispatcher done."
