#!/usr/bin/env bash
# enum-rethinkdb.sh — RethinkDB (28015 driver, 8080 admin) unauth check.
# READ-ONLY: probe the admin UI (8080) and the driver handshake (28015).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "rethinkdb: $(wc -l < "$TARGETS") targets -> $OUT"
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"; mkdir -p "$OUT/${ip}_${port}"
    d="$OUT/${ip}_${port}"
    # driver port: no-auth handshake returns "SUCCESS" when auth is disabled
    if have python3 && { [ "$port" = "28015" ] || [ "$port" = "29015" ]; }; then
        python3 - "$ip" "$port" > "$d/handshake.txt" 2>/dev/null <<'PY' || true
import socket,struct,sys
ip,port=sys.argv[1],int(sys.argv[2])
try:
    s=socket.create_connection((ip,port),timeout=5)
    s.sendall(struct.pack("<I",0x34c2bdc3))  # V0_4 magic
    print(s.recv(256).decode("latin-1","replace"))
    s.close()
except Exception: pass
PY
        grep -qi 'SUCCESS' "$d/handshake.txt" 2>/dev/null && crit "UNAUTH RethinkDB driver: $ip:$port — no auth on 28015"
    fi
    if have curl; then
        curl -ks --connect-timeout 6 --max-time 10 "http://$h:$port/" > "$d/admin.html" 2>/dev/null || true
        grep -qi 'RethinkDB' "$d/admin.html" 2>/dev/null && crit "UNAUTH RethinkDB admin UI: $ip:$port"
    fi
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

RethinkDB follow-ups:
  * Admin UI (8080) with no auth = full data read/write via the Data Explorer.
    Driver (28015) SUCCESS handshake = connect with any client and r.db_list().
EOF
log "rethinkdb dispatcher done."
