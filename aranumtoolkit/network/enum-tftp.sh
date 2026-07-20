#!/usr/bin/env bash
# enum-tftp.sh — TFTP (69/udp) blind config-name grab.
# READ-ONLY: RRQ for canonical network-gear/PXE filenames (no auth in TFTP).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "tftp: $(wc -l < "$TARGETS") targets -> $OUT"
FILES="running-config startup-config config.text network-confg cisco.cfg pxelinux.cfg/default bootstrap.cfg system.cfg"
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; mkdir -p "$OUT/$ip"
    got=""
    if have python3; then
        for f in $FILES; do
            res=$(python3 - "$ip" "$port" "$f" 2>/dev/null <<'PY'
import socket,sys
ip,port,fn=sys.argv[1],int(sys.argv[2]),sys.argv[3]
pkt=b"\x00\x01"+fn.encode()+b"\x00octet\x00"
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
try:
    s.sendto(pkt,(ip,port)); d,_=s.recvfrom(2048)
    if d[:2]==b"\x00\x03": print("DATA")          # got file data
    elif d[:2]==b"\x00\x05": print("ERR")          # error (file not there but server alive)
except Exception: pass
finally: s.close()
PY
)
            [ "$res" = "DATA" ] && { got="$got $f"; echo "$f" >> "$OUT/$ip/tftp_readable.txt"; }
            [ -n "$res" ] && echo "TFTP alive at $ip:$port" > "$OUT/$ip/tftp_${port}.txt"
        done
    fi
    if have nmap && [ ! -s "$OUT/$ip/tftp_${port}.txt" ]; then
        timeout 25 nmap -sU -p "$port" --script tftp-enum --script-timeout 15s -oN "$OUT/$ip/tftp_nmap_${port}.txt" "$ip" >/dev/null 2>&1 || true
    fi
    [ -n "$got" ] && crit "TFTP readable config(s) at $ip:$port:$got"
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

TFTP follow-ups:
  * Pull any readable file: tftp <ip> -c get running-config. Device configs hold
    SNMP communities, enable secrets (often type-7/weakly hashed), and VPN PSKs.
EOF
log "tftp dispatcher done."
