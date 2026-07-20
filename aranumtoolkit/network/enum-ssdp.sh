#!/usr/bin/env bash
# enum-ssdp.sh — SSDP/UPnP (1900/udp) M-SEARCH discovery.
#
# AGGRESSIVE PROBE — requires explicit opt-in:
#   ENUM_RUN_SSDP=1   enable this dispatcher (or use auto-enum.sh --ssdp)
#
# WARNING: SSDP is a reflection/amplification vector. Do NOT fire against
# internet-facing or arbitrary addresses.
#
# READ-ONLY: one unicast M-SEARCH (ST: ssdp:all) → device/service inventory +
# LOCATION XML URLs (device model/firmware). Flags CVE-2020-12695 (CallStranger)
# surface. Stdlib socket; nmap NSE fallback.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

if [ "${ENUM_RUN_SSDP:-0}" != "1" ]; then
    err "enum-ssdp.sh refuses to run — set ENUM_RUN_SSDP=1 (or use auto-enum.sh --ssdp) to enable aggressive UDP probes"
    exit 0
fi
parse_common_args "$@" || exit 1
log "ssdp: $(wc -l < "$TARGETS") targets -> $OUT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out="$OUT/$ip/ssdp_${port}.txt"

    if have python3; then
        python3 - "$ip" "$port" > "$out" 2>/dev/null <<'PY' || true
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
msg = ("M-SEARCH * HTTP/1.1\r\nHOST: %s:%d\r\nMAN: \"ssdp:discover\"\r\n"
       "MX: 2\r\nST: ssdp:all\r\n\r\n" % (ip, port)).encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(msg, (ip, port))
    while True:
        try:
            d, _ = s.recvfrom(8192)
        except socket.timeout:
            break
        print(d.decode("latin-1", "replace").strip()); print("----")
except Exception:
    pass
finally:
    s.close()
PY
    fi
    if have nmap && [ ! -s "$out" ]; then
        timeout 30 nmap -sU -p "$port" --script upnp-info,broadcast-upnp-info --script-timeout 15s \
            -oN "$OUT/$ip/ssdp_nmap_${port}.txt" "$ip" >/dev/null 2>&1 || true
    fi

    if grep -qiE 'HTTP/1.1 200|LOCATION:|USN:|ST:' "$out" 2>/dev/null; then
        hit "SSDP/UPnP responder: $ip:$port — device/service inventory exposed"
        if grep -qi 'LOCATION:' "$out" 2>/dev/null; then
            echo "SSDP LOCATION URLs (device descriptor XML):" >> "$OUT/_hints.txt"
            grep -i 'LOCATION:' "$out" | sort -u >> "$OUT/_hints.txt"
        fi
    fi
    throttle_sleep
done < "$TARGETS"

cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

SSDP / UPnP follow-ups:
  * Fetch each LOCATION URL for the device descriptor (model, firmware, serial,
    presentation/control URLs). SUBSCRIBE with a spoofed callback is the
    CVE-2020-12695 (CallStranger) data-exfil / reflected-amplification vector.
  * Do NOT drive SSDP amplification against arbitrary hosts.
EOF
log "ssdp dispatcher done."
