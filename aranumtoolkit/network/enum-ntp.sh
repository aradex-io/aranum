#!/usr/bin/env bash
# enum-ntp.sh — NTP (123/udp) mode-6 readvar + mode-7 monlist probe.
#
# AGGRESSIVE PROBE — requires explicit opt-in:
#   ENUM_RUN_NTP=1   enable this dispatcher (or use auto-enum.sh --ntp)
#
# WARNING: NTP mode-7 monlist (CVE-2013-5211) is a classic reflection/amplification
# vector (historically the largest factor). Do NOT fire against internet-facing or
# arbitrary addresses — you risk becoming a DDoS reflection source.
#
# READ-ONLY: mode-6 control readvar (version/system) + a single mode-7 monlist
# request to detect the amplification precondition. Stdlib socket; nmap NSE fallback.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

if [ "${ENUM_RUN_NTP:-0}" != "1" ]; then
    err "enum-ntp.sh refuses to run — set ENUM_RUN_NTP=1 (or use auto-enum.sh --ntp) to enable aggressive UDP probes"
    exit 0
fi
parse_common_args "$@" || exit 1
log "ntp: $(wc -l < "$TARGETS") targets -> $OUT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out="$OUT/$ip/ntp_${port}.txt"

    if have python3; then
        python3 - "$ip" "$port" > "$out" 2>/dev/null <<'PY' || true
import socket, sys, struct
ip, port = sys.argv[1], int(sys.argv[2])
def q(pkt, tmo=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(tmo)
    try:
        s.sendto(pkt, (ip, port)); d, _ = s.recvfrom(8192); return d
    except Exception:
        return b""
    finally:
        s.close()
# mode 6 (control) readvar, opcode 2
ctrl = q(b"\x16\x02\x00\x01" + b"\x00"*8)
if ctrl:
    txt = ctrl[12:].decode("latin-1", "replace")
    print("MODE6_READVAR:", " ".join(txt.split())[:400])
# mode 7 (private) MON_GETLIST_1 (req_code 42) — monlist
mon = q(b"\x17\x00\x03\x2a" + b"\x00"*40)
if mon and len(mon) > 8:
    print(f"MODE7_MONLIST: response {len(mon)} bytes — CVE-2013-5211 amplification precondition")
PY
    fi
    # nmap NSE fallback / corroboration
    if have nmap && [ ! -s "$out" ]; then
        timeout 30 nmap -sU -p "$port" --script ntp-info,ntp-monlist --script-timeout 15s \
            -oN "$OUT/$ip/ntp_nmap_${port}.txt" "$ip" >/dev/null 2>&1 || true
    fi

    if grep -q 'MODE6_READVAR' "$out" 2>/dev/null; then
        hit "NTP responds to mode-6 readvar: $ip:$port (version/config leak)"
    fi
    if grep -q 'MODE7_MONLIST' "$out" 2>/dev/null; then
        crit "NTP AMPLIFICATION VECTOR (CVE-2013-5211 monlist): $ip:$port"
    fi
    throttle_sleep
done < "$TARGETS"

cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

NTP / CVE-2013-5211 follow-ups:
  * monlist (mode 7) responding = reflection/amplification source. Disable with
    `disable monitor` (ntpd) or upgrade past 4.2.7p26. Filter UDP 123 ingress.
  * mode-6 readvar leaks version/OS/peer config — useful for host fingerprinting.
EOF
log "ntp dispatcher done."
