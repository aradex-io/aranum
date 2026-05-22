#!/usr/bin/env bash
# enum-telnet.sh — Telnet enumeration (port 23).
#
# Telnet is cleartext — any credential typed over it is visible to on-path
# observers. Its presence on modern networks indicates embedded/legacy devices:
# Cisco routers, HP iLO, Brother printers, Dell iDRAC, Juniper, Ubiquiti APs,
# DD-WRT firmware. Each device family has well-known default credentials.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "telnet: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nc; then
    miss "nc not installed — telnet dispatcher cannot probe banners"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- banner grab ----------
    timeout 6 nc -nv -w 4 "$ip" "$port" < /dev/null \
        > "$OUT/$ip/banner_${port}.txt" 2>&1 || true

    # ---------- nmap Telnet scripts (optional) ----------
    if have nmap; then
        nmap -sT -p "$port" \
            --script telnet-encryption,telnet-ntlm-info,banner \
            --script-timeout 30 \
            $(throttle_nmap_args) \
            "$ip" -oN "$OUT/$ip/telnet_${port}.txt" 2>/dev/null || true
    fi

    # ---------- always flag as open ----------
    hit "Telnet open: $ip:$port"

    # ---------- device family fingerprint (case-insensitive regex) ----------
    banner_text=""
    [ -s "$OUT/$ip/banner_${port}.txt" ] && banner_text=$(cat "$OUT/$ip/banner_${port}.txt")
    [ -s "$OUT/$ip/telnet_${port}.txt" ] && banner_text="$banner_text $(cat "$OUT/$ip/telnet_${port}.txt")"

    if echo "$banner_text" | grep -qiE 'cisco'; then
        hit "Telnet device: Cisco at $ip:$port"
    fi
    if echo "$banner_text" | grep -qiE 'hp ilo|hpe ilo|integrated lights.?out'; then
        hit "Telnet device: HP iLO at $ip:$port"
    fi
    if echo "$banner_text" | grep -qiE 'brother'; then
        hit "Telnet device: Brother at $ip:$port"
    fi
    if echo "$banner_text" | grep -qiE 'dell idrac|idrac'; then
        hit "Telnet device: Dell iDRAC at $ip:$port"
    fi
    if echo "$banner_text" | grep -qiE 'juniper|junos'; then
        hit "Telnet device: Juniper at $ip:$port"
    fi
    if echo "$banner_text" | grep -qiE 'ubiquiti|unifi|edgeos|airos'; then
        hit "Telnet device: Ubiquiti at $ip:$port"
    fi
    if echo "$banner_text" | grep -qiE 'dd.?wrt|openwrt|tomato'; then
        hit "Telnet device: DD-WRT/OpenWRT at $ip:$port"
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Telnet default credential shortlist (DO NOT auto-attempt — manual confirm required):
  Cisco IOS:         cisco/cisco, admin/admin, admin/<blank>, enable/<blank>
  HP iLO:            Administrator/<8-char random printed on rear label>
  Brother printers:  admin/<blank> (no password required by default)
  Dell iDRAC:        root/calvin
  Juniper (JunOS):   root/<blank> (initial setup), admin/admin (some appliances)
  Ubiquiti (AirOS):  ubnt/ubnt
  DD-WRT:            root/admin, admin/admin

Post-foothold:
  * Capture full session: script -a telnet_session.log (then telnet <ip>)
  * Check for NTLM auth banner — Windows Telnet Server (IIS 6+ era) may
    expose NTLM version and domain info via the telnet-ntlm-info NSE script.
  * Any credential transmitted over Telnet is cleartext — flag for immediate
    rotation + protocol replacement (SSH/HTTPS management interface).
EOF

log "telnet dispatcher done."
