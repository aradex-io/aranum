#!/usr/bin/env bash
# enum-afp.sh — Apple Filing Protocol (548) server info + shares.
# READ-ONLY: nmap afp-serverinfo / afp-showmount (no auth needed for either).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "afp: $(wc -l < "$TARGETS") targets -> $OUT"
have nmap || { miss "nmap not installed — afp dispatcher cannot probe"; exit 0; }
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; mkdir -p "$OUT/$ip"
    out="$OUT/$ip/afp_${port}.txt"
    timeout 30 nmap -Pn "${THROTTLE_NMAP_ARGS[@]}" -p "$port" --script afp-serverinfo,afp-showmount --script-timeout 20s -oN "$out" "$ip" >/dev/null 2>&1 || true
    grep -qi 'afp-serverinfo\|Machine Type\|AFP' "$out" 2>/dev/null && hit "AFP server: $ip:$port — model/shares in $out"
    grep -qi 'afp-showmount' "$out" 2>/dev/null && hit "AFP shares enumerated: $ip:$port"
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

AFP follow-ups:
  * afp-serverinfo leaks the Mac model, OS, and UAMs (auth methods). Guest UAM =
    anonymous share mount. Pair with SMB (Macs usually run both).
EOF
log "afp dispatcher done."
