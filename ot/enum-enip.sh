#!/usr/bin/env bash
# ot/enum-enip.sh — EtherNet/IP 44818 read-side identification (List Identity).
#
# Probe: nmap enip-info NSE on TCP and UDP. Single List Identity (0x0063)
# packet. Discloses Vendor / Device Type / Product Code / Serial / Product Name.
# NO Set Attribute, NO Reset, NO Forward Open with config-data.
#
# Anchor: ADR-005 §D2 §D5
# Plan:   ROADMAP-003 §T4.3

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "enip: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — enip dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/enip_${port}.txt"

    # Probe both TCP and UDP — List Identity is the same payload either way
    # and the device may answer on either. nmap handles the protocol choice.
    nmap -Pn -sT -sU -p "$port" \
        --script enip-info \
        --max-retries 1 --host-timeout 30s \
        "$ip" -oN "$out_file" 2>/dev/null || true

    # Two-evidence:
    #   (a) port open + enip-info NSE produced output
    #   (b) at least one List-Identity field (Vendor / Device Type /
    #       Product Code / Serial Number / Product Name) present
    is_enip=0
    if grep -qE '^[0-9]+/(tcp|udp)[[:space:]]+open' "$out_file" 2>/dev/null \
       && grep -q '| enip-info:' "$out_file" 2>/dev/null; then
        is_enip=1
    fi
    has_id=0
    if grep -qE '^\|[[:space:]]+(Vendor|Device Type|Product Code|Product Name|Serial Number|Revision|Status)[[:space:]]*:' "$out_file" 2>/dev/null; then
        has_id=1
    fi

    if [ "$is_enip" = 1 ] && [ "$has_id" = 1 ]; then
        vendor=$(grep -oE '^\| +Vendor:.*'       "$out_file" | head -1 | sed 's/^| *Vendor: *//' | tr -d '\r' || true)
        product=$(grep -oE '^\| +Product Name:.*' "$out_file" | head -1 | sed 's/^| *Product Name: *//' | tr -d '\r' || true)
        serial=$(grep -oE '^\| +Serial Number:.*' "$out_file" | head -1 | sed 's/^| *Serial Number: *//' | tr -d '\r' || true)
        hit "OT-ID EtherNet/IP $ip:$port — vendor=${vendor:-?} product=${product:-?} serial=${serial:-?}"
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
EtherNet/IP OT follow-ups (READ-SIDE ONLY):

  * Allen-Bradley / Rockwell ControlLogix and CompactLogix routinely reveal
    full product info via List Identity — that is the design.

  * NEVER fire Set Attribute Single (0x10), Set Attribute List (0x04),
    Reset (0x05), or Forward Open with embedded configuration data.
    ADR-005 D2.

  * For deeper safe enumeration consider cpppo / pycomm3 in READ mode
    against KNOWN tag names — out of scope for this dispatcher.

  * If serial number matches a vendor recall list, surface to customer
    through the report — do not chain.
EOF

log "enip dispatcher done."
