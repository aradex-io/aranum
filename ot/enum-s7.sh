#!/usr/bin/env bash
# ot/enum-s7.sh — Siemens S7comm 102 read-side identification.
#
# Probe: nmap s7-info NSE — COTP CR + Job 0x29 read SZL (ID 0x11/0x1c).
# Emits CPU model, firmware, plant identification, module type.
# NO PLC stop/start/firmware-download.
#
# Anchor: ADR-005 §D2 §D5
# Plan:   ROADMAP-003 §T4.2

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "s7: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — s7 dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/s7_${port}.txt"

    nmap -Pn -sT -p "$port" \
        --script s7-info \
        --max-retries 1 --host-timeout 30s \
        "$ip" -oN "$out_file" 2>/dev/null || true

    # Two-evidence:
    #   (a) port open + s7-info NSE produced output
    #   (b) at least one SZL-derived field present (Module / Basic Module /
    #       Module Type / Serial Number / System Name / Basic Firmware /
    #       Plant Identification)
    is_s7=0
    if grep -qE '^[0-9]+/tcp[[:space:]]+open' "$out_file" 2>/dev/null \
       && grep -q '| s7-info:' "$out_file" 2>/dev/null; then
        is_s7=1
    fi
    has_szl=0
    if grep -qE '^\|[[:space:]]+(Module|Basic Module|Module Type|Module name|Serial number|System Name|Basic Firmware|Plant Identification|Copyright)[[:space:]]*:' "$out_file" 2>/dev/null; then
        has_szl=1
    fi

    if [ "$is_s7" = 1 ] && [ "$has_szl" = 1 ]; then
        module=$(grep -oE '^\| +Module:.*'        "$out_file" | head -1 | sed 's/^| *Module: *//' | tr -d '\r' || true)
        firmware=$(grep -oE '^\| +Basic Firmware:.*' "$out_file" | head -1 | sed 's/^| *Basic Firmware: *//' | tr -d '\r' || true)
        plant=$(grep -oE '^\| +Plant Identification:.*' "$out_file" | head -1 | sed 's/^| *Plant Identification: *//' | tr -d '\r' || true)
        hit "OT-ID S7 $ip:$port — module=${module:-?} fw=${firmware:-?} plant=${plant:-?}"
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Siemens S7 OT follow-ups (READ-SIDE ONLY):

  * S7-300/400/1200/1500 — module + firmware identification via SZL is
    unauthenticated by design. Treat the disclosure as situational
    awareness, not as an exploitation primitive.

  * Snap7 and python-snap7 libraries can read DB blocks if the operator
    knows DB numbers — out of scope for default probe. Do not chain.

  * NEVER send STOP (0x29 with stop_pdu), Start, firmware download, or
    DB write requests. ADR-005 D2.

  * Plant Identification often discloses physical location / line name —
    treat as engagement-sensitive info.
EOF

log "s7 dispatcher done."
