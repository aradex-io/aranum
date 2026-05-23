#!/usr/bin/env bash
# ot/enum-modbus.sh — Modbus TCP 502 read-side identification.
#
# Probe: nmap modbus-discover NSE with aggressive=false. Single FC 17
# (Report Slave ID) per discovered unit ID. NO write-side function code.
#
# Anchor: docs/ADR-005-22MAY2026-ot-ics-safety-scope.md §D2 §D5
# Plan:   docs/ROADMAP-003 §T4.1

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "modbus: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — modbus dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/modbus_${port}.txt"

    # FC 17 only, no aggressive sweep. modbus-discover.aggressive=false
    # limits to unit IDs 0 + 1 + 255 + the unit ID specified (default 1).
    nmap -Pn -sT -p "$port" \
        --script modbus-discover \
        --script-args 'modbus-discover.aggressive=false' \
        --max-retries 1 --host-timeout 30s \
        "$ip" -oN "$out_file" 2>/dev/null || true

    # Two-evidence guard:
    #   (a) port confirmed open AND service-name 'mbap'/'modbus' fingerprint
    #   (b) at least one `Vendor:` or `Product code:` or `MajorMinorRevision:`
    #       line emitted by modbus-discover.
    is_modbus=0
    if grep -qE '^[0-9]+/tcp[[:space:]]+open[[:space:]]+(mbap|modbus)' "$out_file" 2>/dev/null; then
        is_modbus=1
    fi
    has_disco=0
    if grep -qE '^\|[[:space:]]+(Vendor|Product code|MajorMinorRevision|Device name)[[:space:]]*:' "$out_file" 2>/dev/null; then
        has_disco=1
    fi

    if [ "$is_modbus" = 1 ] && [ "$has_disco" = 1 ]; then
        vendor=$(grep -oE '^\| +Vendor:.*' "$out_file" | head -1 | sed 's/^| *Vendor: *//' | tr -d '\r' || true)
        product=$(grep -oE '^\| +Product code:.*' "$out_file" | head -1 | sed 's/^| *Product code: *//' | tr -d '\r' || true)
        rev=$(grep -oE '^\| +MajorMinorRevision:.*' "$out_file" | head -1 | sed 's/^| *MajorMinorRevision: *//' | tr -d '\r' || true)
        hit "OT-ID Modbus $ip:$port — vendor=${vendor:-?} product=${product:-?} rev=${rev:-?}"
    elif [ "$is_modbus" = 1 ]; then
        # Open + fingerprint but no FC17 disclosure — emit informational
        hit "OT-ID Modbus $ip:$port (no FC17 disclosure — device may have responded with unsupported function)"
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Modbus OT follow-ups (READ-SIDE ONLY — write side is hard-prohibited):

  * Allen-Bradley/Schneider PLCs frequently disclose CPU model via FC 17.
    Cross-reference vendor advisory feeds for known firmware CVEs but DO NOT
    automate CVE-lookup here (ADR-005 D6).

  * If the device fingerprints as Schneider Electric M340/M580: no native
    auth on EtherNet/IP companion channel either — see enum-enip.sh.

  * NEVER fire FC 5/6/15/16/22/23, FC 8 sub-1 (Restart), or FC 43 sub-14
    (Read Device Identification stream-access mode). ADR-005 D2.

  * Document device class + firmware in the engagement notes. Surface to
    customer through the report; do NOT chain into deeper testing without
    a re-scoped maintenance window.
EOF

log "modbus dispatcher done."
