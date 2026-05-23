#!/usr/bin/env bash
# ot/enum-bacnet.sh — BACnet/IP 47808/udp read-side identification (Who-Is).
#
# Probe: nmap bacnet-info NSE on UDP 47808. Single Who-Is broadcast with
# LOW limit 0 / HIGH limit 4194303, then I-Am parse for device instances.
# NO WriteProperty, NO ReinitializeDevice, NO DeviceCommunicationControl.
#
# Anchor: ADR-005 §D2 §D5
# Plan:   ROADMAP-003 §T4.4

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "bacnet: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — bacnet dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/bacnet_${port}.txt"

    # UDP probe — bacnet-info NSE handles Who-Is broadcast and I-Am parsing.
    nmap -Pn -sU -p "$port" \
        --script bacnet-info \
        --max-retries 1 --host-timeout 30s \
        "$ip" -oN "$out_file" 2>/dev/null || true

    # Two-evidence:
    #   (a) port open|open|filtered on UDP + bacnet-info produced output
    #   (b) at least one Object/Vendor/Application/Firmware field
    is_bacnet=0
    if grep -qE '^[0-9]+/udp[[:space:]]+(open|open\|filtered)' "$out_file" 2>/dev/null \
       && grep -q '| bacnet-info:' "$out_file" 2>/dev/null; then
        is_bacnet=1
    fi
    has_id=0
    if grep -qE '^\|[[:space:]]+(Vendor (ID|Name)|Object-identifier|Application Software|Firmware|Model Name|Description|Location)[[:space:]]*:' "$out_file" 2>/dev/null; then
        has_id=1
    fi

    if [ "$is_bacnet" = 1 ] && [ "$has_id" = 1 ]; then
        vendor=$(grep -oE '^\| +Vendor Name:.*'  "$out_file" | head -1 | sed 's/^| *Vendor Name: *//' | tr -d '\r' || true)
        model=$(grep -oE '^\| +Model Name:.*'    "$out_file" | head -1 | sed 's/^| *Model Name: *//' | tr -d '\r' || true)
        fw=$(grep -oE '^\| +Firmware:.*'         "$out_file" | head -1 | sed 's/^| *Firmware: *//' | tr -d '\r' || true)
        loc=$(grep -oE '^\| +Location:.*'        "$out_file" | head -1 | sed 's/^| *Location: *//' | tr -d '\r' || true)
        hit "OT-ID BACnet $ip:$port — vendor=${vendor:-?} model=${model:-?} fw=${fw:-?} loc=${loc:-?}"

        # Building automation devices that ALSO disclose firmware are
        # higher-grade evidence — engagement context may flag them as
        # MEDIUM via report.py rule.
        if [ -n "$fw" ] && [ -z "${vendor##*[a-zA-Z]*}" ]; then
            log "BACnet device with firmware disclosure: $ip:$port"
        fi
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
BACnet OT follow-ups (READ-SIDE ONLY):

  * BACnet has NO authentication by design in the original spec. BACnet/SC
    (Secure Connect) addresses this but is rarely deployed in legacy
    buildings.

  * NEVER send WriteProperty (SimpleACK), WritePropertyMultiple,
    ReinitializeDevice (cold/warm start), DeviceCommunicationControl
    (disable + reenable), or AtomicWriteFile. ADR-005 D2.

  * Location field often reveals exact building / floor / equipment room —
    treat as engagement-sensitive.

  * For deeper safe ENUM: bacnet-tools / yabe (read-only object lists).
    Out of scope for this dispatcher.
EOF

log "bacnet dispatcher done."
