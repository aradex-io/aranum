#!/usr/bin/env bash
# standalones/ot/enum-iec104.sh — IEC 60870-5-104 (TCP 2404) read-side reachability.
#
# Probe: stdlib socket — send TESTFR (act) APDU `0x68 0x04 0x43 0x00 0x00 0x00`
# (start byte 0x68, length 0x04, control bytes 0x43+0x00+0x00+0x00 = TESTFR
# activation). Expect TESTFR confirmation `0x68 0x04 0x83 0x00 0x00 0x00`.
# NO C_** ASDU emitted, ever.
#
# Anchor: ADR-005 §D2 §D5
# Plan:   ROADMAP-003 §T4.7

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=standalones/ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "iec104: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have python3; then
    miss "python3 not installed — iec104 dispatcher cannot probe"
    exit 0
fi

# Embedded Python probe — stdlib only. The probe is exactly 6 bytes outbound,
# reads up to 6 bytes back with a 3s timeout, prints a single line:
#     IEC104 ip port rc=<rc> evidence=<hex>
_iec104_probe() {
    local ip="$1" port="$2"
    python3 - "$ip" "$port" <<'PY'
import socket, sys, binascii
ip, port = sys.argv[1], int(sys.argv[2])
# IEC 60870-5-104 TESTFR (act) APDU:
#   0x68 = start byte
#   0x04 = length of APCI after start (always 4)
#   0x43 0x00 0x00 0x00 = U-format control field, TESTFR act bit set
TESTFR_ACT = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])
try:
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((ip, port))
    s.sendall(TESTFR_ACT)
    resp = s.recv(6)
    s.close()
    print(f"IEC104 {ip} {port} rc=0 evidence={binascii.hexlify(resp).decode() or 'empty'}")
except (socket.timeout, ConnectionRefusedError, OSError) as e:
    print(f"IEC104 {ip} {port} rc=1 err={type(e).__name__}")
PY
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/iec104_${port}.txt"

    _iec104_probe "$ip" "$port" > "$out_file" 2>&1 || true

    # Two-evidence:
    #   (a) probe rc=0 (TCP connect succeeded, response read)
    #   (b) response evidence starts with 0x68 0x04 (start byte + APCI length)
    #       — anything else is not IEC-104.
    is_iec104=0
    if grep -qE 'rc=0 evidence=6804[0-9a-f]{0,8}\b' "$out_file" 2>/dev/null; then
        is_iec104=1
    fi

    if [ "$is_iec104" = 1 ]; then
        evidence=$(grep -oE 'evidence=[0-9a-f]+' "$out_file" | head -1 | cut -d= -f2)
        # 6804 8300 0000 = TESTFR confirmation (U-format, conf bit set)
        if [[ "$evidence" == 680483* ]]; then
            verdict="TESTFR confirmed"
        elif [[ "$evidence" == 6804* ]]; then
            verdict="IEC104 framing present (non-confirm reply)"
        else
            verdict="unknown"
        fi
        hit "OT-ID IEC-104 $ip:$port — verdict='${verdict}' bytes=${evidence}"
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
IEC 60870-5-104 OT follow-ups (READ-SIDE ONLY):

  * IEC-104 is the dominant SCADA protocol in European energy grids and
    substations. A TESTFR confirmation tells you only that the TCP service
    is alive and speaks IEC-104 — not that it is unauthenticated for
    monitoring-direction reads.

  * NEVER emit C_* (control direction) ASDUs. ADR-005 D2. That includes
    C_SC_NA (single command), C_DC_NA (double command), C_RC_NA (regulating
    step), C_SE (setpoint), and the C_CS / C_CI / C_RD / C_RP / C_TS family
    in command direction.

  * For deeper safe ENUM: lib60870 / IEC104-MasterSimulator in read-only
    monitoring-direction (M_* ASDUs are read-side) — out of scope.

  * RFC 2030-style time-sync (C_CS_NA_1) is sometimes treated as benign,
    but ADR-005 D2 prohibits ALL control-direction ASDUs without exception.
EOF

log "iec104 dispatcher done."
