#!/usr/bin/env bash
# standalones/ot/enum-dnp3.sh — DNP3 20000 read-side reachability (link-status).
#
# Probe: nmap dnp3-info NSE — link-status request (link function 9). Emits
# master/outstation flag and link-layer source/destination address.
# NO Operate, NO Direct Operate, NO Cold Restart, NO Warm Restart.
#
# Anchor: ADR-005 §D2 §D5
# Plan:   ROADMAP-003 §T4.6

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=standalones/ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "dnp3: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — dnp3 dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/dnp3_${port}.txt"

    nmap -Pn -sT -p "$port" \
        --script dnp3-info \
        --max-retries 1 --host-timeout 30s \
        "$ip" -oN "$out_file" 2>/dev/null || true

    # Two-evidence:
    #   (a) port open + dnp3-info NSE produced output
    #   (b) at least one DNP3 link-layer field present
    is_dnp3=0
    if grep -qE '^[0-9]+/tcp[[:space:]]+open' "$out_file" 2>/dev/null \
       && grep -q '| dnp3-info:' "$out_file" 2>/dev/null; then
        is_dnp3=1
    fi
    has_link=0
    if grep -qE '^\|[[:space:]]+(Source|Destination|Function|Device Function|Master|Outstation)[[:space:]]*:' "$out_file" 2>/dev/null; then
        has_link=1
    fi

    if [ "$is_dnp3" = 1 ] && [ "$has_link" = 1 ]; then
        src=$(grep -oE '^\| +Source:.*'      "$out_file" | head -1 | sed 's/^| *Source: *//' | tr -d '\r' || true)
        dst=$(grep -oE '^\| +Destination:.*' "$out_file" | head -1 | sed 's/^| *Destination: *//' | tr -d '\r' || true)
        role=$(grep -oE '^\| +(Master|Outstation):.*' "$out_file" | head -1 | tr -d '\r' || true)
        hit "OT-ID DNP3 $ip:$port — src=${src:-?} dst=${dst:-?} role=${role:-?}"
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
DNP3 OT follow-ups (READ-SIDE ONLY):

  * DNP3 link-layer addressing is the read-side identification signal —
    master/outstation distinction tells you whether you reached a SCADA
    polling station or a field RTU/IED.

  * NEVER fire Operate (g12), Direct Operate (g12 v1+v2), Cold Restart
    (function 13), or Warm Restart (function 14). ADR-005 D2.

  * For deeper safe ENUM: opendnp3 CLI in read-only mode with explicit
    object/variation selection — out of scope.

  * Secure Authentication (SAv5/v6) is rarely deployed; if banner indicates
    plain DNP3 (no AGGM exchange), document as engagement context.
EOF

log "dnp3 dispatcher done."
