#!/usr/bin/env bash
# enum-bambu.sh — render a prior nmap-parse multi-signal Bambu correlation.
#
# This dispatcher is intentionally evidence-only: it sends no packet and does
# not attempt the proprietary 3000/3002 framing, MQTT auth, or FTPS auth. The
# `bambu` target category can only be emitted after nmap-parse.py has correlated
# an explicit BBL/Bambu identity with evidence on another distinct endpoint.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "bambu: rendering prior multi-signal correlation; no live probe"

declare -A PORTS_BY_HOST=()
while IFS= read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    PORTS_BY_HOST[$ip]="${PORTS_BY_HOST[$ip]:-} $port"
done < "$TARGETS"

for ip in "${!PORTS_BY_HOST[@]}"; do
    mkdir -p "$OUT/$ip"
    ports=$(printf '%s\n' ${PORTS_BY_HOST[$ip]} | sort -nu | paste -sd, -)
    {
        echo "BAMBU_LAB_CORRELATED: $ip ports=$ports severity=low confidence=likely"
        echo "basis: nmap-parse identity plus independent compatible endpoint evidence"
        echo "probe_policy: identification-only; no live Bambu protocol/auth probe performed"
    } > "$OUT/$ip/bambu_correlation.txt"
    hit "Bambu Lab likely: $ip (ports=$ports; multi-signal correlation, no live probe)"
done

log "bambu dispatcher done (evidence-only)."
