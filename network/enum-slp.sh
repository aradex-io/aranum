#!/usr/bin/env bash
# enum-slp.sh — SLP (Service Location Protocol) UDP 427 discovery.
#
# AGGRESSIVE PROBE — requires explicit opt-in:
#   ENUM_RUN_SLP=1   enable this dispatcher (or use auto-enum.sh --slp)
#
# WARNING: SLP is CVE-2023-29552 amplification surface. Do NOT fire against
# internet-facing hosts or arbitrary addresses — you risk becoming a DDoS
# reflection source toward spoofed victims.
#
# Uses nmap NSE scripts (slp-discovery, slp-info) — slptool does not reliably
# take direct host:port arguments across distros.
#
# Required dep: nmap (with NSE scripts slp-discovery and slp-info)
#
# §9 invariants: enumeration-only; no writes to target.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

# ---- env-gate (exit 0 = documented default, not a failure) -------------------
if [ "${ENUM_RUN_SLP:-0}" != "1" ]; then
    err "enum-slp.sh refuses to run — set ENUM_RUN_SLP=1 (or use auto-enum.sh --slp) to enable aggressive UDP probes"
    exit 0
fi

parse_common_args "$@" || exit 1

log "slp: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    err "nmap not found — install nmap"
    exit 1
fi

# Detect if we have root for reliable UDP scans
IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    log "slp: probing $ip:$port"

    slp_out="$OUT/$ip/slp_nmap_${port}.txt"

    # Non-root nmap UDP scans are unreliable; warn but try anyway.
    if [ "$IS_ROOT" = "0" ]; then
        miss "nmap -sU requires root for reliable UDP probes — falling back to limited scan for $ip:$port"
        nmap_root_flag="--unprivileged"
    else
        nmap_root_flag=""
    fi

    # Run nmap with SLP NSE scripts
    # shellcheck disable=SC2046,SC2086  # optional nmap flags are intentionally split.
    timeout 30 nmap -sU -p "$port" \
        $nmap_root_flag \
        "${THROTTLE_NMAP_ARGS[@]}" \
        --script slp-discovery,slp-info \
        --script-timeout 15s \
        -oN "$slp_out" \
        "$ip" >/dev/null 2>&1 || true

    # Parse nmap NSE output for SLP results
    if grep -qE "^\|[_ ]+(slp-discovery|slp-info):" "$slp_out" 2>/dev/null; then
        hit "SLP open service registry: $ip:$port"

        # Count service types listed
        svc_count=$(grep -c "Service Type:" "$slp_out" 2>/dev/null || echo "0")
        svc_count="${svc_count:-0}"
        if [ "$svc_count" -ge 5 ]; then
            hit "SLP service-type list exposed (HIGH-VALUE): $ip:$port — $svc_count service types"
        fi
    else
        miss "SLP: no service registry response from $ip:$port"
    fi

    # Amplification check: look for large response vs tiny request.
    # nmap reports response size in the NSE output when the script returns data.
    # If the script output block exists and has more than ~20 lines of service
    # data, treat it as an amplification indicator (rough proxy).
    if grep -qE "^\|[_ ]+(slp-discovery|slp-info):" "$slp_out" 2>/dev/null; then
        resp_lines=$(grep -cE "^\|" "$slp_out" 2>/dev/null || echo "0")
        resp_lines="${resp_lines:-0}"
        if [ "$resp_lines" -ge 20 ]; then
            hit "SLP AMPLIFICATION VECTOR (CVE-2023-29552): $ip:$port"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

# ---- hints -------------------------------------------------------------------
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

SLP / CVE-2023-29552 follow-ups:
  * Do NOT fire SLP probes indiscriminately against internet-facing hosts —
    the SLP amplification factor (up to 2200x) means you become a DDoS
    reflection source toward spoofed victim IPs.
  * Exposed SLP registries leak internal service topology (printers, storage,
    ESXi hosts, VMware vCenter). Review slp_nmap_*.txt for service types.
  * CVE-2023-29552 (SLP amplification): patch by disabling SLP on internet-
    facing interfaces or filtering UDP 427 at the perimeter.
EOF

log "slp dispatcher done."
