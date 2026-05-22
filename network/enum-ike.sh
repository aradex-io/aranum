#!/usr/bin/env bash
# enum-ike.sh — IKE/IPsec UDP 500 (and 4500 NAT-T) probe.
#
# AGGRESSIVE PROBE — requires explicit opt-in:
#   ENUM_RUN_IKE=1   enable this dispatcher (or use auto-enum.sh --ike)
#
# Aggressive-mode PSK hash harvest is doubly-gated:
#   ENUM_IKE_AGGRESSIVE_MODE=1   (requires ENUM_RUN_IKE=1 already set)
#
# Required dep: ike-scan
#
# §9 invariants: enumeration-only; no writes to target.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

# ---- env-gate (exit 0 = documented default, not a failure) -------------------
if [ "${ENUM_RUN_IKE:-0}" != "1" ]; then
    err "enum-ike.sh refuses to run — set ENUM_RUN_IKE=1 (or use auto-enum.sh --ike) to enable aggressive UDP probes"
    exit 0
fi

parse_common_args "$@" || exit 1

log "ike: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have ike-scan; then
    err "ike-scan not found — install ike-scan (e.g. dnf install ike-scan)"
    exit 1
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    log "ike: probing $ip:$port (IKEv1 main mode)"

    # ---- IKEv1 Main Mode probe ------------------------------------------------
    main_out="$OUT/$ip/ike_main_${port}.txt"
    timeout 15 ike-scan -M "$ip" > "$main_out" 2>&1 || true

    # ike-scan always returns rc=0; gate hits on response content.
    # A real response contains "Handshake returned"; a no-response scan shows
    # "0 returned handshake" in the summary line — exclude that.
    if grep -q "Handshake returned" "$main_out" 2>/dev/null; then
        hit "IKE/IPsec VPN endpoint reachable: $ip:$port"

        # Extract Vendor ID strings if present
        if grep -q "Vendor ID" "$main_out" 2>/dev/null; then
            vendor=$(grep "Vendor ID" "$main_out" | head -3 | tr '\n' '; ' | sed 's/; $//')
            hit "IKE vendor: $ip:$port — $vendor"
        fi
    else
        miss "IKE/IPsec: no handshake returned from $ip:$port"
    fi

    # ---- Aggressive Mode (PSK hash harvest) — doubly gated -------------------
    if [ "${ENUM_IKE_AGGRESSIVE_MODE:-0}" = "1" ]; then
        log "ike: aggressive mode enabled — probing $ip:$port for PSK hash"
        agg_out="$OUT/$ip/ike_aggressive_${port}.txt"
        timeout 15 ike-scan -A "$ip" > "$agg_out" 2>&1 || true

        if grep -q "HASH" "$agg_out" 2>/dev/null; then
            hit "AGGRESSIVE MODE PSK HASH HARVESTED: $ip:$port — see ike_aggressive_${port}.txt"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

# ---- hints -------------------------------------------------------------------
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

IKE / IPsec follow-ups:
  * Aggressive Mode hash -> psk-crack from the ike-scan suite or hashcat -m 5300
  * Vendor ID strings identify gateway product (Cisco PIX/ASA, Fortinet,
    PaloAlto, Strongswan, etc.) — use to scope vendor-specific CVE search.
  * Aggressive Mode is doubly gated: ENUM_RUN_IKE=1 enables main-mode,
    ENUM_IKE_AGGRESSIVE_MODE=1 also enables aggressive-mode hash harvest.
EOF

log "ike dispatcher done."
