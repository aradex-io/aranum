#!/usr/bin/env bash
# enum-netbios-ns.sh — NetBIOS Name Service enumeration (port 137/UDP).
#
# NetBIOS NS is unauthenticated UDP — the name table reveals host names,
# workgroup/domain membership, and MAC addresses. Reachability from a
# probe host implies flat L2 or guest VLAN bleed into an internal segment.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "netbios-ns: $(wc -l < "$TARGETS") targets -> $OUT"

cat > "$OUT/_hints.txt" <<'EOF'
NetBIOS-NS follow-ups:
  * NetBIOS name table is unauthenticated UDP — never reachable across
    well-segmented networks. Presence of 137/UDP suggests flat L2 or
    guest VLAN bleed into an internal segment.
  * Cross-reference name/workgroup with SMB dispatcher results.
  * <00> suffix = workstation service (standard host); <20> = server service
    (file/print sharing enabled); <1c> = domain controller.
  * MAC OUI prefix lookup: https://maclookup.app/
  * Scan an entire subnet range:
      nbtscan -r 192.0.2.0/24
      nmblookup -A <ip>
  * ENUM_DOMAIN env var: set to expected domain name to trigger workgroup
    mismatch detection (rogue host or mis-joined workgroup alert).
EOF

# Determine which tool is available
NBTOOL=""
if have nbtscan; then
    NBTOOL="nbtscan"
elif have nmblookup; then
    NBTOOL="nmblookup"
else
    miss "neither nbtscan nor nmblookup installed — netbios-ns dispatcher cannot probe"
    log "netbios-ns dispatcher done."
    exit 0
fi
log "netbios-ns: using $NBTOOL"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- name table lookup ----------
    if [ "$NBTOOL" = "nbtscan" ]; then
        timeout 8 nbtscan -r "$ip" \
            > "$OUT/$ip/nbtscan_${port}.txt" 2>&1 || true
        out_file="$OUT/$ip/nbtscan_${port}.txt"
    else
        timeout 8 nmblookup -A "$ip" \
            > "$OUT/$ip/nmblookup_${port}.txt" 2>&1 || true
        out_file="$OUT/$ip/nmblookup_${port}.txt"
    fi

    # ---------- parse results ----------
    if [ -s "$out_file" ]; then
        # Try to extract NetBIOS name, workgroup, MAC from tool output
        # nbtscan:   <ip>  <name>   <workgroup>   <mac>
        # nmblookup: <name> <00> - <workgroup> <active>
        nb_name=$(grep -v '^#\|^$\|Doing\|Looking\|netbios' "$out_file" \
            | grep -v '^\s*$' \
            | head -1 | awk '{print $2}' | tr -d '\r' || true)
        wg=$(grep -v '^#\|^$\|Doing\|Looking\|netbios' "$out_file" \
            | grep -v '^\s*$' \
            | head -1 | awk '{print $3}' | tr -d '\r' || true)
        mac=$(grep -iE '([0-9a-f]{2}:){5}[0-9a-f]{2}' "$out_file" \
            | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1 || true)

        if [ -n "$nb_name" ] || [ -n "$wg" ]; then
            hit "NetBIOS name table exposed: $ip — name=${nb_name:-?} workgroup=${wg:-?} mac=${mac:-?}"

            # Workgroup mismatch signal — if engagement domain env is set, compare
            expected_domain="${ENUM_DOMAIN:-}"
            if [ -n "$expected_domain" ] && [ -n "$wg" ]; then
                wg_upper=$(echo "$wg" | tr '[:lower:]' '[:upper:]')
                exp_upper=$(echo "$expected_domain" | tr '[:lower:]' '[:upper:]')
                if [ "$wg_upper" != "$exp_upper" ]; then
                    hit "NetBIOS workgroup mismatch (HIGH-VALUE — rogue host?): $ip — $wg"
                fi
            fi
        fi
    fi

    throttle_sleep
done < "$TARGETS"

log "netbios-ns dispatcher done."
