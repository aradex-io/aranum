#!/usr/bin/env bash
# enum-flexnet.sh — FlexNet Publisher (FLEXlm) license-server enumeration.
#
# Ports: 27000-27009 (lmgrd master + vendor daemons). Characteristic of
# engineering/science labs running MATLAB, Cadence, Synopsys, Ansys,
# COMSOL, Mentor Graphics, Altium, Intel/Quartus.
#
# Probe surface (UNAUTH BY DESIGN):
#   - lmgrd handshake banner (decimal "5279" or printable lm-banner string)
#   - vendor-daemon advertisement on subsequent ports
#   - if `lmutil` is present locally, run `lmutil lmstat -a -c PORT@HOST` —
#     discloses every licensed product + every currently-checked-out user

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "flexnet: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nc; then
    miss "nc not installed — flexnet dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- lmgrd handshake banner ----------
    # lmgrd answers with a single-byte protocol marker (0x2A on legacy, ASCII
    # "5279"/"lmgrd" on newer builds) followed by capability bytes. We send
    # nothing — many servers drop silently on bad payloads, breaking the FP
    # two-evidence check. Just collect what they send on connect.
    banner_file="$OUT/$ip/flexnet_${port}_banner.bin"
    timeout 5 nc -nv -w 4 "$ip" "$port" < /dev/null \
        > "$banner_file" 2>&1 || true

    # Two-evidence guard:
    #   (a) banner non-empty AND
    #   (b) at least one of: literal "lmgrd"/"FLEXlm"/"FLEXnet", the legacy
    #       0x2A protocol byte, the "License server status" ASCII reply, or
    #       the canonical "5279" string (FLEXlm port-number ack).
    is_flexnet=0
    if [ -s "$banner_file" ]; then
        if LC_ALL=C grep -qE '(lmgrd|FLEXlm|FLEXnet|License server status|5279)' "$banner_file" 2>/dev/null; then
            is_flexnet=1
        elif head -c 1 "$banner_file" 2>/dev/null | LC_ALL=C grep -q $'\x2a'; then
            is_flexnet=1
        fi
    fi

    if [ "$is_flexnet" = 1 ]; then
        # Strip non-printable for log readability
        banner=$(LC_ALL=C tr -dc '[:print:]' < "$banner_file" | head -c 80)
        hit "FlexNet/FLEXlm license server reachable: $ip:$port — banner=\"${banner}\""
    else
        # Quiet skip — banner did not match. The default port range is wide
        # (27000-27009), so most ports in that range will not be lmgrd.
        rm -f "$banner_file" 2>/dev/null
        continue
    fi

    # ---------- lmutil lmstat -a (only if available locally) ----------
    if have lmutil; then
        log "lmutil present — running lmstat -a -c $port@$ip"
        lmstat_file="$OUT/$ip/flexnet_${port}_lmstat.txt"
        timeout 20 lmutil lmstat -a -c "$port@$ip" \
            > "$lmstat_file" 2>&1 || true

        if [ -s "$lmstat_file" ]; then
            # Count licensed features (each "Users of <feature>:" line).
            feat_count=$(grep -cE '^Users of [^:]+:' "$lmstat_file" 2>/dev/null | tr -d '[:space:]')
            feat_count="${feat_count:-0}"
            # Count distinct active users (col 1 of any line not starting with whitespace
            # in a "Users of …" block — heuristic).
            user_count=$(awk '/^Users of /{f=1;next} f && /^[[:space:]]+[A-Za-z]/ {print $1; next} /^[[:space:]]*$/{f=0}' \
                "$lmstat_file" 2>/dev/null | sort -u | wc -l | tr -d '[:space:]')
            user_count="${user_count:-0}"

            if [ "$feat_count" -gt 0 ]; then
                hit "FlexNet UNAUTH lmstat disclosure: $ip:$port — features=${feat_count} active_users=${user_count}"

                # Surface the first 5 licensed product names as evidence
                prods=$(grep -oE '^Users of [^:]+:' "$lmstat_file" | head -5 | sed 's/^Users of //; s/:$//' | tr '\n' '/' | sed 's,/$,,')
                [ -n "$prods" ] && log "FlexNet licensed products (top 5): $ip:$port — $prods"
            fi
        fi
    else
        log "lmutil not installed — skipping lmstat phase (banner-only evidence)"
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
FlexNet / FLEXlm follow-ups:

  * `lmutil lmstat -a -c <port>@<ip>` — discloses EVERY licensed product
    and EVERY currently-checked-out user. Unauth by design. If lmutil is
    on the attacker box, the dispatcher already ran this.

  * `lmutil lmdiag -c <port>@<ip>` — per-feature diagnostic; reveals
    license-file path on the server.

  * `lmutil lmhostid` — get server hostid (useful if you find a stolen
    license file elsewhere).

  * Engineering-vendor characteristics:
      - MATLAB           : vendor daemon "MLM"
      - Cadence          : "cdslmd"
      - Synopsys         : "snpslmd"
      - Ansys            : "ansyslmd"
      - COMSOL           : "LMCOMSOL"
      - Mentor / Siemens : "mgcld"
      - Altium           : "altiumlmd"
      - Intel / Quartus  : "quartuslm"
    Active-user list lets you correlate workstation hostnames to roles
    (PCB designer vs RF designer vs FPGA dev) — engagement intelligence.

  * Defensive note: FlexNet has no native authentication. The mitigations
    are network ACLs at the perimeter and license-file `INCLUDE`/`EXCLUDE`
    lines for per-product access control.
EOF

log "flexnet dispatcher done."
