#!/usr/bin/env bash
# enum-msrpc.sh — MSRPC endpoint mapper enumeration.
#
# Port 135 is the MSRPC endpoint mapper — maps interface UUIDs to dynamic
# ephemeral ports. Enumerating registered interfaces reveals available
# Windows services and pivot paths (DCOM, WMI, scheduled tasks, print spooler).
#
# Tool priority: impacket-rpcdump > rpcdump.py > rpcclient > nmap msrpc-enum

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "msrpc: $(wc -l < "$TARGETS") targets -> $OUT"

cat > "$OUT/_hints.txt" <<'EOF'
MSRPC follow-ups:
  * Cross-reference discovered endpoint UUIDs with SMB findings to find
    exploit chains (e.g. PrintSpooler + SeImpersonate for PrintNightmare).
  * Coercion tools that use discovered MSRPC endpoints:
      coercer.py  -- enumerate and trigger NTLM coerce via many MS-* methods
      petitpotam.py -- MS-EFSRPC-based NTLM coerce (EfsBkupKey etc.)
  * Common HIGH-VALUE interfaces to look for in rpcdump output:
      MS-RPRN   (print spooler — PrintNightmare, SpoolSample)
      MS-EFSR   (encrypting file system — PetitPotam)
      MS-SAMR   (SAM remote — user/group enum)
      MS-LSAD   (local security authority — domain info)
      MS-DCOM   (DCOM activation — DCOM-based laterals)
  * rpcclient anonymous enum: srvinfo, enumdomusers, querydominfo,
    lsaquery, lookupnames <name>, lookupsids <sid>
EOF

# Determine which tools are available
RPCDUMP=""
if have impacket-rpcdump; then
    RPCDUMP="impacket-rpcdump"
elif have rpcdump.py; then
    RPCDUMP="rpcdump.py"
fi

if [ -z "$RPCDUMP" ] && ! have rpcclient && ! have nmap; then
    miss "no MSRPC tools found (impacket-rpcdump, rpcdump.py, rpcclient, nmap) — cannot probe"
    log "msrpc dispatcher done."
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- rpcdump (impacket) — priority 1 & 2 ----------
    if [ -n "$RPCDUMP" ]; then
        timeout 15 "$RPCDUMP" "@$ip" \
            > "$OUT/$ip/rpcdump_${port}.txt" 2>&1 || true

        if [ -s "$OUT/$ip/rpcdump_${port}.txt" ]; then
            iface_count=$(grep -cE '^Protocol:.*MS-|^Protocol:.*MSRPC|uuid:' \
                "$OUT/$ip/rpcdump_${port}.txt" 2>/dev/null || echo 0)
            if [ "${iface_count:-0}" -gt 0 ]; then
                hit "MSRPC endpoint mapper open: $ip:$port — $iface_count interfaces"
            fi
        fi
    fi

    # ---------- rpcclient anonymous enum — priority 3 ----------
    if have rpcclient; then
        timeout 10 rpcclient -U '' -N "$ip" \
            -c 'srvinfo;enumdomusers;querydominfo' \
            > "$OUT/$ip/rpcclient_${port}.txt" 2>&1 || true

        if grep -qi 'Server Type:' "$OUT/$ip/rpcclient_${port}.txt" 2>/dev/null; then
            hit "MSRPC anonymous srvinfo: $ip:$port"
        fi
    fi

    # ---------- nmap msrpc-enum — priority 4 ----------
    if have nmap; then
        nmap -sT -p "$port" \
            --script msrpc-enum \
            --script-timeout 30 \
            $(throttle_nmap_args) \
            "$ip" \
            -oN "$OUT/$ip/msrpc_nmap_${port}.txt" 2>/dev/null || true
    fi

    throttle_sleep
done < "$TARGETS"

log "msrpc dispatcher done."
