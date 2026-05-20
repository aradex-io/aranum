#!/usr/bin/env bash
# enum-rdp.sh — RDP security & cred check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "rdp: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# nmap rdp scripts (security level, NLA, encryption)
if have nmap; then
    log "nmap rdp-enum-encryption + rdp-ntlm-info"
    nmap -Pn -p3389 --script 'rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-rdp" >/dev/null 2>&1 || true
fi

# nxc rdp cred spray
if (have nxc || have netexec) && [ -n "${ENUM_USER:-}" ]; then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc rdp (cred check)"
    echo "$IPS" | "$NXC" rdp - "${NXC_ARGS[@]}" > "$OUT/nxc_rdp.txt" 2>&1 || true

    # screenshot accepting hosts (requires xfreerdp under the hood)
    log "nxc rdp --screenshot"
    echo "$IPS" | "$NXC" rdp - "${NXC_ARGS[@]}" --screenshot \
        --screentime 5 > "$OUT/nxc_rdp_screenshot.txt" 2>&1 || true
fi

# rdp-sec-check (perl tool) — independent NLA/SSL check
if have rdp-sec-check.pl; then
    for ip in $IPS; do
        rdp-sec-check.pl "$ip" > "$OUT/rdpseccheck_${ip}.txt" 2>&1 || true
    done
fi

log "rdp dispatcher done."
