#!/usr/bin/env bash
# enum-oracle.sh — Oracle DB / TNS Listener enumeration (ports 1521, 1522, 1526).
#
# The TNS Listener accepts unauthenticated queries in versions prior to Oracle 12c.
# SID brute-force reveals database names used for subsequent auth (scott/tiger,
# system/manager). CVE-2012-1675 (TNS poisoning) allows rogue listener registration
# on pre-12c versions.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "oracle: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — oracle dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- nmap Oracle TNS scripts ----------
    nmap -sT -p "$port" \
        --script oracle-tns-version,oracle-sid-brute,oracle-brute-stealth \
        --script-timeout 60 \
        $(throttle_nmap_args) \
        "$ip" -oN "$OUT/$ip/oracle_${port}.txt" 2>/dev/null || true

    # ---------- detect Oracle TNS ----------
    if grep -qi 'Oracle TNS Listener' "$OUT/$ip/oracle_${port}.txt" 2>/dev/null; then
        hit "Oracle TNS: $ip:$port"
    fi

    # ---------- extract discovered SIDs ----------
    if grep -qi 'Found SID:' "$OUT/$ip/oracle_${port}.txt" 2>/dev/null; then
        grep -i 'Found SID:' "$OUT/$ip/oracle_${port}.txt" \
            > "$OUT/$ip/sids_${port}.txt" 2>/dev/null || true
        sid_count=$(wc -l < "$OUT/$ip/sids_${port}.txt" 2>/dev/null || echo 0)
        hit "Oracle SIDs discovered: $ip:$port ($sid_count SIDs) — see sids_${port}.txt"
    fi

    # ---------- optional tnscmd10g ----------
    if have tnscmd10g; then
        timeout 10 tnscmd10g version -h "$ip" -p "$port" \
            > "$OUT/$ip/tnscmd_version_${port}.txt" 2>&1 || true
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Oracle follow-ups:
  * Default creds shortlist: sys/change_on_install, system/manager, scott/tiger,
    dbsnmp/dbsnmp, outln/outln. Use the discovered SIDs with `odat` (Oracle DB
    Attack Tool) for authenticated escalation paths.
  * TNS poisoning (CVE-2012-1675) — pre-12c versions accept rogue listener
    registration; check `oracle-tns-version` output for a vulnerable version.
  * Enumerate SIDs further with: tnscmd10g status -h <ip> -p <port>
  * Connect with sqlplus: sqlplus <user>/<pass>@<ip>:<port>/<SID>
  * odat: odat all -s <ip> -p <port> -d <SID> (requires odat install)
  * Check for EXTPROC listener — allows OS command execution via external procedures.
EOF

log "oracle dispatcher done."
