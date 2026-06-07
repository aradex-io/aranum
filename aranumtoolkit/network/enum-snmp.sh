#!/usr/bin/env bash
# enum-snmp.sh — onesixtyone community sweep + snmpwalk on accepted communities.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "snmp: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")
echo "$IPS" > "$OUT/_hosts.txt"

# 1. Community list (built-in + common)
COMMUNITY_LIST="$OUT/_communities.txt"
cat > "$COMMUNITY_LIST" <<'EOF'
public
private
community
manager
admin
cisco
router
default
read
write
snmp
secret
network
guest
ilmi
root
EOF
# Append SecLists wordlist if available
[ -r /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt ] && \
    cat /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt >> "$COMMUNITY_LIST"
sort -u -o "$COMMUNITY_LIST" "$COMMUNITY_LIST"

# 2. onesixtyone scan
if have onesixtyone; then
    log "onesixtyone (community sweep)"
    onesixtyone -c "$COMMUNITY_LIST" -i "$OUT/_hosts.txt" \
        -w 100 > "$OUT/onesixtyone.txt" 2>&1 || true
else
    miss "onesixtyone not installed"
fi

# 3. snmpwalk for hits
if have snmpwalk && [ -f "$OUT/onesixtyone.txt" ]; then
    log "snmpwalk on accepted communities"
    grep -E '^\[' "$OUT/onesixtyone.txt" 2>/dev/null | while read -r line; do
        community=$(echo "$line" | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]')
        ip=$(echo "$line" | awk '{print $2}')
        [ -z "$community" ] || [ -z "$ip" ] && continue
        mkdir -p "$OUT/$ip"
        snmpwalk -v2c -c "$community" -t 2 -r 1 "$ip" \
            > "$OUT/$ip/walk_${community}.txt" 2>&1 || true
        # Specific OIDs of interest
        snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.4.1.77.1.2.25 \
            > "$OUT/$ip/users_${community}.txt" 2>&1 || true     # Windows users
        snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.2.1.25.4.2.1.2 \
            > "$OUT/$ip/procs_${community}.txt" 2>&1 || true     # running processes
        snmpwalk -v2c -c "$community" "$ip" 1.3.6.1.4.1.77.1.2.27 \
            > "$OUT/$ip/shares_${community}.txt" 2>&1 || true    # shares
    done
fi

# 4. nmap snmp-brute
if have nmap; then
    log "nmap snmp-info + snmp-sysdescr"
    nmap -Pn $(nmap_bound_args) -sU -p161 --script 'snmp-info,snmp-sysdescr,snmp-interfaces' \
        -iL "$OUT/_hosts.txt" -oA "$OUT/nmap-snmp" >/dev/null 2>&1 || true
fi

log "snmp dispatcher done."
