#!/usr/bin/env bash
# enum-ftp.sh — FTP anonymous + cred check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "ftp: $(wc -l < "$TARGETS") targets -> $OUT"

# Anonymous probe per host
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    {
        echo "--- banner ---"
        timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$port; head -1 <&3" 2>/dev/null
        echo "--- anonymous listing ---"
        timeout 15 curl -s --max-time 10 "ftp://$ip:$port/" --user "anonymous:anonymous@example.com" 2>&1 | head -30
    } > "$OUT/$ip/ftp.txt" 2>&1 || true
done < "$TARGETS"

# nxc ftp cred check
if (have nxc || have netexec) && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
    NXC=$(command -v nxc || command -v netexec)
    log "nxc ftp (cred check)"
    ips_only "$TARGETS" | \
        "$NXC" ftp - -u "$ENUM_USER" -p "$ENUM_PASS" \
        > "$OUT/nxc_ftp.txt" 2>&1 || true
fi

# nmap ftp scripts
if have nmap; then
    log "nmap ftp-anon + ftp-syst"
    IPS=$(ips_only "$TARGETS")
    nmap -Pn $(nmap_bound_args) -p21 --script 'ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor' \
        -iL <(echo "$IPS") -oA "$OUT/nmap-ftp" >/dev/null 2>&1 || true
fi

log "ftp dispatcher done."
