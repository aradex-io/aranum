#!/usr/bin/env bash
# enum-ssh.sh — SSH banner / algos / auth method enumeration + cred check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "ssh: $(wc -l < "$TARGETS") targets -> $OUT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    # 1. Banner
    nc -nv -w 5 "$ip" "$port" </dev/null > "$OUT/$ip/banner.txt" 2>&1 || true

    # 2. ssh-audit
    if have ssh-audit; then
        ssh-audit -p "$port" "$ip" > "$OUT/$ip/ssh-audit.txt" 2>&1 || true
    fi

    # 3. Supported auth methods via verbose connect
    ssh -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o PasswordAuthentication=no -o BatchMode=yes \
        -o PreferredAuthentications=none "${ENUM_USER:-root}@$ip" 2>&1 |
        grep -i 'authentication methods' > "$OUT/$ip/auth_methods.txt" || true
done < "$TARGETS"

# nxc ssh cred check
if (have nxc || have netexec) && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
    NXC=$(command -v nxc || command -v netexec)
    log "nxc ssh (cred check)"
    ips_only "$TARGETS" | \
        "$NXC" ssh - -u "$ENUM_USER" -p "$ENUM_PASS" \
        > "$OUT/nxc_ssh.txt" 2>&1 || true
fi

log "ssh dispatcher done."
