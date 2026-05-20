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

# ---------- iteration C.14: key-only refusal + CVE-2018-15473 hints ----------
# 1) Key-only refusal — if we found "publickey" but not "password" in auth_methods,
#    surface a refusal to spray (separate spray tool, not bundled here).
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    am_file="$OUT/$ip/auth_methods.txt"
    [ ! -s "$am_file" ] && continue
    if grep -qiE 'publickey' "$am_file" && ! grep -qiE 'password|keyboard-interactive' "$am_file"; then
        echo "KEY_ONLY: $ip:$port advertises publickey only — refuse password spray" \
            > "$OUT/$ip/_key_only_${port}.txt"
        log "  $ip:$port key-only — password spray would be wasted RTT + log noise"
    fi
done < "$TARGETS"

# 2) CVE-2018-15473 user-enum hint (timing oracle in pre-7.7 OpenSSH).
#    Detection is genuine timing-based and requires a calibration phase
#    against a known-good and known-bad username. We surface the version
#    range here; operator runs the dedicated probe (`paramiko_cve_2018_15473`
#    in msf or our future jabber-style helper) if they want to harvest names.
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    banner_file="$OUT/$ip/banner.txt"
    [ ! -s "$banner_file" ] && continue
    ver=$(grep -oE 'OpenSSH_[0-9]+\.[0-9]+' "$banner_file" | head -1 | sed 's/OpenSSH_//')
    [ -z "$ver" ] && continue
    # Vulnerable range: pre-7.7 (any 5.x, 6.x, 7.0-7.6)
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if [ "$major" -lt 7 ] || { [ "$major" -eq 7 ] && [ "$minor" -lt 7 ]; }; then
        echo "OpenSSH $ver — vulnerable to CVE-2018-15473 user-enum timing oracle" \
            > "$OUT/$ip/_cve-2018-15473_signal_${port}.txt"
        hit "CVE-2018-15473 candidate: $ip:$port OpenSSH $ver"
    fi
done < "$TARGETS"

log "ssh dispatcher done."
