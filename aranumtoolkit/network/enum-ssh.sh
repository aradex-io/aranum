#!/usr/bin/env bash
# enum-ssh.sh — SSH banner / algos / auth method enumeration + cred check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

# classify_ssh_os_from_banner <banner-text> -> echoes "linux" | "windows" | "other"
#
# Cheapest OS signal for an SSH host: the pre-auth banner string (the
# "SSH-2.0-..." line the daemon sends before any auth exchange — see the
# banner grab a few lines below, or ssh-triage.sh's own grab for the same
# text). Windows' OpenSSH port ships a distinctive banner suffix; ordinary
# OpenSSH/Sun_SSH banners are Linux/Unix; embedded drop-in implementations
# (dropbear, ROSSSH, vendor SSH stacks on network gear/appliances) are
# deliberately bucketed as "other" rather than guessed at — ssh-triage.sh
# escalates "other" to an authenticated probe when creds are available.
# Reused by both enum-ssh.sh (informational) and ssh-triage.sh (dispatch
# routing) per ADR-006 D1b-2 — extend here, not by duplicating the mapping.
classify_ssh_os_from_banner() {
    local banner="$1"
    case "$banner" in
        *SSH-2.0-OpenSSH_for_Windows_*) echo "windows" ;;
        *SSH-2.0-OpenSSH_*|*SSH-1.99-OpenSSH_*|*SSH-2.0-Sun_SSH*) echo "linux" ;;
        *) echo "other" ;;
    esac
}

# The rest of this file is the enum-ssh.sh dispatcher's main body. It is
# wrapped in a function and guarded so ssh-triage.sh can `. enum-ssh.sh` to
# pick up only classify_ssh_os_from_banner above without running a banner
# sweep / nxc cred check against whatever $TARGETS happens to be set (or
# failing outright because no --targets was given). Direct execution
# (`./enum-ssh.sh ...` or `bash enum-ssh.sh ...`) is byte-for-byte unchanged:
# BASH_SOURCE[0] == $0 in that case, so _enum_ssh_main runs immediately below.
_enum_ssh_main() {
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

# 3) regreSSHion (CVE-2024-6387) + Terrapin (CVE-2023-48795) signals.
#    regreSSHion: pre-auth RCE in OpenSSH < 4.4p1 and 8.5p1 <= x < 9.8p1.
#    Distro backports blur the version (e.g. Ubuntu patched 9.6p1-3ubuntu13.x
#    without a version bump) — signal only. Terrapin: prefix-truncation attack
#    mitigated by strict-kex in 9.6+; confirm via the negotiated ciphers.
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    banner_file="$OUT/$ip/banner.txt"
    [ ! -s "$banner_file" ] && continue
    full=$(grep -oE 'OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?' "$banner_file" | head -1 | sed 's/OpenSSH_//')
    [ -z "$full" ] && continue
    maj=$(echo "$full" | cut -d. -f1)
    min=$(echo "$full" | sed -E 's/^[0-9]+\.([0-9]+).*/\1/')
    case "$maj$min" in *[!0-9]*) continue ;; esac
    mm=$((maj * 100 + min))
    # regreSSHion: mm < 4.04  OR  8.05 <= mm < 9.08 (major*100+minor).
    if [ "$mm" -lt 404 ] || { [ "$mm" -ge 805 ] && [ "$mm" -lt 908 ]; }; then
        echo "OpenSSH $full — CVE-2024-6387 (regreSSHion) pre-auth RCE candidate (confirm distro backport revision)" \
            > "$OUT/$ip/_cve-2024-6387_signal_${port}.txt"
        hit "CVE-2024-6387 regreSSHion candidate: $ip:$port OpenSSH $full"
    fi
    # Terrapin: prefer ssh-audit's verdict; else flag pre-9.6 (no strict-kex) as a candidate.
    audit_file="$OUT/$ip/ssh-audit.txt"
    if [ -s "$audit_file" ] && grep -qi 'CVE-2023-48795' "$audit_file"; then
        echo "OpenSSH $full — CVE-2023-48795 (Terrapin) signal flagged by ssh-audit" \
            > "$OUT/$ip/_cve-2023-48795_signal_${port}.txt"
        hit "CVE-2023-48795 Terrapin (ssh-audit): $ip:$port"
    elif [ "$mm" -lt 906 ]; then
        echo "OpenSSH $full — CVE-2023-48795 (Terrapin) candidate: pre-9.6 lacks strict-kex; confirm chacha20-poly1305 / CBC-EtM offered" \
            > "$OUT/$ip/_cve-2023-48795_signal_${port}.txt"
        log "  Terrapin candidate $ip:$port (OpenSSH $full < 9.6)"
    fi
done < "$TARGETS"

log "ssh dispatcher done."
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _enum_ssh_main "$@"
fi
