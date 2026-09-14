#!/usr/bin/env bash
# enum-ftp.sh — FTP anonymous + cred check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
task_phase_require || exit 1
log "ftp: $(wc -l < "$TARGETS") targets -> $OUT"

ftp_discovery_phase() {
    local target ip port
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        {
            echo "--- banner ---"
            timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$port; head -1 <&3" 2>/dev/null
        } > "$OUT/$ip/ftp.txt" 2>&1 || true
    done < "$TARGETS"
}

ftp_enumeration_phase() {
    local target ip port nxc_bin nxc_port
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        {
            echo "--- anonymous listing ---"
            timeout 15 curl -s --max-time 10 "ftp://$ip:$port/" \
                --user "anonymous:anonymous@example.com" 2>&1 | head -30
        } >> "$OUT/$ip/ftp.txt" 2>&1 || true
    done < "$TARGETS"

    # nxc ftp cred check
    if (have nxc || have netexec) && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
        nxc_bin=$(command -v nxc || command -v netexec)
        : > "$OUT/nxc_ftp.txt"
        # NXC accepts one port per invocation. Group the exact selected
        # endpoints by port instead of collapsing them through ips_only;
        # otherwise every credential probe silently falls back to FTP/21.
        while IFS= read -r nxc_port; do
            [ -n "$nxc_port" ] || continue
            log "nxc ftp (cred check, port $nxc_port)"
            ip_port_pairs "$TARGETS" | \
                awk -v selected_port="$nxc_port" '$2 == selected_port { print $1 }' | \
                sort -u | \
                "$nxc_bin" ftp - --port "$nxc_port" \
                    -u "$ENUM_USER" -p "$ENUM_PASS" \
                    >> "$OUT/nxc_ftp.txt" 2>&1 || true
        done < <(ip_port_pairs "$TARGETS" | awk '{ print $2 }' | sort -nu)
    fi

    # nmap ftp scripts
    if have nmap; then
        local ips ports
        log "nmap ftp-anon + ftp-syst"
        ips=$(ips_only "$TARGETS")
        ports=$(ip_port_pairs "$TARGETS" | awk '{print $2}' | sort -nu | paste -sd, -)
        nmap -Pn $(nmap_bound_args) -p"$ports" --script 'ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor' \
            -iL <(echo "$ips") -oA "$OUT/nmap-ftp" >/dev/null 2>&1 || true
    fi
}

task_phase_run 1 ftp_discovery_phase || exit 1
task_phase_run 2 ftp_enumeration_phase || exit 1

log "ftp dispatcher done."
