#!/usr/bin/env bash
# enum-ftp.sh — FTP anonymous + cred check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
task_phase_require || exit 1
log "ftp: $(wc -l < "$TARGETS") targets -> $OUT"

ftp_evidence_path() {
    local ip="$1" port="$2"
    if [ "${ENUM_TASK_CONSTRAINED:-0}" = "1" ]; then
        printf '%s/%s/ftp.txt' "$OUT" "$ip"
    else
        printf '%s/%s/ftp_%s.txt' "$OUT" "$ip" "$port"
    fi
}

ftp_discovery_phase() {
    local target ip port url_host evidence
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        evidence=$(ftp_evidence_path "$ip" "$port")
        url_host="$ip"; [[ "$ip" == *:* ]] && url_host="[$ip]"
        if [ "$port" = "990" ]; then
            {
                echo "--- implicit FTPS banner ---"
                if have openssl; then
                    printf 'QUIT\r\n' | timeout 8 openssl s_client -quiet \
                        -connect "$url_host:$port" -servername "$ip"
                else
                    echo "openssl unavailable — implicit FTPS banner skipped"
                fi
            } > "$evidence" 2>&1 || true
        else
            {
                echo "--- banner ---"
                timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$port; head -1 <&3" 2>/dev/null
            } > "$evidence" 2>&1 || true
        fi
    done < "$TARGETS"
}

ftp_enumeration_phase() {
    local target ip port url_host evidence nxc_bin nxc_port
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        evidence=$(ftp_evidence_path "$ip" "$port")
        url_host="$ip"; [[ "$ip" == *:* ]] && url_host="[$ip]"
        if [ "$port" = "990" ]; then
            {
                echo "--- anonymous implicit FTPS listing ---"
                if have curl; then
                    timeout 15 curl -ksS --ssl-reqd --max-time 10 \
                        "ftps://$url_host:$port/" --user "anonymous:anonymous@example.com" 2>&1 | head -30
                else
                    echo "curl unavailable — implicit FTPS listing skipped"
                fi
            } >> "$evidence" 2>&1 || true
        else
            {
                echo "--- anonymous listing ---"
                if have curl; then
                    timeout 15 curl -s --max-time 10 "ftp://$url_host:$port/" \
                        --user "anonymous:anonymous@example.com" 2>&1 | head -30
                else
                    echo "curl unavailable — anonymous listing skipped"
                fi
            } >> "$evidence" 2>&1 || true
        fi
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

    # Nmap accepts one endpoint per invocation here. This avoids turning a
    # mixed host/port inventory into a Cartesian product of unintended probes.
    if have nmap; then
        log "nmap ftp-anon + ftp-syst"
        while read -r target; do
            [ -z "$target" ] && continue
            read -r ip port <<< "$(split_ipport "$target")"
            mkdir -p "$OUT/$ip"
            nmap -Pn $(nmap_bound_args) -p "$port" \
                --script 'ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor' \
                "$ip" -oA "$OUT/$ip/nmap-ftp-${port}" >/dev/null 2>&1 || true
        done < "$TARGETS"
    fi
}

task_phase_run 1 ftp_discovery_phase || exit 1
task_phase_run 2 ftp_enumeration_phase || exit 1

log "ftp dispatcher done."
