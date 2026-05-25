#!/usr/bin/env bash
# enum-unknown.sh — generic enumeration for ports that match no service category.
#
# Strategy (each is best-effort, results dropped per ip_port dir):
#   1. Raw TCP banner grab (5s)
#   2. HTTP probe (both schemes) — many oddball ports turn out to be web
#   3. nmap -sV --version-all -sC for baseline service ID + default NSE
#   4. targeted NSE follow-up: http-* for HTTP-like ports, ssl-* for TLS,
#      and protocol NSE sets for obvious SSH/FTP/SMTP/Redis/VNC/RDP banners
#   5. nuclei (if installed) with no tag filter — catches generic exposures
#   6. amap if present — alt protocol fingerprinter
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "unknown: $(wc -l < "$TARGETS") targets -> $OUT"

# Sanitize ip:port -> ip_port for directory names (and strip brackets)
safe() { echo "$1" | tr -d '[]' | tr ':' '_'; }

append_unique() {
    local line="$1" file="$2"
    touch "$file"
    grep -Fxq "$line" "$file" 2>/dev/null || printf "%s\n" "$line" >> "$file"
}

run_grouped_nmap() {
    local label="$1" script_expr="$2" targets_file="$3"
    [ -s "$targets_file" ] || return 0
    : > "$OUT/_per_host_ports_${label}.txt.tmp"
    while read -r t; do
        [ -z "$t" ] && continue
        read -r ip port <<< "$(split_ipport "$t")"
        echo "$ip $port" >> "$OUT/_per_host_ports_${label}.txt.tmp"
    done < "$targets_file"
    awk '{ports[$1]=ports[$1]","$2} END{for(ip in ports){p=substr(ports[ip],2); print ip" "p}}' \
        "$OUT/_per_host_ports_${label}.txt.tmp" > "$OUT/_per_host_ports_${label}.txt"
    rm -f "$OUT/_per_host_ports_${label}.txt.tmp"

    local script_timeout="${ENUM_NMAP_SCRIPT_TIMEOUT:-45s}"
    local host_timeout="${ENUM_NMAP_HOST_TIMEOUT:-6m}"
    log "nmap targeted NSE (${label}: ${script_expr}) on $(wc -l < "$targets_file") target(s)"
    while read -r ip ports; do
        nmap -Pn -n -sV --version-all "${THROTTLE_NMAP_ARGS[@]}" \
            --script "$script_expr" \
            --script-timeout "$script_timeout" --host-timeout "$host_timeout" \
            -p "$ports" "$ip" \
            -oN "$OUT/$(safe "$ip:_")_nmap_${label}.txt" \
            >/dev/null 2>&1 &
        while [ "$(jobs -rp | wc -l)" -ge "${ENUM_PARALLEL:-4}" ]; do sleep 0.2; done
    done < "$OUT/_per_host_ports_${label}.txt"
    wait
}

if ! awk 'NF { found = 1; exit } END { exit found ? 0 : 1 }' "$TARGETS"; then
    : > "$OUT/_findings.txt"
    {
        echo "=== Probable HTTP (got HTTP response header) ==="
        echo
        echo "=== Got a non-empty banner ==="
        echo
        echo "=== nmap identified service !=unknown ==="
    } > "$OUT/_summary.txt"
    log "unknown dispatcher done. See $OUT/_summary.txt and $OUT/_findings.txt"
    exit 0
fi

# ---------- 1 + 2. banner + HTTP probe per target (parallel) ----------
banner_probe() {
    read -r ip port <<< "$(split_ipport "$1")"
    d="$OUT/$(safe "$1")"
    mkdir -p "$d"
    printf "%s\n" "$1" > "$d/target.txt"
    printf "%s\n" "$ip" > "$d/ip.txt"
    printf "%s\n" "$port" > "$d/port.txt"
    # Raw banner — many services emit a greeting; HTTP requires a request
    {
        echo "=== raw connect ==="
        timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$port; head -c 512 <&3" 2>/dev/null | strings
        echo
        echo "=== send newline (often triggers prompt) ==="
        printf "\r\n\r\n" | timeout 5 nc -nv -w 3 "$ip" "$port" 2>&1 | head -50
    } > "$d/banner.txt" 2>&1

    # HTTP — try both schemes; harmless if not HTTP
    for scheme in http https; do
        timeout 5 curl -ksI --max-time 5 "$scheme://$ip:$port/" \
            > "$d/http_${scheme}.txt" 2>&1 || true
        # 0-byte responses are noise
        [ -s "$d/http_${scheme}.txt" ] || rm -f "$d/http_${scheme}.txt"
    done

    # Mark interesting results
    if [ -s "$d/banner.txt" ] && grep -qE 'SSH-|HTTP/|RFB |^220 |^\* OK |Welcome|VNC|MySQL|PostgreSQL|Redis|smtp|220 ProFTPD|\+OK|<\?xml' "$d/banner.txt"; then
        protocol=$(grep -oE 'SSH-[0-9.]+|HTTP/[0-9.]+|RFB [0-9.]+|VNC|MySQL|PostgreSQL|Redis|<\?xml|220 .*' "$d/banner.txt" | head -1)
        printf "\033[1;32m[+]\033[0m %s -> %s\n" "$1" "$protocol" | tee -a "$OUT/_findings.txt"
    fi
}
export -f banner_probe safe split_ipport
export OUT

log "banner + http probe (parallel=${ENUM_PARALLEL:-4})"
xargs -a "$TARGETS" -P"${ENUM_PARALLEL:-4}" -I{} bash -c 'banner_probe "$@"' _ {}

# ---------- 3. nmap -sV baseline against the unknown set in one pass ----------
if have nmap; then
    log "nmap -sV -sC baseline (version + default scripts) on unknown ports"
    # Build a port spec grouped by host so nmap can do them efficiently
    # Simpler: just feed ip + port as -p arg per host; do it per host serially with light parallelism
    # nmap can handle a -p list per scan, so coalesce ports per ip
    # Coalesce ports per host (IPv4 + bracketed IPv6 safe)
    : > "$OUT/_per_host_ports.txt.tmp"
    while read -r t; do
        [ -z "$t" ] && continue
        read -r ip port <<< "$(split_ipport "$t")"
        echo "$ip $port" >> "$OUT/_per_host_ports.txt.tmp"
    done < "$TARGETS"
    awk '{ports[$1]=ports[$1]","$2} END{for(ip in ports){p=substr(ports[ip],2); print ip" "p}}' \
        "$OUT/_per_host_ports.txt.tmp" > "$OUT/_per_host_ports.txt"
    rm -f "$OUT/_per_host_ports.txt.tmp"
    while read -r ip ports; do
        nmap -Pn -n -sV --version-all -sC "${THROTTLE_NMAP_ARGS[@]}" \
            --script-timeout "${ENUM_NMAP_SCRIPT_TIMEOUT:-45s}" \
            --host-timeout "${ENUM_NMAP_HOST_TIMEOUT:-6m}" \
            -p "$ports" "$ip" \
            -oN "$OUT/$(safe "$ip:_")_nmap.txt" \
            >/dev/null 2>&1 &
        # Throttle
        while [ "$(jobs -rp | wc -l)" -ge "${ENUM_PARALLEL:-4}" ]; do sleep 0.2; done
    done < "$OUT/_per_host_ports.txt"
    wait
fi

# ---------- 4. targeted NSE follow-up ----------
if have nmap; then
    : > "$OUT/_http_targets.txt"
    : > "$OUT/_tls_targets.txt"
    : > "$OUT/_ssh_targets.txt"
    : > "$OUT/_ftp_targets.txt"
    : > "$OUT/_smtp_targets.txt"
    : > "$OUT/_redis_targets.txt"
    : > "$OUT/_vnc_targets.txt"
    : > "$OUT/_rdp_targets.txt"

    while read -r t; do
        [ -z "$t" ] && continue
        d="$OUT/$(safe "$t")"
        [ -d "$d" ] || continue
        if grep -hE '^HTTP/' "$d"/http_*.txt "$d/banner.txt" >/dev/null 2>&1; then
            append_unique "$t" "$OUT/_http_targets.txt"
        fi
        if [ -s "$d/http_https.txt" ] \
           || grep -hEi 'ssl|tls|certificate|HTTPS' "$d"/http_*.txt "$d/banner.txt" >/dev/null 2>&1; then
            append_unique "$t" "$OUT/_tls_targets.txt"
        fi
        grep -hE 'SSH-[0-9.]+' "$d/banner.txt" >/dev/null 2>&1 && append_unique "$t" "$OUT/_ssh_targets.txt"
        grep -hEi '(^220 .*FTP|ftp server|FileZilla|ProFTPD|vsftpd)' "$d/banner.txt" >/dev/null 2>&1 && append_unique "$t" "$OUT/_ftp_targets.txt"
        grep -hEi '(^220 .*smtp|ESMTP|Postfix|Exim|Sendmail)' "$d/banner.txt" >/dev/null 2>&1 && append_unique "$t" "$OUT/_smtp_targets.txt"
        grep -hEi '(Redis|^-ERR|^\+PONG)' "$d/banner.txt" >/dev/null 2>&1 && append_unique "$t" "$OUT/_redis_targets.txt"
        grep -hEi '(RFB [0-9.]|VNC)' "$d/banner.txt" >/dev/null 2>&1 && append_unique "$t" "$OUT/_vnc_targets.txt"
        grep -hEi '(CredSSP|NTLMSSP|ms-wbt-server|RDP)' "$d/banner.txt" >/dev/null 2>&1 && append_unique "$t" "$OUT/_rdp_targets.txt"
    done < "$TARGETS"

    # Operator can override these expressions if a lab needs the full script
    # family. Defaults are aggressive enough to fingerprint, but skip brute,
    # DoS, and external scripts so unknown-port triage stays safe by default.
    run_grouped_nmap "http_nse"  "${ENUM_UNKNOWN_HTTP_NSE:-http-* and not brute and not dos and not external}" "$OUT/_http_targets.txt"
    run_grouped_nmap "tls_nse"   "${ENUM_UNKNOWN_TLS_NSE:-ssl-* and not brute and not dos and not external}" "$OUT/_tls_targets.txt"
    run_grouped_nmap "ssh_nse"   "${ENUM_UNKNOWN_SSH_NSE:-ssh2-enum-algos,ssh-hostkey,ssh-auth-methods}" "$OUT/_ssh_targets.txt"
    run_grouped_nmap "ftp_nse"   "${ENUM_UNKNOWN_FTP_NSE:-ftp-anon,ftp-syst,ftp-bounce}" "$OUT/_ftp_targets.txt"
    run_grouped_nmap "smtp_nse"  "${ENUM_UNKNOWN_SMTP_NSE:-smtp-commands,smtp-ntlm-info,smtp-open-relay}" "$OUT/_smtp_targets.txt"
    run_grouped_nmap "redis_nse" "${ENUM_UNKNOWN_REDIS_NSE:-redis-info}" "$OUT/_redis_targets.txt"
    run_grouped_nmap "vnc_nse"   "${ENUM_UNKNOWN_VNC_NSE:-vnc-info,realvnc-auth-bypass}" "$OUT/_vnc_targets.txt"
    run_grouped_nmap "rdp_nse"   "${ENUM_UNKNOWN_RDP_NSE:-rdp-enum-encryption,rdp-ntlm-info}" "$OUT/_rdp_targets.txt"
fi

# ---------- 5. nuclei (no tag filter) ----------
# Honors NO_NUCLEI=1, NUCLEI_TIMEOUT, NUCLEI_RATE — same as enum-http.sh.
if [ "${NO_NUCLEI:-0}" = "1" ]; then
    log "nuclei skipped (NO_NUCLEI=1)"
elif have nuclei; then
    TPL_DIR="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"
    if [ ! -d "$TPL_DIR" ] || [ -z "$(ls -A "$TPL_DIR" 2>/dev/null)" ]; then
        miss "nuclei templates not found ($TPL_DIR) — skipping. Run 'nuclei -update-templates' once, or pass NO_NUCLEI=1 to silence."
    else
        # Turn ip:port lines into both http and tcp probes; nuclei auto-detects
        sed 's|^|http://|' "$TARGETS" >  "$OUT/_nuclei_urls.txt"
        sed 's|^|https://|' "$TARGETS" >> "$OUT/_nuclei_urls.txt"
        cat "$TARGETS"                  >> "$OUT/_nuclei_urls.txt"   # raw ip:port for tcp templates
        NUC_TO="${NUCLEI_TIMEOUT:-600}"
        NUC_RATE="${NUCLEI_RATE:-150}"
        log "nuclei (network templates only, timeout ${NUC_TO}s, rate ${NUC_RATE})"
        timeout --kill-after=10 "$NUC_TO" nuclei \
            -l "$OUT/_nuclei_urls.txt" -tags network,tcp,default-logins,exposure -silent \
            -rate-limit "$NUC_RATE" -timeout 8 -retries 1 \
            -max-host-error 3 -disable-update-check -stats-interval 30 \
            -o "$OUT/nuclei.txt" >/dev/null 2>&1
        rc=$?
        if   [ "$rc" -eq 124 ]; then err "nuclei wall-clock timeout (${NUC_TO}s) — partial results in $OUT/nuclei.txt"
        elif [ "$rc" -ne 0 ];   then miss "nuclei exited $rc (non-fatal)"
        fi
    fi
fi

# ---------- 6. amap (legacy but still useful) ----------
if have amap; then
    log "amap fingerprinting"
    while read -r t; do
        [ -z "$t" ] && continue
        read -r ip port <<< "$(split_ipport "$t")"
        amap -b "$ip" "$port" >> "$OUT/amap.txt" 2>&1 || true
    done < "$TARGETS"
fi

# ---------- 6. summarize what looks promising ----------
log "Summarizing"
{
    echo "=== Probable HTTP (got HTTP response header) ==="
    grep -lE '^HTTP/' "$OUT"/*/http_*.txt 2>/dev/null | sed "s|$OUT/||;s|/http_.*||"
    echo
    echo "=== Got a non-empty banner ==="
    find "$OUT" -name banner.txt -size +20c 2>/dev/null | sed "s|$OUT/||;s|/banner.txt||"
    echo
    echo "=== nmap identified service !=unknown ==="
    grep -E '^[0-9]+/tcp +open +[a-z]' "$OUT"/*_nmap.txt 2>/dev/null | grep -v 'unknown\|tcpwrapped'
    echo
    echo "=== Targeted NSE follow-up files ==="
    find "$OUT" -maxdepth 1 -name '*_nmap_*_nse.txt' -type f 2>/dev/null | sed "s|$OUT/||" | sort
} > "$OUT/_summary.txt"

log "unknown dispatcher done. See $OUT/_summary.txt and $OUT/_findings.txt"
