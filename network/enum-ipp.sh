#!/usr/bin/env bash
# enum-ipp.sh — IPP / CUPS printer enumeration.
#
# Internet Printing Protocol (IPP) runs over HTTP on port 631.
# CUPS (Common Unix Printing System) exposes printer lists, admin UI, and
# job queues unauthenticated on misconfigured installs.
#
# Notable CVE chain (Sept 2024):
#   CVE-2024-47176 — cups-browsed binds 0.0.0.0:631/udp, accepts any packet,
#                    registers attacker-supplied IPP URL as printer source.
#   CVE-2024-47175 — libppd writes attacker-controlled attributes to temp PPD.
#   CVE-2024-47177 — FoomaticRIPCommandLine executes attacker payload on print.
#   Combined: unauthenticated RCE when cups-browsed is reachable from LAN/WAN.
#   Patched in CUPS 2.4.10+.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "ipp: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — ipp dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- root banner ----------
    curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 -i \
        "http://$ip:$port/" \
        > "$OUT/$ip/root_${port}.txt" 2>&1 || true

    # ---------- printer list ----------
    curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
        "http://$ip:$port/printers" \
        > "$OUT/$ip/printers_${port}.txt" 2>&1 || true

    # ---------- admin UI reachability ----------
    curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
        "http://$ip:$port/admin" \
        > "$OUT/$ip/admin_${port}.txt" 2>&1 || true

    # ---------- parse Server: header ----------
    server_line=$(grep -i '^Server:' "$OUT/$ip/root_${port}.txt" 2>/dev/null | head -1 | tr -d '\r')
    if echo "$server_line" | grep -qi 'CUPS/'; then
        version=$(echo "$server_line" | grep -oE 'CUPS/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | cut -d/ -f2)
        if [ -n "$version" ]; then
            # Compare version < 2.4.10 using sort -V
            lowest=$(printf '%s\n%s\n' "$version" "2.4.10" | sort -V | head -1)
            if [ "$lowest" = "$version" ] && [ "$version" != "2.4.10" ]; then
                hit "CUPS UNAUTH and POTENTIALLY VULN (CVE-2024-47176 chain): $ip:$port — $version"
            else
                hit "CUPS UNAUTH: $ip:$port — $version"
            fi
        else
            hit "CUPS UNAUTH: $ip:$port — version unknown"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
IPP / CUPS follow-ups:
  * CVE-2024-47176 + CVE-2024-47175 + CVE-2024-47177 RCE chain (Sept 2024)
    requires reachable cups-browsed on 631/udp. Verify with:
      sudo nmap -sU -p631 --script cups-info <target>
  * Default printer URL format: ipp://<ip>:631/printers/<name>
  * Job exfil: GET /printers/<name>?which-jobs=completed lists captured docs.
EOF

log "ipp dispatcher done."
