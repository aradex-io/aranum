#!/usr/bin/env bash
# enum-dns.sh — AXFR + SOA / NS / version.bind.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "dns: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

for ip in $IPS; do
    mkdir -p "$OUT/$ip"

    # version.bind
    dig @"$ip" version.bind chaos txt +short \
        > "$OUT/$ip/version.txt" 2>&1 || true

    # zone transfer if we have a domain
    if [ -n "${ENUM_DOMAIN:-}" ]; then
        dig @"$ip" "$ENUM_DOMAIN" axfr \
            > "$OUT/$ip/axfr_${ENUM_DOMAIN}.txt" 2>&1 || true
        # SOA, NS, MX
        for rr in SOA NS MX TXT; do
            dig @"$ip" "$ENUM_DOMAIN" "$rr" +short \
                > "$OUT/$ip/${rr}.txt" 2>&1 || true
        done
    fi

    # Reverse PTR sweep against discovered DCs (only useful if you have a target net)
    # Skipping by default — left as a hint
done

# dnsrecon if available + domain known
if have dnsrecon && [ -n "${ENUM_DOMAIN:-}" ]; then
    for ip in $IPS; do
        dnsrecon -d "$ENUM_DOMAIN" -n "$ip" -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
            > "$OUT/dnsrecon_${ip}.txt" 2>&1 || true
    done
fi

log "dns dispatcher done."
