#!/usr/bin/env bash
# enum-smtp.sh — SMTP discovery dispatcher.
# Banner + EHLO capability matrix + STARTTLS + VRFY/EXPN/RCPT probe + open-relay quick test.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "smtp: $(wc -l < "$TARGETS") targets -> $OUT"

probe_one() {
    local target="$1"
    read -r ip port <<< "$(split_ipport "$target")"
    local hostport="${ip}_${port}"
    local d="$OUT/$hostport"
    mkdir -p "$d"

    # 1. Banner
    {
        echo "QUIT" | timeout 5 nc -nv "$ip" "$port" 2>&1 | head -5
    } > "$d/banner.txt"

    # 2. EHLO capabilities
    {
        printf 'EHLO recon.local\r\nQUIT\r\n' | timeout 5 nc -nv "$ip" "$port" 2>&1
    } > "$d/ehlo.txt"

    # 3. VRFY/EXPN test (try a known nonexistent and a known-likely user)
    {
        echo "--- VRFY root ---"
        printf 'EHLO recon.local\r\nVRFY root\r\nVRFY nonexistent_xyzzy_user\r\nEXPN root\r\nQUIT\r\n' | timeout 5 nc -nv "$ip" "$port" 2>&1
    } > "$d/vrfy_expn.txt"

    # 4. STARTTLS probe — does the server offer encryption, and what cert?
    if echo "$EHLO_OUT" 2>/dev/null | grep -qi starttls || grep -qi starttls "$d/ehlo.txt"; then
        echo | timeout 10 openssl s_client -connect "$ip:$port" -starttls smtp -servername "$ip" \
            > "$d/starttls.txt" 2>&1
    fi

    # 5. Open-relay smoke test (single canonical form — relay if accepted)
    {
        printf 'EHLO recon.local\r\nMAIL FROM:<probe@external.example>\r\nRCPT TO:<target@external.example>\r\nQUIT\r\n' \
            | timeout 5 nc -nv "$ip" "$port" 2>&1
    } > "$d/relay_probe.txt"

    # 6. Flag if it accepted the RCPT (250) — that's strong open-relay signal
    if grep -E '^250.*Ok|^250.*Accepted|^250.*OK' "$d/relay_probe.txt" >/dev/null; then
        hit "$ip:$port  OPEN RELAY CANDIDATE — see $d/relay_probe.txt"
        echo "$ip:$port" >> "$OUT/_open_relay_candidates.txt"
    fi

    # 7. Flag VRFY enabled
    if grep -E '^250.*root|^252' "$d/vrfy_expn.txt" >/dev/null; then
        hit "$ip:$port  VRFY enabled — user enum possible"
        echo "$ip:$port" >> "$OUT/_vrfy_enabled.txt"
    fi

    # 8. Fingerprint banner version
    BANNER=$(head -1 "$d/banner.txt" 2>/dev/null)
    log "$ip:$port  banner: ${BANNER:0:80}"
}

export -f probe_one split_ipport hit log
export OUT

while read -r t; do
    [ -z "$t" ] && continue
    probe_one "$t" &
    while [ "$(jobs -rp | wc -l)" -ge "${ENUM_PARALLEL:-4}" ]; do sleep 0.1; done
done < "$TARGETS"
wait

# nmap NSE — SMTP-specific scripts in one pass
if have nmap; then
    log "nmap smtp-* NSE scripts"
    IPS=$(ips_only "$TARGETS")
    nmap -Pn $(nmap_bound_args) -p25,465,587,2525 --script 'smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-*,smtp-ntlm-info' \
        -iL <(echo "$IPS") -oA "$OUT/nmap-smtp" >/dev/null 2>&1 || true
fi

log "smtp dispatcher done. Tip: see standalones/smtp/ toolkit for deep enum (relay variations, user enum, phishing send)"
