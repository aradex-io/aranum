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
    if grep -qi starttls "$d/ehlo.txt"; then
        echo | timeout 10 openssl s_client -connect "$ip:$port" -starttls smtp -servername "$ip" \
            > "$d/starttls.txt" 2>&1
    fi

    # 5. Open-relay smoke test — a few high-value variants (the standalones/smtp/
    #    toolkit runs the full 19-variant matrix). external->external acceptance of
    #    the RCPT = open relay. Detection uses the SMTP final-reply convention (space
    #    after the code) and takes the last reply before QUIT, so multi-line EHLO
    #    extension lines don't get mistaken for the RCPT outcome.
    : > "$d/relay_probe.txt"
    relay_hit=""
    for variant in \
        "canonical|MAIL FROM:<probe@external.example>|RCPT TO:<target@external.example>" \
        "null-sender|MAIL FROM:<>|RCPT TO:<target@external.example>" \
        "percent-hack|MAIL FROM:<probe@external.example>|RCPT TO:<target%external.example@${ip}>" \
        "source-route|MAIL FROM:<probe@external.example>|RCPT TO:<@${ip}:target@external.example>"; do
        vid=${variant%%|*}; rest=${variant#*|}; mfrom=${rest%%|*}; rcpt=${rest#*|}
        resp=$(printf 'EHLO recon.local\r\n%s\r\n%s\r\nQUIT\r\n' "$mfrom" "$rcpt" \
                 | timeout 5 nc -nv "$ip" "$port" 2>&1)
        printf -- '--- variant: %s ---\n%s\n\n' "$vid" "$resp" >> "$d/relay_probe.txt"
        code=$(printf '%s\n' "$resp" | grep -E '^[2-5][0-9][0-9] ' | grep -vE '^221 ' | tail -1 | grep -oE '^[2-5][0-9][0-9]')
        case "$code" in 250|251) relay_hit="$relay_hit $vid" ;; esac
    done

    # 6. Flag if any external->external variant accepted the RCPT — open-relay signal
    if [ -n "$relay_hit" ]; then
        hit "$ip:$port  OPEN RELAY CANDIDATE (variants:$relay_hit) — see $d/relay_probe.txt"
        echo "$ip:$port relay-variants:$relay_hit" >> "$OUT/_open_relay_candidates.txt"
        echo "follow up: standalones/smtp/smtp-relay-test.sh for the full 19-variant matrix" >> "$d/relay_probe.txt"
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
