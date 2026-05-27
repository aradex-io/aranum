#!/usr/bin/env bash
# smtp-quickwin.sh — detection + exploitability tier.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_smtp_lib.sh"

TARGETS=""; TARGET=""; OUT="./smtp-quickwin"; PARALLEL=4
EHLO_NAME="recon.local"

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2 ;;
        --targets)   TARGETS="$2"; shift 2 ;;
        --output|-o) OUT="$2"; shift 2 ;;
        --ehlo)      EHLO_NAME="$2"; shift 2 ;;
        --parallel)  PARALLEL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --target HOST:PORT | --targets file [-o dir]"
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT"
: > "$OUT/_tiers.tsv"

scan_one() {
    local t="$1"
    parse_target "$t"
    local d="$OUT/${HOST}_${PORT}"
    mkdir -p "$d"
    local tier="LOW" reason=""

    # 1. Banner + EHLO
    local banner ehlo
    banner=$(smtp_send "$HOST" "$PORT" "$(smtp_dialog 'QUIT')" 5)
    ehlo=$(smtp_send "$HOST" "$PORT" "$(smtp_dialog "EHLO $EHLO_NAME" "QUIT")" 8)
    echo "$banner" > "$d/banner.txt"
    echo "$ehlo"   > "$d/ehlo.txt"

    # Parse features
    local has_starttls=0 has_vrfy=0 has_expn=0 auth_mechs=""
    grep -qi 'STARTTLS' "$d/ehlo.txt" && has_starttls=1
    grep -qi '^250.VRFY\|250 VRFY' "$d/ehlo.txt" && has_vrfy=1
    grep -qi '^250.EXPN\|250 EXPN' "$d/ehlo.txt" && has_expn=1
    auth_mechs=$(grep -i '^250.AUTH' "$d/ehlo.txt" | tail -1 | sed 's/.*AUTH//I' | tr -d '\r')

    # Banner fingerprint
    local banner_first
    banner_first=$(head -1 "$d/banner.txt")

    # 2. Open relay smoke test — try ONE canonical form
    local relay
    relay=$(smtp_send "$HOST" "$PORT" \
        "$(smtp_dialog "EHLO $EHLO_NAME" "MAIL FROM:<probe@external.example>" \
                       "RCPT TO:<external@external.example>" "QUIT")" 8)
    echo "$relay" > "$d/relay_probe.txt"
    local relay_open=0
    grep -E '^250[-\s]+(2\.[0-9.]+\s+)?(Ok|OK|Accepted|Recipient)' "$d/relay_probe.txt" >/dev/null && relay_open=1

    # 3. Internal relay test — receiving mail for an internal-looking recipient
    local internal_domain="${HOST}"
    local internal
    internal=$(smtp_send "$HOST" "$PORT" \
        "$(smtp_dialog "EHLO $EHLO_NAME" \
            "MAIL FROM:<probe@${internal_domain}>" \
            "RCPT TO:<postmaster@${internal_domain}>" "QUIT")" 8)
    echo "$internal" > "$d/internal_relay.txt"
    local internal_ok=0
    grep -E '^250.*(Ok|OK|Accepted)' "$d/internal_relay.txt" >/dev/null && internal_ok=1

    # 4. VRFY user-enumeration test
    if [ "$has_vrfy" = "1" ]; then
        local vrfy_out
        vrfy_out=$(smtp_send "$HOST" "$PORT" \
            "$(smtp_dialog "EHLO $EHLO_NAME" "VRFY root" "VRFY nonexistent_xyzzy_user_12345" "QUIT")" 5)
        echo "$vrfy_out" > "$d/vrfy.txt"
    fi

    # 5. STARTTLS cert
    if [ "$has_starttls" = "1" ]; then
        echo | timeout 8 openssl s_client -connect "$HOST:$PORT" -starttls smtp -servername "$HOST" \
            > "$d/starttls.txt" 2>&1
    fi

    # Classify
    if [ "$relay_open" = "1" ]; then
        tier="CRITICAL"; reason="OPEN RELAY — sender spoofing + external phish vehicle"
    elif [ "$internal_ok" = "1" ]; then
        tier="CRITICAL"; reason="internal-domain relay accepted unauth — internal phishing pivot"
    elif [ "$has_vrfy" = "1" ] || [ "$has_expn" = "1" ]; then
        tier="HIGH"; reason="VRFY/EXPN enabled — user enumeration possible"
    elif [ "$has_starttls" = "0" ]; then
        tier="MEDIUM"; reason="no STARTTLS offered — passive auth interception if MitM possible"
    else
        tier="LOW"; reason="standard SMTP, no immediate primitive"
    fi

    # Banner version is also informative
    grep -qiE 'Exim ([1-3]\.|4\.([0-8][0-9]|9[0-1]))' "$d/banner.txt" && {
        tier="CRITICAL"; reason="$reason; Exim version <=4.91 — CVE-2019-10149 / CVE-2019-15846 candidate"
    }

    {
        echo "Target: $HOST:$PORT"
        echo "Banner: $banner_first"
        echo "STARTTLS: $has_starttls  VRFY: $has_vrfy  EXPN: $has_expn"
        echo "AUTH mechs: $auth_mechs"
        echo "relay_open=$relay_open  internal_ok=$internal_ok"
        echo
        echo "Tier:   $tier"
        echo "Reason: $reason"
    } > "$d/summary.txt"

    case "$tier" in
        CRITICAL) printf "%s[!!] %-22s CRITICAL%s  %s\n" "$_R" "$HOST:$PORT" "$_RST" "$reason" ;;
        HIGH)     printf "%s[+]  %-22s HIGH%s      %s\n" "$_G" "$HOST:$PORT" "$_RST" "$reason" ;;
        MEDIUM)   printf "%s[*]  %-22s MEDIUM%s    %s\n" "$_C" "$HOST:$PORT" "$_RST" "$reason" ;;
        LOW)      printf "%s[-]  %-22s LOW%s       %s\n" "$_Y" "$HOST:$PORT" "$_RST" "$reason" ;;
    esac
    echo "$tier|$HOST:$PORT|$reason" >> "$OUT/_tiers.tsv"
}

export -f scan_one parse_target smtp_send smtp_dialog have log hit miss err crit
export OUT EHLO_NAME _G _Y _R _C _RST

if [ -n "$TARGET" ]; then
    scan_one "$TARGET"
elif [ -n "$TARGETS" ]; then
    xargs -a "$TARGETS" -n1 -P"$PARALLEL" -I{} bash -c 'scan_one "$@"' _ {}
else
    err "specify --target or --targets"; exit 1
fi

echo
echo "================== SUMMARY =================="
sort "$OUT/_tiers.tsv" | awk -F'|' '{count[$1]++} END {for (t in count) printf "  %-9s %d\n", t, count[t]}' | sort
echo "Detailed reports: $OUT/"
