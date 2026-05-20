#!/usr/bin/env bash
# smtp-relay-test.sh — open relay tester with the 19 classical variations.
#
# A "closed" SMTP server should only relay mail FOR its own domains.
# Servers commonly fail in unexpected ways: the canonical RCPT TO form is
# rejected but routed forms (%-encoded, !-bang paths, source routing,
# unbracketed addresses) get through.
#
# Sends a probe email through each variation; non-2xx after RCPT TO means
# that variation is blocked. Any 250 after RCPT TO means relay is open
# via that form -- and you should immediately follow with smtp-phish-send.sh.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_smtp_lib.sh"

TARGET=""
FROM_DOMAIN="external.example"
TO_USER="probe"
TO_DOMAIN="external.example"
INTERNAL_DOMAIN=""        # for routed forms like "@internal:to@external"
EHLO_NAME="recon.local"

while [ $# -gt 0 ]; do
    case "$1" in
        --target)          TARGET="$2"; shift 2 ;;
        --from-domain)     FROM_DOMAIN="$2"; shift 2 ;;
        --to-user)         TO_USER="$2"; shift 2 ;;
        --to-domain)       TO_DOMAIN="$2"; shift 2 ;;
        --internal-domain) INTERNAL_DOMAIN="$2"; shift 2 ;;
        --ehlo)            EHLO_NAME="$2"; shift 2 ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port --internal-domain CORP.LOCAL [--to-domain external.example]
  --internal-domain   the target's own domain (so we can construct routed forms)
  --to-domain         external recipient domain (default: example.com)
  --to-user           recipient user (default: probe)
  --from-domain       envelope-from domain (default: external.example)
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
[ -z "$INTERNAL_DOMAIN" ] && { err "--internal-domain required"; exit 1; }
parse_target "$TARGET"

FROM="probe@$FROM_DOMAIN"
EXT="${TO_USER}@${TO_DOMAIN}"
INT="${TO_USER}@${INTERNAL_DOMAIN}"

# The 19 classical RFC822/routing forms (with a few modern additions)
TESTS=(
    "1|MAIL FROM:<$FROM>|RCPT TO:<$EXT>"
    "2|MAIL FROM:<$FROM>|RCPT TO:$EXT"
    "3|MAIL FROM:<$FROM>|RCPT TO:<$EXT>|<$EXT>"
    "4|MAIL FROM:<$FROM>|RCPT TO:$TO_USER%$TO_DOMAIN@$INTERNAL_DOMAIN"
    "5|MAIL FROM:<$FROM>|RCPT TO:<$TO_USER%$TO_DOMAIN@$INTERNAL_DOMAIN>"
    "6|MAIL FROM:<$FROM>|RCPT TO:$TO_USER@$TO_DOMAIN@$INTERNAL_DOMAIN"
    "7|MAIL FROM:<$FROM>|RCPT TO:<$TO_USER@$TO_DOMAIN@$INTERNAL_DOMAIN>"
    "8|MAIL FROM:<$FROM>|RCPT TO:\"$TO_USER@$TO_DOMAIN\"@$INTERNAL_DOMAIN"
    "9|MAIL FROM:<$FROM>|RCPT TO:<@$INTERNAL_DOMAIN:$EXT>"
    "10|MAIL FROM:<$FROM>|RCPT TO:$INTERNAL_DOMAIN!$EXT"
    "11|MAIL FROM:<$FROM>|RCPT TO:$INTERNAL_DOMAIN!$TO_USER@$TO_DOMAIN"
    "12|MAIL FROM:<$FROM>|RCPT TO:<$TO_USER+spam@$TO_DOMAIN>"
    "13|MAIL FROM:postmaster@$INTERNAL_DOMAIN|RCPT TO:<$EXT>"
    "14|MAIL FROM:<>|RCPT TO:<$EXT>"
    "15|MAIL FROM:<$FROM>|RCPT TO:$EXT $INTERNAL_DOMAIN"
    "16|MAIL FROM:<$FROM>|RCPT TO:<>"
    "17|MAIL FROM:<$INT>|RCPT TO:<$EXT>"
    "18|MAIL FROM:<$EXT>|RCPT TO:<$INT>"
    "19|MAIL FROM:<$FROM>|RCPT TO:<$TO_USER>"
)

printf "%-3s %-50s %-50s %-10s %s\n" "ID" "MAIL FROM" "RCPT TO" "STATUS" "INTERPRETATION"
printf -- "%.0s-" {1..170}; echo
RELAYABLE=()
for tt in "${TESTS[@]}"; do
    IFS='|' read -r id mailfrom rcptto extra <<< "$tt"
    dialog=$(smtp_dialog "EHLO $EHLO_NAME" "$mailfrom" "$rcptto" ${extra:+"$extra"} "QUIT")
    resp=$(smtp_send "$HOST" "$PORT" "$dialog" 5)
    # The third response code is the RCPT TO outcome
    rcpt_code=$(echo "$resp" | grep -E '^[2-5][0-9][0-9]' | sed -n '3p' | grep -oE '^[2-5][0-9][0-9]')
    [ -z "$rcpt_code" ] && rcpt_code="???"
    interp=""
    case "$rcpt_code" in
        250|251) interp=$(printf "%s[!! RELAY OPEN]%s" "$_R" "$_RST"); RELAYABLE+=("$id: $mailfrom -> $rcptto") ;;
        550|554) interp="closed" ;;
        553)     interp="rejected (policy)" ;;
        452|421) interp="temp-fail" ;;
        ???)     interp="no response" ;;
        *)       interp="unexpected" ;;
    esac
    printf "%-3s %-50s %-50s %-10s %s\n" "$id" "${mailfrom:0:50}" "${rcptto:0:50}" "$rcpt_code" "$interp"
done

echo
if [ "${#RELAYABLE[@]}" -gt 0 ]; then
    crit "${#RELAYABLE[@]} of ${#TESTS[@]} relay variations accepted — see above"
    printf '  %s\n' "${RELAYABLE[@]}"
    echo
    echo "Next step: smtp-phish-send.sh --target $HOST:$PORT --... (use the working variation)"
else
    hit "No relay variations accepted — server appears properly configured"
fi
