#!/usr/bin/env bash
# smtp-user-enum.sh — timing-aware user enumeration via VRFY/EXPN/RCPT.
#
# Three methods (chosen automatically by what the server accepts):
#   1. VRFY method:   VRFY <user>   ->  250 (exists) vs 550 (doesn't)
#   2. EXPN method:   EXPN <user>   ->  250 + member list
#   3. RCPT method:   MAIL FROM:<x>; RCPT TO:<user>   -> 250 vs 550
#                     This is the most reliable — works against Postfix/Sendmail/Exim
#                     even when VRFY/EXPN are off, because mail acceptance has to
#                     resolve the recipient.
#
# Timing: also measures response time as a secondary signal — even when the
# server returns "OK" for every recipient (catch-all), real users tend to take
# fractionally longer because of LMTP lookup.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_smtp_lib.sh"

TARGET=""
USERS_FILE=""
DOMAIN=""
METHOD="auto"
EHLO_NAME="recon.local"
DELAY=0.05
OUT="smtp-users.txt"

while [ $# -gt 0 ]; do
    case "$1" in
        --target)   TARGET="$2"; shift 2 ;;
        --users)    USERS_FILE="$2"; shift 2 ;;
        --domain)   DOMAIN="$2"; shift 2 ;;
        --method)   METHOD="$2"; shift 2 ;;
        --ehlo)     EHLO_NAME="$2"; shift 2 ;;
        --delay)    DELAY="$2"; shift 2 ;;
        --output|-o) OUT="$2"; shift 2 ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port --users file [options]

Options:
  --users FILE       one username per line (try /usr/share/seclists/Usernames/Names/names.txt)
  --domain DOMAIN    append @DOMAIN to RCPT TO addresses (default: <user> bare)
  --method auto|vrfy|expn|rcpt   probe method (default: auto-detect)
  --ehlo NAME        EHLO hostname (default: $EHLO_NAME)
  --delay SECONDS    per-attempt delay (default: $DELAY)
  --output FILE      results file (default: $OUT)
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
[ -z "$USERS_FILE" ] || [ ! -f "$USERS_FILE" ] && { err "--users <file> required"; exit 1; }
parse_target "$TARGET"

# Auto-detect method
if [ "$METHOD" = "auto" ]; then
    ehlo_out=$(smtp_send "$HOST" "$PORT" "$(smtp_dialog "EHLO $EHLO_NAME" 'QUIT')")
    if echo "$ehlo_out" | grep -qi 'VRFY'; then
        METHOD=vrfy
    elif echo "$ehlo_out" | grep -qi 'EXPN'; then
        METHOD=expn
    else
        METHOD=rcpt
    fi
fi
log "Method: $METHOD   Target: $HOST:$PORT   Domain: ${DOMAIN:-(bare)}"

# Calibration — first send a known-bad to get the "doesn't exist" response shape
calibrate() {
    local bad="nonexistent_xyzzy_$$_$(date +%s%N)"
    local addr="$bad"
    [ -n "$DOMAIN" ] && addr="${bad}@${DOMAIN}"
    local dialog
    case "$METHOD" in
        vrfy) dialog=$(smtp_dialog "EHLO $EHLO_NAME" "VRFY $bad" "QUIT") ;;
        expn) dialog=$(smtp_dialog "EHLO $EHLO_NAME" "EXPN $bad" "QUIT") ;;
        rcpt) dialog=$(smtp_dialog "EHLO $EHLO_NAME" "MAIL FROM:<probe@$EHLO_NAME>" "RCPT TO:<$addr>" "QUIT") ;;
    esac
    smtp_send "$HOST" "$PORT" "$dialog" 5 | grep -oE '^[2-5][0-9][0-9]' | tail -1
}
NEG_CODE=$(calibrate)
log "Negative-response code: $NEG_CODE"

probe_user() {
    local u="$1"
    local addr="$u"
    [ -n "$DOMAIN" ] && addr="${u}@${DOMAIN}"
    local dialog
    case "$METHOD" in
        vrfy) dialog=$(smtp_dialog "EHLO $EHLO_NAME" "VRFY $u" "QUIT") ;;
        expn) dialog=$(smtp_dialog "EHLO $EHLO_NAME" "EXPN $u" "QUIT") ;;
        rcpt) dialog=$(smtp_dialog "EHLO $EHLO_NAME" "MAIL FROM:<probe@$EHLO_NAME>" "RCPT TO:<$addr>" "QUIT") ;;
    esac

    local t0 t1 dur
    t0=$(date +%s%N)
    local response
    response=$(smtp_send "$HOST" "$PORT" "$dialog" 5)
    t1=$(date +%s%N)
    dur=$(( (t1 - t0) / 1000000 ))   # ms

    # Pull the response code matching the probing command (NOT the EHLO 250)
    local code
    case "$METHOD" in
        vrfy|expn)
            code=$(echo "$response" | grep -E '^[2-5][0-9][0-9]' | grep -v '250.*Hello\|250.*at your service\|220 ' | head -1 | grep -oE '^[2-5][0-9][0-9]') ;;
        rcpt)
            # Walk to the third 25x/55x (after EHLO and MAIL FROM)
            code=$(echo "$response" | grep -E '^[2-5][0-9][0-9]' | head -3 | tail -1 | grep -oE '^[2-5][0-9][0-9]') ;;
    esac
    [ -z "$code" ] && code="???"

    echo "$u|$code|${dur}ms"
}

: > "$OUT"
while read -r u; do
    [ -z "$u" ] || [[ "$u" == "#"* ]] && continue
    result=$(probe_user "$u")
    code=$(echo "$result" | cut -d'|' -f2)
    if [ "$code" != "$NEG_CODE" ] && [ "$code" != "???" ]; then
        printf "%s[+] EXISTS%s  %s\n" "$_G" "$_RST" "$result"
        echo "$result" >> "$OUT"
    else
        printf "%s[-]%s        %s\n" "$_Y" "$_RST" "$result"
    fi
    sleep "$DELAY"
done < "$USERS_FILE"

echo
hit "$(wc -l < "$OUT") users identified — see $OUT"
