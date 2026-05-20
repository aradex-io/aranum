#!/usr/bin/env bash
# smtp-phish-send.sh — send a spoofed email via a confirmed open/internal relay.
# For authorized red-team / phishing simulation. Writes the message exactly as you
# specify it -- no rate limiting, no rewrite -- so headers stay clean.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_smtp_lib.sh"

TARGET=""
FROM_ADDR=""
FROM_NAME=""
TO_ADDR=""
TO_NAME=""
SUBJECT=""
BODY_FILE=""
BODY_TEXT=""
HTML=0
EHLO_NAME="recon.local"
EXTRA_HEADERS=""
USE_TLS=0
AUTH_USER=""
AUTH_PASS=""
SEND=0

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2 ;;
        --from)      FROM_ADDR="$2"; shift 2 ;;
        --from-name) FROM_NAME="$2"; shift 2 ;;
        --to)        TO_ADDR="$2"; shift 2 ;;
        --to-name)   TO_NAME="$2"; shift 2 ;;
        --subject)   SUBJECT="$2"; shift 2 ;;
        --body-file) BODY_FILE="$2"; shift 2 ;;
        --body)      BODY_TEXT="$2"; shift 2 ;;
        --html)      HTML=1; shift ;;
        --ehlo)      EHLO_NAME="$2"; shift 2 ;;
        --header)    EXTRA_HEADERS+=$'\r\n'"$2"; shift 2 ;;
        --tls)       USE_TLS=1; shift ;;
        --auth-user) AUTH_USER="$2"; shift 2 ;;
        --auth-pass) AUTH_PASS="$2"; shift 2 ;;
        --send)      SEND=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port --from x@y --to a@b --subject 'S' --body 'B' --send [options]

Required:
  --target HOST:PORT
  --from   spoofed sender email
  --to     recipient
  --subject
  one of:  --body 'text'  |  --body-file path
  --send   REQUIRED to actually transmit. Without it the script prints the
           assembled DATA block and exits 0. Per CLAUDE.md §9 invariant 1.

Optional:
  --from-name 'Display Name'
  --to-name   'Display Name'
  --html              treat body as text/html
  --header 'X-Foo: bar'   repeatable
  --ehlo NAME         (default: $EHLO_NAME)
  --tls               use STARTTLS (requires swaks)
  --auth-user / --auth-pass   if relay requires auth
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
[ -z "$FROM_ADDR" ] && { err "--from required"; exit 1; }
[ -z "$TO_ADDR" ] && { err "--to required"; exit 1; }
[ -z "$SUBJECT" ] && { err "--subject required"; exit 1; }
parse_target "$TARGET"

if [ -n "$BODY_FILE" ]; then BODY=$(cat "$BODY_FILE"); else BODY="$BODY_TEXT"; fi
[ -z "$BODY" ] && { err "--body or --body-file required"; exit 1; }

if [ "$SEND" != 1 ]; then
    log "DRY RUN — would send to $HOST:$PORT"
    log "  envelope-from:  $FROM_ADDR"
    log "  envelope-to:    $TO_ADDR"
    log "  subject:        $SUBJECT"
    log "  tls:            $USE_TLS    auth-user: ${AUTH_USER:-(none)}"
    log "  body-size:      ${#BODY} bytes"
    log ""
    log "  Re-run with --send to actually transmit. Authorized red-team / phishing-simulation only."
    exit 0
fi

# Use swaks if available + TLS/auth requested (handles tricky bits better)
if [ "$USE_TLS" = "1" ] || [ -n "$AUTH_USER" ]; then
    if ! have swaks; then err "swaks required for --tls or --auth-*"; exit 1; fi
    SWARGS=(
        --server "$HOST:$PORT"
        --from "$FROM_ADDR" --to "$TO_ADDR"
        --header "Subject: $SUBJECT"
        --ehlo "$EHLO_NAME"
        --body "$BODY"
    )
    [ "$HTML" = "1" ] && SWARGS+=(--add-header "Content-Type: text/html")
    [ -n "$FROM_NAME" ] && SWARGS+=(--header "From: \"$FROM_NAME\" <$FROM_ADDR>")
    [ -n "$TO_NAME" ]   && SWARGS+=(--header "To: \"$TO_NAME\" <$TO_ADDR>")
    [ "$USE_TLS" = "1" ] && SWARGS+=(--tls)
    [ -n "$AUTH_USER" ] && SWARGS+=(--auth-user "$AUTH_USER" --auth-password "$AUTH_PASS")
    swaks "${SWARGS[@]}"
    exit $?
fi

# Plain SMTP — write the DATA block ourselves to keep headers exact
DATE_RFC=$(date -R)
MSGID="<$(date +%s).$RANDOM@$EHLO_NAME>"

# Build message
FROM_HDR="$FROM_ADDR"
[ -n "$FROM_NAME" ] && FROM_HDR="\"$FROM_NAME\" <$FROM_ADDR>"
TO_HDR="$TO_ADDR"
[ -n "$TO_NAME" ] && TO_HDR="\"$TO_NAME\" <$TO_ADDR>"

CTYPE="text/plain"
[ "$HTML" = "1" ] && CTYPE="text/html"

HEADERS=$(cat <<EOF
From: $FROM_HDR
To: $TO_HDR
Subject: $SUBJECT
Date: $DATE_RFC
Message-ID: $MSGID
MIME-Version: 1.0
Content-Type: $CTYPE; charset=UTF-8
EOF
)
[ -n "$EXTRA_HEADERS" ] && HEADERS+="$EXTRA_HEADERS"

# Dot-stuff body lines starting with .
BODY_STUFFED=$(printf '%s' "$BODY" | sed 's/^\./../')

# Full dialog
DIALOG=$(printf 'EHLO %s\r\nMAIL FROM:<%s>\r\nRCPT TO:<%s>\r\nDATA\r\n%s\r\n\r\n%s\r\n.\r\nQUIT\r\n' \
    "$EHLO_NAME" "$FROM_ADDR" "$TO_ADDR" \
    "$(printf '%s' "$HEADERS" | sed 's/$/\r/')" \
    "$BODY_STUFFED")

log "Sending..."
RESP=$(printf '%s' "$DIALOG" | timeout 15 nc -nv "$HOST" "$PORT" 2>&1)
echo "$RESP"

if echo "$RESP" | grep -qE '^250 2\.0\.0 Ok\|^250.*queued\|^250.*Message accepted'; then
    hit "Message accepted"
else
    err "Send may have failed — review the response above"
fi
