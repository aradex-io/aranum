# shellcheck shell=bash
# _smtp_lib.sh — shared helpers for smtp-* scripts. Source me.

parse_target() {
    local t="$1"
    if [[ "$t" == \[*\]:* ]]; then
        HOST="${t#[}"; HOST="${HOST%%]:*}"; PORT="${t##*]:}"
    elif [[ "$t" == *:* ]]; then
        HOST="${t%:*}"; PORT="${t##*:}"
    else
        HOST="$t"; PORT="${PORT:-25}"
    fi
}

_RST=$'\033[0m'; _G=$'\033[1;32m'; _Y=$'\033[1;33m'; _R=$'\033[1;31m'; _C=$'\033[1;36m'
[ -t 1 ] || { _RST=""; _G=""; _Y=""; _R=""; _C=""; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
hit()  { printf "%s[+]%s %s\n" "$_G" "$_RST" "$*"; }
miss() { printf "%s[-]%s %s\n" "$_Y" "$_RST" "$*"; }
err()  { printf "%s[!]%s %s\n" "$_R" "$_RST" "$*"; }
crit() { printf "%s[!!]%s %s\n" "$_R" "$_RST" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Send a SMTP dialog string (with proper CRLF), return raw response.
# Usage:  smtp_send "$HOST" "$PORT" "$(printf 'EHLO x\r\nQUIT\r\n')"
smtp_send() {
    local host="$1" port="$2" dialog="$3" t="${4:-5}"
    printf '%s' "$dialog" | timeout "$t" nc -nv "$host" "$port" 2>&1
}

# Build CRLF-correct dialog from a list of commands (each given as one arg).
smtp_dialog() {
    local s=""
    for line in "$@"; do s+="$line"$'\r\n'; done
    printf '%s' "$s"
}

# Print the final reply code associated with a command in a pipelined SMTP
# transcript.  Command indexes are one-based; the server greeting is reply 0.
# Multiline continuation lines ("250-") are deliberately ignored so an EHLO
# extension can never be mistaken for the MAIL/RCPT/DATA result.
smtp_command_code() {
    local transcript="$1" command_index="$2"
    printf '%s\n' "$transcript" | awk -v wanted="$((command_index + 1))" '
        /^[2-5][0-9][0-9] / {
            seen++
            if (seen == wanted) { print substr($0, 1, 3); exit }
        }
    '
}

smtp_code_is_success() {
    case "$1" in 250|251) return 0 ;; *) return 1 ;; esac
}

# Read one complete SMTP reply from an already-open descriptor. Diagnostic
# lines emitted by netcat are ignored. The caller owns timeout/lifecycle.
smtp_read_reply() {
    local fd="$1" line code="" saw=0
    while IFS= read -r -u "$fd" line; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^([2-5][0-9][0-9])([-\ ]) ]] || continue
        printf '%s\n' "$line"
        saw=1
        code="${BASH_REMATCH[1]}"
        [ "${BASH_REMATCH[2]}" = " " ] && break
    done
    [ "$saw" = 1 ] && [ -n "$code" ]
}
