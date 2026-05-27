# shellcheck shell=bash
# _redis_lib.sh — shared helpers for redis-* scripts. Source me, do not exec.
#
# Conventions:
#   $HOST     target ip (no brackets, no port)
#   $PORT     target tcp port
#   $PASS     redis AUTH password (may be empty for unauth targets)
#   rcmd ...  run a redis command using redis-cli, returns stdout, sets RCMD_RC

have_redis_cli() { command -v redis-cli >/dev/null; }

# Parse a target string "ip:port" or "[v6]:port" -> sets HOST and PORT.
parse_target() {
    local t="$1"
    if [[ "$t" == \[*\]:* ]]; then
        HOST="${t#[}"; HOST="${HOST%%]:*}"; PORT="${t##*]:}"
    elif [[ "$t" == *:* ]]; then
        HOST="${t%:*}"; PORT="${t##*:}"
    else
        HOST="$t"; PORT=6379
    fi
}

# Run one Redis command; output to stdout, status in $RCMD_RC.
# Auth handled via $PASS env (empty = no auth attempt).
rcmd() {
    local args=()
    [ -n "${PASS:-}" ] && args+=(-a "$PASS" --no-auth-warning)
    timeout 10 redis-cli -h "$HOST" -p "$PORT" "${args[@]}" "$@" 2>&1
    # shellcheck disable=SC2034  # exported state — read by callers via $?-style check
    RCMD_RC=$?
}

# Raw multi-line script via redis-cli pipe (handles binary OK because redis-cli -x reads stdin).
# rscript <<EOF
#   CONFIG SET dir /tmp
#   CONFIG SET dbfilename foo
#   SAVE
# EOF
rscript() {
    local args=()
    [ -n "${PASS:-}" ] && args+=(-a "$PASS" --no-auth-warning)
    timeout 15 redis-cli -h "$HOST" -p "$PORT" "${args[@]}"
}

# Probe — sets:
#   REACHABLE=1/0
#   AUTH_REQUIRED=1/0
#   AUTHED=1/0     (only meaningful when AUTH_REQUIRED=1)
#   REDIS_VERSION (e.g. "7.2.4")
# shellcheck disable=SC2034  # REACHABLE/AUTH_REQUIRED/REDIS_VERSION: exported probe results read by every caller
probe_redis() {
    REACHABLE=0; AUTH_REQUIRED=0; AUTHED=0; REDIS_VERSION=""
    local out
    out=$(timeout 5 redis-cli -h "$HOST" -p "$PORT" --no-auth-warning PING 2>&1)
    case "$out" in
        PONG)
            REACHABLE=1; AUTH_REQUIRED=0; AUTHED=1 ;;
        *NOAUTH*|*"AUTH "*required*)
            REACHABLE=1; AUTH_REQUIRED=1
            if [ -n "${PASS:-}" ]; then
                out=$(timeout 5 redis-cli -h "$HOST" -p "$PORT" -a "$PASS" --no-auth-warning PING 2>&1)
                [ "$out" = PONG ] && AUTHED=1
            fi
            ;;
        *DENIED*|*restricted*|*"WRONGPASS"*)
            REACHABLE=1; AUTH_REQUIRED=1 ;;
        *)
            return 1 ;;
    esac

    if [ "$AUTHED" = 1 ]; then
        # shellcheck disable=SC2034  # REDIS_VERSION read by every caller
        REDIS_VERSION=$(rcmd INFO server | awk -F: '/^redis_version:/{gsub(/[\r\n]/,"",$2); print $2}')
    fi
    return 0
}

# Try a list of common passwords; on success, $PASS is set and AUTHED=1.
try_default_creds() {
    local candidates=("" redis password foobared default 123456 admin)
    for p in "${candidates[@]}"; do
        local out
        if [ -z "$p" ]; then
            out=$(timeout 5 redis-cli -h "$HOST" -p "$PORT" --no-auth-warning PING 2>&1)
        else
            out=$(timeout 5 redis-cli -h "$HOST" -p "$PORT" -a "$p" --no-auth-warning PING 2>&1)
        fi
        if [ "$out" = PONG ]; then
            PASS="$p"; AUTHED=1
            echo "$p"
            return 0
        fi
    done
    return 1
}

# Save dir + dbfilename + appendonly so the target's persistence settings can be restored.
save_config() {
    SAVED_DIR=$(rcmd CONFIG GET dir | tail -1)
    SAVED_DBFILE=$(rcmd CONFIG GET dbfilename | tail -1)
    SAVED_AOF=$(rcmd CONFIG GET appendonly | tail -1)
}

restore_config() {
    [ -n "${SAVED_DIR:-}" ]    && rcmd CONFIG SET dir       "$SAVED_DIR"    >/dev/null
    [ -n "${SAVED_DBFILE:-}" ] && rcmd CONFIG SET dbfilename "$SAVED_DBFILE" >/dev/null
    [ -n "${SAVED_AOF:-}" ]    && rcmd CONFIG SET appendonly "$SAVED_AOF"   >/dev/null
}

# Coloured logging
_RST=$'\033[0m'; _G=$'\033[1;32m'; _Y=$'\033[1;33m'; _R=$'\033[1;31m'; _C=$'\033[1;36m'
[ -t 1 ] || { _RST=""; _G=""; _Y=""; _R=""; _C=""; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
hit()  { printf "%s[+]%s %s\n" "$_G" "$_RST" "$*"; }
miss() { printf "%s[-]%s %s\n" "$_Y" "$_RST" "$*"; }
err()  { printf "%s[!]%s %s\n" "$_R" "$_RST" "$*"; }
crit() { printf "%s[!!]%s %s\n" "$_R" "$_RST" "$*"; }
