# shellcheck shell=bash
# _redis_lib.sh — shared helpers for redis-* scripts. Source me, do not exec.
#
# Conventions:
#   $HOST     target ip (no brackets, no port)
#   $PORT     target tcp port
#   $USERNAME optional Redis 6+ ACL username
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
    local args=() rc
    if [ -n "${USERNAME:-}" ]; then
        args+=(--user "$USERNAME")
        [ -n "${PASS:-}" ] && args+=(--pass "$PASS" --no-auth-warning)
    elif [ -n "${PASS:-}" ]; then
        args+=(-a "$PASS" --no-auth-warning)
    fi
    timeout 10 redis-cli -h "$HOST" -p "$PORT" "${args[@]}" "$@" 2>&1
    rc=$?
    # shellcheck disable=SC2034  # exported state — read by callers via $?-style check
    RCMD_RC=$rc
    return "$rc"
}

# Raw multi-line script via redis-cli pipe (handles binary OK because redis-cli -x reads stdin).
# rscript <<EOF
#   CONFIG SET dir /tmp
#   CONFIG SET dbfilename foo
#   SAVE
# EOF
rscript() {
    local args=()
    if [ -n "${USERNAME:-}" ]; then
        args+=(--user "$USERNAME")
        [ -n "${PASS:-}" ] && args+=(--pass "$PASS" --no-auth-warning)
    elif [ -n "${PASS:-}" ]; then
        args+=(-a "$PASS" --no-auth-warning)
    fi
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
            if [ -n "${PASS:-}" ] || [ -n "${USERNAME:-}" ]; then
                out=$(rcmd PING)
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
    # Operator-supplied wordlist (redis-quickwin --passlist) is tried first.
    if [ -n "${PASS_LIST:-}" ] && [ -r "${PASS_LIST:-}" ]; then
        local extra=() line
        while IFS= read -r line; do [ -n "$line" ] && extra+=("$line"); done < "$PASS_LIST"
        candidates=("${extra[@]}" "${candidates[@]}")
    fi
    for p in "${candidates[@]}"; do
        local out
        if [ -z "$p" ]; then
            out=$(timeout 5 redis-cli -h "$HOST" -p "$PORT" --no-auth-warning PING 2>&1)
        else
            PASS="$p"
            out=$(rcmd PING)
        fi
        if [ "$out" = PONG ]; then
            PASS="$p"; AUTHED=1
            echo "$p"
            return 0
        fi
    done
    return 1
}

# Save persistence, replication, and replication-auth state. Returning nonzero
# means exact restoration cannot be guaranteed and callers must not mutate.
_config_get_value() {
    local key="$1" out first
    out=$(rcmd CONFIG GET "$key" 2>&1) || return 1
    printf '%s' "$out" | grep -qiE '^(ERR|NOAUTH|NOPERM)|unknown command|disabled' && return 1
    out=${out//$'\r'/}
    first=${out%%$'\n'*}
    [ "$first" = "$key" ] || return 1
    # Command substitution strips trailing newlines. A two-line Redis response
    # whose value is empty therefore arrives as exactly the key name; preserve
    # that as the empty string rather than accidentally returning the key.
    [ "$out" = "$key" ] && { printf ''; return 0; }
    printf '%s' "${out#*$'\n'}"
}

# Redis status replies used for mutation gates must be exactly OK.  Prefix
# matching would incorrectly accept a diagnostic such as "OK-but-not-applied".
redis_reply_is_ok() {
    local reply="${1//$'\r'/}"
    reply="${reply#"${reply%%[![:space:]]*}"}"
    reply="${reply%"${reply##*[![:space:]]}"}"
    [ "$reply" = "OK" ]
}

save_config() {
    local repl
    SAVED_DIR=$(_config_get_value dir) || return 1
    SAVED_DBFILE=$(_config_get_value dbfilename) || return 1
    SAVED_AOF=$(_config_get_value appendonly) || return 1
    SAVED_MASTERAUTH=$(_config_get_value masterauth) || return 1
    SAVED_MASTERUSER=$(_config_get_value masteruser) || return 1
    repl=$(rcmd INFO replication 2>&1) || return 1
    printf '%s' "$repl" | grep -qiE '^(ERR|NOAUTH|NOPERM)' && return 1
    SAVED_ROLE=$(printf '%s\n' "$repl" | awk -F: '/^role:/{gsub(/\r/,"",$2); print $2; exit}')
    case "$SAVED_ROLE" in
        master) SAVED_MASTER_HOST=""; SAVED_MASTER_PORT="" ;;
        slave|replica)
            SAVED_MASTER_HOST=$(printf '%s\n' "$repl" | awk -F: '/^master_host:/{gsub(/\r/,"",$2); print $2; exit}')
            SAVED_MASTER_PORT=$(printf '%s\n' "$repl" | awk -F: '/^master_port:/{gsub(/\r/,"",$2); print $2; exit}')
            [ -n "$SAVED_MASTER_HOST" ] && [ -n "$SAVED_MASTER_PORT" ] || return 1 ;;
        *) return 1 ;;
    esac
}

restore_config() {
    local failed=0
    _restore_config_value() {
        local key="$1" value="$2" out current
        if ! out=$(rcmd CONFIG SET "$key" "$value" 2>&1); then
            failed=1
        fi
        redis_reply_is_ok "$out" || failed=1
        current=$(_config_get_value "$key") || { failed=1; return; }
        [ "$current" = "$value" ] || failed=1
    }
    _restore_config_value dir "${SAVED_DIR:-}"
    _restore_config_value dbfilename "${SAVED_DBFILE:-}"
    _restore_config_value appendonly "${SAVED_AOF:-}"
    _restore_config_value masterauth "${SAVED_MASTERAUTH:-}"
    _restore_config_value masteruser "${SAVED_MASTERUSER:-}"
    unset -f _restore_config_value
    return "$failed"
}

restore_replication_state() {
    local out repl role host port
    if [ "${SAVED_ROLE:-}" = "master" ]; then
        out=$(rcmd REPLICAOF NO ONE 2>&1) || return 1
    else
        out=$(rcmd REPLICAOF "$SAVED_MASTER_HOST" "$SAVED_MASTER_PORT" 2>&1) || return 1
    fi
    redis_reply_is_ok "$out" || return 1
    repl=$(rcmd INFO replication 2>&1) || return 1
    role=$(printf '%s\n' "$repl" | awk -F: '/^role:/{gsub(/\r/,"",$2); print $2; exit}')
    if [ "${SAVED_ROLE:-}" = "master" ]; then
        [ "$role" = "master" ]
    else
        host=$(printf '%s\n' "$repl" | awk -F: '/^master_host:/{gsub(/\r/,"",$2); print $2; exit}')
        port=$(printf '%s\n' "$repl" | awk -F: '/^master_port:/{gsub(/\r/,"",$2); print $2; exit}')
        { [ "$role" = "slave" ] || [ "$role" = "replica" ]; } && \
            [ "$host" = "$SAVED_MASTER_HOST" ] && [ "$port" = "$SAVED_MASTER_PORT" ]
    fi
}

# Prove module-load policy and the current ACL without attempting a load.
# Sets MODULE_LOAD_STATE=allowed|denied|unknown and MODULE_LOAD_REASON.
probe_module_load_capability() {
    MODULE_LOAD_STATE="unknown"; MODULE_LOAD_REASON="configuration/ACL not observable"
    local config_value who dry help major
    major=${REDIS_VERSION%%.*}
    if config_value=$(_config_get_value enable-module-command); then
        case "$config_value" in
            no)
                MODULE_LOAD_STATE="denied"; MODULE_LOAD_REASON="enable-module-command=no"; return 0 ;;
            local)
                MODULE_LOAD_STATE="denied"
                MODULE_LOAD_REASON="enable-module-command=local permits only a local Unix-socket client, not this TCP target"
                return 0 ;;
            yes) ;;
            *) return 0 ;;
        esac
    elif ! [ "$major" -lt 7 ] 2>/dev/null; then
        return 0
    fi
    who=$(rcmd ACL WHOAMI 2>&1 | tail -1 | tr -d '\r')
    if [ -n "$who" ] && ! printf '%s' "$who" | grep -qiE '^(ERR|NOAUTH|NOPERM)'; then
        dry=$(rcmd ACL DRYRUN "$who" MODULE LOAD /__aranum_capability_probe_missing__.so 2>&1)
        if printf '%s' "$dry" | grep -qi '^OK'; then
            MODULE_LOAD_STATE="allowed"; MODULE_LOAD_REASON="server policy enabled and ACL DRYRUN permits MODULE LOAD"; return 0
        fi
        if printf '%s' "$dry" | grep -qiE 'NOPERM|has no permissions'; then
            MODULE_LOAD_STATE="denied"; MODULE_LOAD_REASON="current ACL denies MODULE LOAD"; return 0
        fi
    fi
    # Redis before ACL DRYRUN: MODULE HELP exercises the same command ACL while
    # remaining side-effect free. Redis 7+ stays unknown without DRYRUN proof.
    if [ "$major" -lt 7 ] 2>/dev/null; then
        help=$(rcmd MODULE HELP 2>&1)
        if ! printf '%s' "$help" | grep -qiE '^(ERR|NOAUTH|NOPERM)|disabled|forbidden'; then
            MODULE_LOAD_STATE="allowed"; MODULE_LOAD_REASON="legacy MODULE command ACL permits HELP"; return 0
        fi
    fi
    return 0
}

# Coloured logging
_RST=$'\033[0m'; _G=$'\033[1;32m'; _Y=$'\033[1;33m'; _R=$'\033[1;31m'; _C=$'\033[1;36m'
[ -t 1 ] || { _RST=""; _G=""; _Y=""; _R=""; _C=""; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
hit()  { printf "%s[+]%s %s\n" "$_G" "$_RST" "$*"; }
miss() { printf "%s[-]%s %s\n" "$_Y" "$_RST" "$*"; }
err()  { printf "%s[!]%s %s\n" "$_R" "$_RST" "$*"; }
crit() { printf "%s[!!]%s %s\n" "$_R" "$_RST" "$*"; }
