# shellcheck shell=bash
# _lib.sh — shared helpers for enum dispatchers. Source me, don't exec.
# Expects: ENUM_USER ENUM_PASS ENUM_HASH ENUM_DOMAIN ENUM_DC_IP ENUM_PARALLEL

# --------------- arg parsing ---------------
parse_common_args() {
    TARGETS=""
    OUT=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --targets) TARGETS="$2"; shift 2 ;;
            --output)  OUT="$2";     shift 2 ;;
            *) echo "unknown arg: $1"; return 1 ;;
        esac
    done
    if [ -z "$TARGETS" ] || [ -z "$OUT" ]; then
        echo "usage: $0 --targets <file> --output <dir>"
        return 1
    fi
    if [ ! -f "$TARGETS" ]; then
        echo "targets file missing: $TARGETS"
        return 1
    fi
    mkdir -p "$OUT"
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    _ARANUM_GREEN=$'\033[1;32m'
    _ARANUM_YELLOW=$'\033[1;33m'
    _ARANUM_RED=$'\033[1;31m'
    _ARANUM_RESET=$'\033[0m'
else
    _ARANUM_GREEN=""
    _ARANUM_YELLOW=""
    _ARANUM_RED=""
    _ARANUM_RESET=""
fi
hit()  { printf "%s[+]%s %s\n" "$_ARANUM_GREEN" "$_ARANUM_RESET" "$*"; }
miss() { printf "%s[-]%s %s\n" "$_ARANUM_YELLOW" "$_ARANUM_RESET" "$*"; }
err()  { printf "%s[!]%s %s\n" "$_ARANUM_RED" "$_ARANUM_RESET" "$*"; }

# split  ip:port  or  [v6]:port  -> echoes "<ip> <port>"
split_ipport() {
    local t="$1"
    if [[ "$t" == \[*\]:* ]]; then
        # [2001:db8::1]:22 -> 2001:db8::1 22
        local ip="${t#[}"
        ip="${ip%%]:*}"
        echo "$ip" "${t##*]:}"
    else
        # 10.0.0.1:22 -> 10.0.0.1 22
        echo "${t%:*}" "${t##*:}"
    fi
}

# Print unique IPs from a targets file (handles ipv4 + bracketed ipv6).
ips_only() {
    awk '{
        n = $1
        if (n ~ /^\[.*\]:[0-9]+$/) {
            sub(/^\[/, "", n); sub(/\]:.*$/, "", n)
        } else {
            sub(/:[0-9]+$/, "", n)
        }
        print n
    }' "$1" | sort -u
}

# Print "ip port" pairs from a targets file (one per line).
ip_port_pairs() {
    while read -r t _; do
        [ -z "$t" ] && continue
        split_ipport "$t"
    done < "$1"
}

# Populate the named bash array with nxc/netexec credential flags built from
# ENUM_USER/ENUM_PASS/ENUM_HASH/ENUM_DOMAIN. Use this instead of string
# concatenation — a credential containing quotes/spaces will not break the
# command line, and there is no eval/word-split surface for an attacker
# (or for a fat-fingered operator) to exploit.
#
# Usage:
#     local args=()
#     nxc_creds_array args
#     "$NXC" smb - "${args[@]}" --shares
#
# Requires bash >= 4.3 for namerefs (declare -n).
nxc_creds_array() {
    local -n _arr="$1"
    _arr=()
    if [ -n "${ENUM_USER:-}" ]; then
        _arr+=(-u "$ENUM_USER")
        if   [ -n "${ENUM_HASH:-}" ]; then _arr+=(-H "$ENUM_HASH")
        elif [ -n "${ENUM_PASS:-}" ]; then _arr+=(-p "$ENUM_PASS")
        fi
        [ -n "${ENUM_DOMAIN:-}" ] && _arr+=(-d "$ENUM_DOMAIN")
    fi
}

# Build the LDAP URL for a given IP. IPv6 addresses must be bracketed —
# 'ldap://2001:db8::1' is ambiguous to URL parsers; 'ldap://[2001:db8::1]' is not.
# Usage:
#     url=$(ldap_url "$ip")           # ldap://10.0.0.1
#     url=$(ldap_url "$ip" 636 ldaps) # ldaps://[2001:db8::1]:636
ldap_url() {
    local ip="$1"
    local port="${2:-}"
    local scheme="${3:-ldap}"
    local host
    if [[ "$ip" == *:* ]]; then host="[$ip]"; else host="$ip"; fi
    if [ -n "$port" ]; then echo "${scheme}://${host}:${port}"
    else                    echo "${scheme}://${host}"
    fi
}

# Make xargs use the requested parallelism
xargs_p() { xargs -n1 -P"${ENUM_PARALLEL:-4}" "$@"; }

# ----------------------------------------------------------
# E.5 + E.6 — proxy + User-Agent helpers for curl callsites
# ----------------------------------------------------------
# curl honors HTTPS_PROXY / HTTP_PROXY / ALL_PROXY natively, so no extra
# argument is required there. We also honor ENUM_PROXY for parity with
# standalones/graphql/gql.py's GQL_PROXY, and ENUM_USER_AGENT for the UA override.
#
# Usage from a dispatcher:
#     CURL_ARGS=()
#     curl_common_args CURL_ARGS
#     curl -ks "${CURL_ARGS[@]}" "$url"
curl_ua() {
    # Operator override wins; otherwise fall back to a Chrome-stable string
    # matching what standalones/graphql/gql.py uses by default (consistent fingerprint).
    if [ -n "${ENUM_USER_AGENT:-}" ]; then
        printf '%s' "$ENUM_USER_AGENT"
    else
        printf '%s' "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    fi
}

curl_proxy_arg() {
    # Returns "-x <url>" iff ENUM_PROXY is set (env-fallback to HTTPS_PROXY).
    # curl's native env honor means we usually don't need to pass anything,
    # but explicit -x is useful when the operator wants the dispatcher to
    # ignore conflicting *_PROXY env (e.g. inside a wrapper that sets them).
    if [ -n "${ENUM_PROXY:-}" ]; then
        printf -- "-x %s" "$ENUM_PROXY"
    fi
}

# Populate a bash array with common curl args. This preserves spaces and
# shell metacharacters in user-agent/proxy values without eval or word-splitting.
curl_common_args() {
    # shellcheck disable=SC2178  # _arr is a nameref to the caller's array.
    local -n _arr="$1"
    _arr=(-A "$(curl_ua)")
    if [ -n "${ENUM_PROXY:-}" ]; then
        _arr+=(-x "$ENUM_PROXY")
    fi
}

# ----------------------------------------------------------
# G.7 — throttle helpers for "gentle mode" in sensitive environments.
# auto-enum.sh's --throttle exports ENUM_THROTTLE=1 (and lowers NUCLEI_RATE,
# disables FFUF/NIKTO). Dispatchers that hammer the target (banner sweeps,
# multi-port nmap fans) can opt in via these helpers without rewriting flow.
# ----------------------------------------------------------

# Returns the seconds-per-target inter-host pause for gentle mode. Default 1s;
# override with ENUM_THROTTLE_DELAY=<n>. Returns 0 when throttle is off.
throttle_delay() {
    if [ "${ENUM_THROTTLE:-0}" = 1 ]; then
        printf '%s' "${ENUM_THROTTLE_DELAY:-1}"
    else
        printf '0'
    fi
}

# Sleep the throttle delay. Safe to call unconditionally — no-op when throttle is off.
throttle_sleep() {
    local d; d=$(throttle_delay)
    [ "$d" = 0 ] && return 0
    sleep "$d"
}

# Echo the nmap timing flag appropriate for the current throttle state.
# Prefer "${THROTTLE_NMAP_ARGS[@]}" in dispatchers so the empty case adds no arg.
throttle_nmap_args() {
    if [ "${ENUM_THROTTLE:-0}" = 1 ]; then
        printf '%s' "-T2"
    fi
}

# shellcheck disable=SC2034  # sourced dispatchers consume this shared array.
THROTTLE_NMAP_ARGS=()
if [ "${ENUM_THROTTLE:-0}" = 1 ]; then
    # shellcheck disable=SC2034  # sourced dispatchers consume this shared array.
    THROTTLE_NMAP_ARGS=(-T2)
fi
