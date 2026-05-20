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
    [ -z "$TARGETS" ] || [ -z "$OUT" ] && { echo "usage: $0 --targets <file> --output <dir>"; return 1; }
    [ -f "$TARGETS" ] || { echo "targets file missing: $TARGETS"; return 1; }
    mkdir -p "$OUT"
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
hit()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
miss() { printf "\033[1;33m[-]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[!]\033[0m %s\n" "$*"; }

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
# graphql/gql.py's GQL_PROXY, and ENUM_USER_AGENT for the UA override.
#
# Usage from a dispatcher:
#     curl -ks "$(curl_proxy_arg)" -A "$(curl_ua)" "$url"
# or with arrays:
#     extra=(); read -ra extra <<< "$(curl_extra_args)"
#     curl -ks "${extra[@]}" "$url"
curl_ua() {
    # Operator override wins; otherwise fall back to a Chrome-stable string
    # matching what graphql/gql.py uses by default (consistent fingerprint).
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

# Convenience: emit `-A <ua> [-x proxy]` as a single string suitable for
# `eval`-free word-splitting via `read -ra`. Callers that want full safety
# should use a bash array directly.
curl_extra_args() {
    local ua; ua=$(curl_ua)
    local proxy; proxy=$(curl_proxy_arg)
    printf -- "-A %q %s" "$ua" "$proxy"
}
