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

# nxc credential args (echoes nothing if no creds)
nxc_creds() {
    local args=""
    [ -n "${ENUM_USER:-}" ] && args+=" -u '$ENUM_USER'"
    if [ -n "${ENUM_HASH:-}" ]; then args+=" -H '$ENUM_HASH'"
    elif [ -n "${ENUM_PASS:-}" ]; then args+=" -p '$ENUM_PASS'"; fi
    [ -n "${ENUM_DOMAIN:-}" ] && args+=" -d '$ENUM_DOMAIN'"
    echo "$args"
}

# Make xargs use the requested parallelism
xargs_p() { xargs -n1 -P"${ENUM_PARALLEL:-4}" "$@"; }
