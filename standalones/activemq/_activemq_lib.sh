# shellcheck shell=bash
# _activemq_lib.sh — shared helpers for activemq-* scripts. Source me.

# --------------- shared state ---------------
# All scripts honor these env vars / args
#   HOST PORT USER PASS
# and use jolokia_url() / version_check() / etc.

parse_target() {
    local t="$1"
    if [[ "$t" == \[*\]:* ]]; then
        HOST="${t#[}"; HOST="${HOST%%]:*}"; PORT="${t##*]:}"
    elif [[ "$t" == *:* ]]; then
        HOST="${t%:*}"; PORT="${t##*:}"
    else
        HOST="$t"; PORT="${PORT:-8161}"
    fi
}

# Coloured logging
_RST=$'\033[0m'; _G=$'\033[1;32m'; _Y=$'\033[1;33m'; _R=$'\033[1;31m'; _C=$'\033[1;36m'
[ -t 1 ] || { _RST=""; _G=""; _Y=""; _R=""; _C=""; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
hit()  { printf "%s[+]%s %s\n" "$_G" "$_RST" "$*"; }
miss() { printf "%s[-]%s %s\n" "$_Y" "$_RST" "$*"; }
err()  { printf "%s[!]%s %s\n" "$_R" "$_RST" "$*"; }
crit() { printf "%s[!!]%s %s\n" "$_R" "$_RST" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Build curl auth args
curl_auth() {
    if [ -n "${USER:-}" ]; then
        echo "-u" "${USER}:${PASS:-}"
    fi
}

# Jolokia base
jolokia_url() { echo "http://$HOST:$PORT/api/jolokia"; }

# Probe broker version. Returns "X.Y.Z" on stdout, sets BROKER_VERSION
broker_version() {
    local out
    # shellcheck disable=SC2046  # curl_auth() emits "-u user:pass" (two tokens); word-splitting is intentional
    out=$(curl -sk -m 5 $(curl_auth) "$(jolokia_url)/read/org.apache.activemq:type=Broker,brokerName=localhost/BrokerVersion" 2>/dev/null)
    BROKER_VERSION=$(echo "$out" | grep -oE '"value":"[0-9.]+"' | head -1 | sed 's/"value":"//; s/"$//')
    echo "$BROKER_VERSION"
}

# Compare version against thresholds for known CVEs.
# Returns vulnerability classification on stdout: PATCHED|VULN_46604|UNKNOWN
classify_version() {
    local ver="$1"
    [ -z "$ver" ] && { echo "UNKNOWN"; return; }
    IFS=. read -r major minor patch <<< "$ver"
    # CVE-2023-46604 fixed in 5.18.3 / 5.17.6 / 5.16.7 / 5.15.16
    if [ "$major" = "5" ]; then
        case "$minor" in
            18) [ "$patch" -lt 3 ]  && echo "VULN_46604" || echo "PATCHED" ;;
            17) [ "$patch" -lt 6 ]  && echo "VULN_46604" || echo "PATCHED" ;;
            16) [ "$patch" -lt 7 ]  && echo "VULN_46604" || echo "PATCHED" ;;
            15) [ "$patch" -lt 16 ] && echo "VULN_46604" || echo "PATCHED" ;;
            *)  [ "$minor" -lt 15 ] && echo "VULN_46604" || echo "UNKNOWN" ;;
        esac
    else
        echo "UNKNOWN"
    fi
}

# Test Jolokia auth — returns 0 if creds work
jolokia_auth_works() {
    local code
    # shellcheck disable=SC2046  # curl_auth() emits "-u user:pass" (two tokens); word-splitting is intentional
    code=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' $(curl_auth) "$(jolokia_url)/version" 2>/dev/null)
    [ "$code" = "200" ]
}

# Parse Jolokia JSON value field
jolokia_value() {
    grep -oE '"value":[^,}]+' "$1" | head -1 | sed 's/"value"://; s/^"//; s/"$//'
}
