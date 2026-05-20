#!/usr/bin/env bash
# activemq-quickwin.sh — ActiveMQ detection + exploitability tier.
#
# Per target:
#   1. Check web console (8161) — reachable? admin:admin? other default creds?
#   2. Check OpenWire (61616) — confirm signature
#   3. Pull version via Jolokia (auth or unauth)
#   4. Classify against CVE-2023-46604 (unauth RCE, port 61616)
#   5. Tier:
#       CRITICAL: vulnerable to CVE-2023-46604 → unauth RCE
#       CRITICAL: admin:admin or other default creds on Jolokia → admin RCE
#       HIGH:     web console reachable, version disclosed but creds rejected
#       MEDIUM:   AMQP/STOMP only — credential-dependent
#       LOW:      Reachable but no exploit primitives identified

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_activemq_lib.sh"

TARGETS=""; TARGET=""; OUT="./activemq-quickwin"; PARALLEL=4
CRED_LIST="admin:admin admin:password admin:activemq system:manager user:password"

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2 ;;
        --targets)   TARGETS="$2"; shift 2 ;;
        --output|-o) OUT="$2"; shift 2 ;;
        --creds)     CRED_LIST="$2"; shift 2 ;;
        --parallel)  PARALLEL="$2"; shift 2 ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port | --targets file [-o dir] [--creds 'u:p u:p ...'] [--parallel N]
  --creds   space-separated 'user:pass' pairs to try (default: $CRED_LIST)
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT"
: > "$OUT/_tiers.tsv"

scan_one() {
    local t="$1"
    parse_target "$t"
    local d="$OUT/${HOST}_${PORT}"
    mkdir -p "$d"
    local tier="LOW" reason=""

    if [ "$PORT" = "61616" ]; then
        # OpenWire — probe with a banner connect
        local sig
        sig=$(printf '' | timeout 5 nc -nv "$HOST" "$PORT" 2>&1 | head -c 256)
        echo "$sig" > "$d/openwire_banner.txt"
        if echo "$sig" | grep -qi 'ActiveMQ\|MagicID'; then
            tier="CRITICAL"; reason="OpenWire signature; if version <5.18.3/5.17.6/5.16.7/5.15.16 -> CVE-2023-46604 unauth RCE"
            echo "$HOST:$PORT" >> "$OUT/_openwire_targets.txt"
        else
            # Still classify potential ActiveMQ if any byte returned
            [ -n "$sig" ] && { tier="MEDIUM"; reason="port open but signature unclear"; }
        fi

    elif [ "$PORT" = "8161" ]; then
        # Web console — first check if reachable
        local code; code=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "http://$HOST:$PORT/admin/" || echo "000")
        echo "unauth status: $code" > "$d/web.txt"
        if [ "$code" = "000" ]; then
            tier="LOW"; reason="web console unreachable"
        elif [ "$code" = "401" ]; then
            # Try default creds
            for cu in $CRED_LIST; do
                USER="${cu%:*}"; PASS="${cu##*:}"
                local cred_code; cred_code=$(curl -sk -m 5 -u "$USER:$PASS" -o /dev/null -w '%{http_code}' "http://$HOST:$PORT/admin/" || echo "000")
                if [ "$cred_code" = "200" ]; then
                    BROKER_VERSION=""
                    broker_version >/dev/null
                    tier="CRITICAL"; reason="Default creds work: $USER:$PASS — Jolokia/MBean RCE via activemq-jolokia-rce.sh (version=${BROKER_VERSION:-?})"
                    echo "$HOST:$PORT|$USER:$PASS|${BROKER_VERSION:-?}" >> "$OUT/_admin_targets.txt"
                    break
                fi
            done
            [ "$tier" = "LOW" ] && { tier="HIGH"; reason="web console requires auth; cred-spray candidate"; }
        elif [ "$code" = "200" ]; then
            # Open without auth (or anon enabled — bad)
            USER=""; PASS=""
            BROKER_VERSION=""
            broker_version >/dev/null
            tier="CRITICAL"; reason="web console OPEN (no auth) — version=${BROKER_VERSION:-?}, Jolokia/MBean RCE available"
            echo "$HOST:$PORT|noauth|${BROKER_VERSION:-?}" >> "$OUT/_admin_targets.txt"
        fi

        # Dump Jolokia capability summary if we found working creds
        if [ "$tier" = "CRITICAL" ] && grep -q "$HOST:$PORT" "$OUT/_admin_targets.txt" 2>/dev/null; then
            # shellcheck disable=SC2046  # curl_auth() emits "-u user:pass" (two tokens); word-splitting is intentional
            curl -sk -m 8 $(curl_auth) "$(jolokia_url)/list" \
                > "$d/jolokia_list.json" 2>&1
        fi

    else
        tier="MEDIUM"; reason="non-standard port ($PORT) — manual review"
    fi

    {
        echo "Target: $HOST:$PORT"
        echo "Time:   $(date -Is)"
        echo "Tier:   $tier"
        echo "Reason: $reason"
        echo
        for f in web.txt openwire_banner.txt; do
            [ -s "$d/$f" ] && { echo "--- $f ---"; cat "$d/$f"; echo; }
        done
    } > "$d/summary.txt"

    case "$tier" in
        CRITICAL) printf "%s[!!] %-22s CRITICAL%s  %s\n" "$_R" "$HOST:$PORT" "$_RST" "$reason" ;;
        HIGH)     printf "%s[+]  %-22s HIGH%s      %s\n" "$_G" "$HOST:$PORT" "$_RST" "$reason" ;;
        MEDIUM)   printf "%s[*]  %-22s MEDIUM%s    %s\n" "$_C" "$HOST:$PORT" "$_RST" "$reason" ;;
        LOW)      printf "%s[-]  %-22s LOW%s       %s\n" "$_Y" "$HOST:$PORT" "$_RST" "$reason" ;;
    esac
    echo "$tier|$HOST:$PORT|$reason" >> "$OUT/_tiers.tsv"
}

export -f scan_one parse_target broker_version curl_auth jolokia_url have log hit miss err crit
export OUT CRED_LIST _R _G _Y _C _RST

if [ -n "$TARGET" ]; then
    scan_one "$TARGET"
elif [ -n "$TARGETS" ]; then
    [ ! -f "$TARGETS" ] && { err "targets file missing"; exit 1; }
    xargs -a "$TARGETS" -n1 -P"$PARALLEL" -I{} bash -c 'scan_one "$@"' _ {}
else
    err "specify --target or --targets"; exit 1
fi

# Summary
echo
echo "================== SUMMARY =================="
sort "$OUT/_tiers.tsv" | awk -F'|' '{count[$1]++} END {for (t in count) printf "  %-9s %d\n", t, count[t]}' | sort
echo
[ -s "$OUT/_admin_targets.txt" ] && {
    echo "Hosts with admin web-console access (use activemq-jolokia-rce.sh):"
    sed 's/^/  /' "$OUT/_admin_targets.txt"
}
[ -s "$OUT/_openwire_targets.txt" ] && {
    echo "OpenWire targets (test CVE-2023-46604 with activemq-cve-2023-46604.py):"
    sed 's/^/  /' "$OUT/_openwire_targets.txt"
}
echo
echo "Detailed per-host reports: $OUT/"
