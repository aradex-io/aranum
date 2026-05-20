#!/usr/bin/env bash
# enum-activemq.sh — ActiveMQ discovery dispatcher.
# Distinguishes the two ActiveMQ-relevant ports:
#   * 61616 (OpenWire) — protocol port, CVE-2023-46604 unauth RCE candidate
#   * 8161  (Web console / Jolokia) — admin:admin → RCE path
#   * 5672  (AMQP) — auxiliary
#   * 61613 (STOMP) — auxiliary
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "activemq: $(wc -l < "$TARGETS") targets -> $OUT"

probe_one() {
    local target="$1"
    read -r ip port <<< "$(split_ipport "$target")"
    local d="$OUT/${ip}_${port}"
    mkdir -p "$d"

    case "$port" in
        8161)
            # Web console — try admin:admin and the version-disclosing pages
            {
                echo "=== HEAD / ==="
                curl -sk -m 5 -I "http://$ip:$port/admin/" 2>&1
                echo
                echo "=== unauth GET / ==="
                curl -sk -m 5 -o /dev/null -w 'http=%{http_code} size=%{size_download}\n' "http://$ip:$port/admin/"
                echo
                echo "=== admin:admin auth probe ==="
                curl -sk -m 5 -u admin:admin -o /dev/null -w 'http=%{http_code} size=%{size_download}\n' "http://$ip:$port/admin/"
                echo
                echo "=== admin:admin version (via Jolokia) ==="
                curl -sk -m 5 -u admin:admin "http://$ip:$port/api/jolokia/read/org.apache.activemq:type=Broker,brokerName=localhost/BrokerVersion" 2>&1
                echo
                echo "=== Jolokia /list (cred=admin:admin) — operation surface ==="
                curl -sk -m 8 -u admin:admin "http://$ip:$port/api/jolokia/list" 2>&1 | head -c 4000
            } > "$d/http.txt" 2>&1

            # Classify
            if grep -q '"value":"' "$d/http.txt" && grep -q 'BrokerVersion' "$d/http.txt"; then
                VER=$(grep -oE '"value":"[0-9.]+"' "$d/http.txt" | head -1 | tr -d '"' | cut -d: -f2)
                hit "$ip:$port  admin:admin WORKS  v$VER  -> activemq/activemq-jolokia-rce.sh"
                echo "$ip:$port|$VER|admin:admin" >> "$OUT/_jolokia_admin.txt"
            elif curl -sk -m 3 -o /dev/null -w '%{http_code}' "http://$ip:$port/admin/" | grep -q '401'; then
                miss "$ip:$port  web console up but default creds rejected — try cred spray"
            fi
            ;;

        61616)
            # OpenWire — try a marshaled probe. ActiveMQ greets with a WireFormat info packet.
            {
                # Send a minimal OpenWire connection-info request and see if a marshaled response comes back
                printf '\x00\x00\x00\x16\x01ActiveMQ\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                    | timeout 5 nc -nv "$ip" "$port" 2>&1 | head -c 256 | xxd
            } > "$d/openwire.txt" 2>&1

            if grep -qi 'ActiveMQ' "$d/openwire.txt" 2>/dev/null; then
                hit "$ip:$port  OpenWire confirmed — CVE-2023-46604 candidate -> activemq/activemq-cve-2023-46604.py"
                echo "$ip:$port" >> "$OUT/_openwire_targets.txt"
            else
                # Still possibly OpenWire but not echoing — log for manual review
                log "$ip:$port  unclear OpenWire signature; check $d/openwire.txt"
            fi
            ;;

        5672|61613)
            # AMQP / STOMP — banner grab
            {
                echo "QUIT" | timeout 5 nc -nv "$ip" "$port" 2>&1 | head -10
            } > "$d/banner.txt"
            ;;

        *)
            log "$ip:$port  port not in activemq probe set; skipping"
            ;;
    esac
}

export -f probe_one split_ipport hit miss log
export OUT

while read -r t; do
    [ -z "$t" ] && continue
    probe_one "$t" &
    while [ "$(jobs -rp | wc -l)" -ge "${ENUM_PARALLEL:-4}" ]; do sleep 0.1; done
done < "$TARGETS"
wait

# Summary
echo
echo "=== ActiveMQ targets discovered ==="
[ -s "$OUT/_jolokia_admin.txt" ] && {
    echo "  Admin web-console with default creds:"
    sed 's/^/    /' "$OUT/_jolokia_admin.txt"
}
[ -s "$OUT/_openwire_targets.txt" ] && {
    echo "  OpenWire (port 61616) — try CVE-2023-46604:"
    sed 's/^/    /' "$OUT/_openwire_targets.txt"
}

log "activemq dispatcher done. Deep exploitation: activemq/ toolkit"
