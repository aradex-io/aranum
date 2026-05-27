#!/usr/bin/env bash
# jabber-admin-api-probe.sh — detect Ejabberd / Prosody admin surfaces.
#
# READ-ONLY. Sends only HTTP HEAD/GET (curl -I) and one TCP banner read
# against Prosody mod_admin_telnet (5582). No POST, no auth attempt.
#
# Usage:
#   ./jabber-admin-api-probe.sh --host <ip> [--out <dir>]
#
# Exit 0 always (one or more surfaces may be EXPOSED — operator inspects output).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to source _lib.sh from the network/ peer for log/hit/miss helpers; if
# we're invoked outside that layout, define stripped-down equivalents.
if [ -f "$SCRIPT_DIR/../../aranumtoolkit/network/_lib.sh" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/../../aranumtoolkit/network/_lib.sh"
else
    have() { command -v "$1" >/dev/null 2>&1; }
    log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
    hit()  { printf "[+] %s\n" "$*"; }
    miss() { printf "[-] %s\n" "$*"; }
fi

HOST=""
OUT="."
while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --out)  OUT="$2";  shift 2 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done
[ -z "$HOST" ] && { echo "usage: $0 --host <ip> [--out <dir>]"; exit 1; }
mkdir -p "$OUT"

log "admin-api probe: $HOST -> $OUT"

# --------------- Ejabberd commands API (REST or "old" mod_http_api) ---------------
# Ejabberd exposes /api/<command> for the REST commands module. Many deployments
# leave it on the public HTTP listener (typically 5280). Unauth status codes:
#   200/400  — command parsed; very bad (no auth required)
#   401/403  — auth required (good)
#   404      — not enabled, or differently routed
if have curl; then
    for port in 5280 5281 80 8088; do
        url_http="http://${HOST}:${port}/api/status"
        url_https="https://${HOST}:${port}/api/status"
        # HEAD first; some servers only respond to GET
        for url in "$url_http" "$url_https"; do
            code=$(curl -ksI --connect-timeout 4 --max-time 8 \
                   -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
            [ "$code" = "000" ] && continue
            scheme="${url%%:*}"
            outfile="$OUT/ejabberd_api_${scheme}_${port}.txt"
            curl -ksi --connect-timeout 4 --max-time 8 "$url" \
                 > "$outfile" 2>&1 || true
            case "$code" in
                200|400|405)
                    hit "EXPOSED ejabberd-api ($scheme:$port) HTTP $code — $url" ;;
                401|403)
                    log "  ejabberd-api ($scheme:$port) HTTP $code — auth required (expected)" ;;
                404)
                    log "  ejabberd-api ($scheme:$port) 404 — module not enabled" ;;
                *)
                    log "  ejabberd-api ($scheme:$port) HTTP $code — unexpected" ;;
            esac
        done
    done
else
    miss "curl not installed — skipping Ejabberd HTTP-API probe"
fi

# --------------- Prosody mod_admin_telnet (TCP 5582 by default) ---------------
# mod_admin_telnet has historically defaulted to listening on 127.0.0.1 only,
# but misconfigurations (interface = "*") expose it. Banner shape is a Lua
# prompt: "Welcome to the Prosody administration console...".
if have nc; then
    banner=$(printf '\r\n' | timeout 3 nc -nv -w 2 "$HOST" 5582 2>/dev/null \
             | head -c 256)
    if [ -n "$banner" ]; then
        echo "$banner" > "$OUT/prosody_mod_admin_telnet.txt"
        if echo "$banner" | grep -qi "prosody"; then
            hit "EXPOSED prosody-mod_admin_telnet on 5582 — banner mentions prosody"
        else
            log "  5582 responded with non-prosody banner: $(echo "$banner" | tr -d '\r\n' | head -c 80)"
        fi
    else
        log "  prosody-mod_admin_telnet 5582 silent / closed"
    fi
else
    miss "nc not installed — skipping Prosody admin-telnet probe"
fi

# --------------- Prosody mod_admin_web (web UI on 5280/5281 /admin) ---------------
if have curl; then
    for port in 5280 5281; do
        scheme="http"
        [ "$port" = "5281" ] && scheme="https"
        url="${scheme}://${HOST}:${port}/admin/"
        code=$(curl -ksI --connect-timeout 4 --max-time 8 \
               -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
        [ "$code" = "000" ] && continue
        outfile="$OUT/prosody_mod_admin_web_${port}.txt"
        curl -ksi --connect-timeout 4 --max-time 8 "$url" > "$outfile" 2>&1 || true
        case "$code" in
            200|302)
                hit "EXPOSED prosody-mod_admin_web ($scheme:$port/admin/) HTTP $code" ;;
            401|403)
                log "  prosody-mod_admin_web ($scheme:$port/admin/) HTTP $code — auth required" ;;
            404)
                : ;;
            *)
                log "  prosody-mod_admin_web ($scheme:$port/admin/) HTTP $code" ;;
        esac
    done
fi

log "admin-api probe done."
