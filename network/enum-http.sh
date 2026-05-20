#!/usr/bin/env bash
# enum-http.sh — HTTP/HTTPS enumeration: tech fingerprint, headers, common paths.
# Handles both http and https targets in one run (urls are built from ip:port).
#
# Env knobs (all optional):
#   NO_NUCLEI=1         skip nuclei entirely
#   NO_FFUF=1           skip ffuf entirely
#   NO_WHATWEB=1        skip whatweb entirely
#   WEB_PROBE_ONLY=1    only run httpx alive-check (implies NO_NUCLEI/NO_FFUF/NO_WHATWEB/no-headers/no-nikto)
#   RUN_NIKTO=1         enable nikto (off by default — very slow)
#   NUCLEI_TIMEOUT=600  hard wall-clock cap on nuclei in seconds (default 600 = 10m)
#   NUCLEI_RATE=150     nuclei -rate-limit (default 150)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "http: $(wc -l < "$TARGETS") targets -> $OUT"

# CLI aliases for the env knobs above (override or set them)
for a in "$@"; do
    case "$a" in
        --no-nuclei)      NO_NUCLEI=1 ;;
        --no-ffuf)        NO_FFUF=1 ;;
        --no-whatweb)     NO_WHATWEB=1 ;;
        --probe-only)     WEB_PROBE_ONLY=1 ;;
    esac
done

if [ "${WEB_PROBE_ONLY:-0}" = "1" ]; then
    NO_NUCLEI=1; NO_FFUF=1; NO_WHATWEB=1
fi

# Build URL list. We can't know scheme just from port — try both for 443/8443/etc.
URLS=$(mktemp)
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    # IPv6 needs brackets in URL form
    [[ "$ip" == *:* ]] && ip="[$ip]"
    case "$port" in
        443|4443|8443|9443|10443) echo "https://$ip:$port" >> "$URLS" ;;
        80|81|8000|8008|8080|8081|8888|7001|7002|9000|9090|5000) echo "http://$ip:$port" >> "$URLS" ;;
        *) echo "http://$ip:$port" >> "$URLS"; echo "https://$ip:$port" >> "$URLS" ;;
    esac
done < "$TARGETS"
sort -u -o "$URLS" "$URLS"
cp "$URLS" "$OUT/urls.txt"
log "  $(wc -l < "$URLS") candidate URLs"

# ---------- 1. httpx — alive check, tech, status, title ----------
# TLS verification is disabled across the board (engagements often hit self-signed certs).
# Detect projectdiscovery httpx (the scanner) vs python-httpx (HTTP client). They share the name.
PD_HTTPX=""
for cand in httpx httpx-toolkit /usr/bin/httpx-toolkit /home/jay/go/bin/httpx; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -version 2>&1 | grep -qi 'projectdiscovery\|nuclei\|httpx version'; then
            PD_HTTPX="$(command -v "$cand")"; break
        fi
    fi
done

if [ -n "$PD_HTTPX" ]; then
    log "httpx ($PD_HTTPX — alive / status / title / tech, TLS verify off)"
    "$PD_HTTPX" -silent -l "$URLS" -status-code -title -tech-detect -follow-redirects \
        -no-tls-verify \
        -o "$OUT/httpx.txt" >/dev/null 2>&1 || true
else
    # Fallback: curl-based alive probe so the dispatcher still produces an alive-list.
    miss "projectdiscovery httpx not found — using curl fallback for alive-check"
    : > "$OUT/httpx.txt"
    while read -r url; do
        code=$(curl -ksL -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 "$url" 2>/dev/null || echo "000")
        [ "$code" != "000" ] && printf "%s [%s]\n" "$url" "$code" >> "$OUT/httpx.txt"
    done < "$URLS"
fi

if [ "${WEB_PROBE_ONLY:-0}" = "1" ]; then
    log "WEB_PROBE_ONLY=1 — httpx only, skipping whatweb/curl/nuclei/ffuf/nikto"
    rm -f "$URLS"
    log "http dispatcher done."
    exit 0
fi

# ---------- 2. whatweb ----------
if [ "${NO_WHATWEB:-0}" != "1" ] && have whatweb; then
    log "whatweb"
    timeout 120 whatweb -i "$URLS" --no-errors -q --colour=never \
        > "$OUT/whatweb.txt" 2>&1 || true
fi

# ---------- 3. curl headers ----------
log "curl -I (headers only)"
while read -r url; do
    safe=$(echo "$url" | sed 's|[:/]|_|g')
    curl -ksLI --connect-timeout 5 --max-time 10 "$url" \
        > "$OUT/headers_${safe}.txt" 2>&1 || true
done < "$URLS"

# ---------- 4. nuclei (optional; off if no templates, NO_NUCLEI=1, or no live URLs) ----------
if [ "${NO_NUCLEI:-0}" = "1" ]; then
    log "nuclei skipped (NO_NUCLEI=1)"
elif have nuclei; then
    # Pre-flight: need templates cached (auto-download on first run = multi-minute hang)
    TPL_DIR="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"
    [ ! -d "$TPL_DIR" ] && TPL_DIR="$(nuclei -version 2>&1 | awk -F': ' '/Templates Directory/{print $2}' | tr -d '\r')"
    if [ -z "$TPL_DIR" ] || [ ! -d "$TPL_DIR" ] || [ -z "$(ls -A "$TPL_DIR" 2>/dev/null)" ]; then
        miss "nuclei templates not found ($TPL_DIR) — skipping. Run 'nuclei -update-templates' once, or pass NO_NUCLEI=1 to silence."
    else
        # Prefer alive-only URL list from httpx if available, else full URL list
        NUC_TARGETS="$URLS"
        if [ -s "$OUT/httpx.txt" ]; then
            awk '{print $1}' "$OUT/httpx.txt" | sort -u > "$OUT/_alive_urls.txt"
            [ -s "$OUT/_alive_urls.txt" ] && NUC_TARGETS="$OUT/_alive_urls.txt"
        fi
        NUC_TO="${NUCLEI_TIMEOUT:-600}"
        NUC_RATE="${NUCLEI_RATE:-150}"
        log "nuclei (severity high,critical; timeout ${NUC_TO}s; rate ${NUC_RATE}; $(wc -l < "$NUC_TARGETS") targets)"
        timeout --kill-after=10 "$NUC_TO" nuclei \
            -l "$NUC_TARGETS" -severity high,critical -silent \
            -tags exposures,cve,misconfig,default-logins \
            -rate-limit "$NUC_RATE" -timeout 8 -retries 1 \
            -max-host-error 3 -disable-update-check \
            -stats-interval 30 \
            -o "$OUT/nuclei.txt" >/dev/null 2>&1
        rc=$?
        if   [ "$rc" -eq 124 ]; then err "nuclei wall-clock timeout (${NUC_TO}s) — partial results in $OUT/nuclei.txt"
        elif [ "$rc" -ne 0 ];   then miss "nuclei exited $rc (non-fatal)"
        fi
        rm -f "$OUT/_alive_urls.txt"
    fi
fi

# ---------- 5. ffuf light wordlist ----------
if [ "${NO_FFUF:-0}" != "1" ] && have ffuf; then
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
    if [ -r "$WORDLIST" ]; then
        log "ffuf common.txt against alive URLs (top 30)"
        head -30 "$OUT/httpx.txt" 2>/dev/null | awk '{print $1}' | while read -r url; do
            [ -z "$url" ] && continue
            safe=$(echo "$url" | sed 's|[:/]|_|g')
            timeout 120 ffuf -u "$url/FUZZ" -w "$WORDLIST" -mc 200,204,301,302,307,401,403 \
                 -k -t 20 -s -o "$OUT/ffuf_${safe}.json" -of json >/dev/null 2>&1 || true
        done
    else
        miss "no $WORDLIST — skipping ffuf"
    fi
fi

# ---------- 6. nikto (optional, slow) ----------
if have nikto; then
    if [ "${RUN_NIKTO:-0}" = "1" ]; then
        log "nikto (slow — RUN_NIKTO=1)"
        while read -r url; do
            safe=$(echo "$url" | sed 's|[:/]|_|g')
            timeout 600 nikto -h "$url" -nointeractive -ask no \
                > "$OUT/nikto_${safe}.txt" 2>&1 || true
        done < "$URLS"
    else
        log "(skipping nikto by default — set RUN_NIKTO=1 to enable; very slow)"
    fi
fi

rm -f "$URLS"
log "http dispatcher done."
