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
log "curl -I (headers only, UA=$(curl_ua | head -c 40)...)"
UA=$(curl_ua)
while read -r url; do
    safe=$(echo "$url" | sed 's|[:/]|_|g')
    curl -ksLI -A "$UA" --connect-timeout 5 --max-time 10 "$url" \
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

# ---------- 7. Bug-class checks (iteration C — read-only) ----------
# Six small per-URL probes that don't fit any of the prior tools. Each is
# best-effort; failure is silent. Operator inspects the per-URL files.
LIVE_URLS="$OUT/_alive_urls.txt"
if [ ! -s "$LIVE_URLS" ] && [ -s "$OUT/httpx.txt" ]; then
    awk '{print $1}' "$OUT/httpx.txt" | sort -u > "$LIVE_URLS"
fi
# Fall back to the candidate-URL list if httpx didn't run / found nothing
[ ! -s "$LIVE_URLS" ] && cp "$URLS" "$LIVE_URLS" 2>/dev/null || true

if [ -s "$LIVE_URLS" ]; then
    log "iteration-C bug-class probes against $(wc -l < "$LIVE_URLS") URL(s)"

    # ----- C.11 cert + SAN collection (HTTPS only) -----
    while read -r url; do
        [ -z "$url" ] && continue
        [[ "$url" != https://* ]] && continue
        # Parse host:port from the URL
        hp=$(echo "$url" | sed -E 's|^https://([^/]+).*|\1|')
        safe=$(echo "$url" | sed 's|[:/]|_|g')
        if have openssl; then
            timeout 8 openssl s_client -connect "$hp" -servername "${hp%%:*}" \
                -showcerts </dev/null > "$OUT/cert_${safe}.txt" 2>/dev/null || true
            # Extract SANs into a flat per-URL list
            awk '/-----BEGIN CERT/{f=1} f{print} /-----END CERT/{f=0; exit}' \
                "$OUT/cert_${safe}.txt" 2>/dev/null \
                | openssl x509 -noout -ext subjectAltName 2>/dev/null \
                | grep -oE 'DNS:[^,[:space:]]+' | sed 's/^DNS://' \
                > "$OUT/sans_${safe}.txt" 2>/dev/null || true
        fi
    done < "$LIVE_URLS"
    # Aggregate every discovered SAN — feeds vhost-fuzz seeds and DNS pivot
    cat "$OUT"/sans_*.txt 2>/dev/null | sort -u > "$OUT/_all_sans.txt" || true

    # ----- C.9 exposed VCS / sensitive paths -----
    declare -a VCS_PATHS=(
        "/.git/HEAD" "/.git/config" "/.svn/entries" "/.svn/wc.db"
        "/.hg/store" "/.DS_Store" "/.env" "/.env.local" "/.env.production"
        "/web.config" "/wp-config.php.bak" "/config.json"
        "/server-status" "/server-info"
    )
    declare -a API_PATHS=(
        "/api/swagger.json" "/swagger.json" "/openapi.json"
        "/actuator/health" "/actuator/env" "/actuator/heapdump"
        "/wp-json/wp/v2/users" "/admin" "/phpmyadmin/" "/manager/html"
    )
    while read -r url; do
        [ -z "$url" ] && continue
        safe=$(echo "$url" | sed 's|[:/]|_|g')
        : > "$OUT/exposed_${safe}.txt"
        for p in "${VCS_PATHS[@]}" "${API_PATHS[@]}"; do
            code=$(curl -ksI --connect-timeout 4 --max-time 8 \
                        -o /dev/null -w '%{http_code}' "${url}${p}" 2>/dev/null)
            [ "$code" = "000" ] && continue
            # Anything 200/401/403 is interesting; 404 is not.
            case "$code" in
                200) hit "EXPOSED: ${url}${p} (HTTP 200)" ; echo "$code  ${url}${p}" >> "$OUT/exposed_${safe}.txt" ;;
                401|403) echo "$code  ${url}${p}" >> "$OUT/exposed_${safe}.txt" ;;
            esac
        done
    done < "$LIVE_URLS"

    # ----- C.8 CORS misconfig probe -----
    while read -r url; do
        [ -z "$url" ] && continue
        safe=$(echo "$url" | sed 's|[:/]|_|g')
        evil="https://attacker.example.invalid"
        hdrs=$(curl -ksI -H "Origin: $evil" --connect-timeout 4 --max-time 8 \
                    "$url/" 2>/dev/null)
        echo "$hdrs" > "$OUT/cors_${safe}.txt"
        # Flag any reflection of the attacker origin
        if echo "$hdrs" | grep -qi "Access-Control-Allow-Origin: ${evil}"; then
            if echo "$hdrs" | grep -qi "Access-Control-Allow-Credentials: true"; then
                err "CRITICAL CORS: $url reflects attacker Origin + ACAC=true"
            else
                hit "CORS: $url reflects attacker Origin (no credentials flag)"
            fi
        fi
    done < "$LIVE_URLS"

    # ----- C.7 JWT extraction + weak-alg flag -----
    # Find anything looking like a JWT in response bodies (header.payload.sig
    # with base64url-ish segments). Decode the header; flag alg=none / HS256.
    : > "$OUT/_jwts.txt"
    while read -r url; do
        [ -z "$url" ] && continue
        body=$(curl -ks --connect-timeout 5 --max-time 10 "$url/" 2>/dev/null | head -c 200000)
        # Greedy match for JWT shape (header.payload.signature)
        echo "$body" | grep -oE 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' \
            | sort -u | while read -r jwt; do
            hdr=$(echo "$jwt" | cut -d. -f1)
            # base64url -> base64 (pad)
            pad=$((4 - ${#hdr} % 4)); [ "$pad" -eq 4 ] && pad=0
            hdr_b64="${hdr}$(printf '=%.0s' $(seq 1 $pad))"
            hdr_b64=$(echo "$hdr_b64" | tr '_-' '/+')
            decoded=$(echo "$hdr_b64" | base64 -d 2>/dev/null)
            alg=$(echo "$decoded" | grep -oE '"alg":"[^"]+' | head -1 | cut -d'"' -f4)
            case "$alg" in
                none|None|NONE)
                    err "JWT alg=none in $url (forge any token)" ;;
                HS256|HS384|HS512)
                    hit "JWT $alg in $url — HMAC; brute the secret with hashcat -m 16500" ;;
            esac
            echo "$url  $alg  $jwt" >> "$OUT/_jwts.txt"
        done
    done < "$LIVE_URLS"

    # ----- C.10 virtual-host fuzz seed -----
    # We don't ship a wordlist; we surface the seed (target IP + collected
    # SANs) so the operator can fire ffuf manually. Sample command goes in
    # _hints.txt.
    if [ -s "$OUT/_all_sans.txt" ]; then
        log "vhost seed: $(wc -l < "$OUT/_all_sans.txt") SAN domain(s) collected — see _hints.txt for ffuf command"
    fi

    # ----- C.12 micro-wordlist of high-value paths -----
    # Already covered by the VCS+API list in C.9 above. Skip duplicate work.
fi

# ---------- 8. iteration-C hints ----------
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

iteration-C HTTP follow-ups:
  * VCS/exposed/admin paths — see exposed_*.txt for HTTP 200/401/403 results.
  * CORS reflection — see cors_*.txt; ACAC=true + reflected Origin is critical.
  * JWTs found — see _jwts.txt. alg=none = forge any token; HS* = brute-secret.
  * Cert SANs aggregated into _all_sans.txt. To virtual-host fuzz:
      ffuf -u http://<target-ip>/ -H "Host: FUZZ" -w _all_sans.txt -fs <baseline-size>
EOF
# If _hints.txt didn't exist, create it minimal so the appender above isn't lost
[ ! -f "$OUT/_hints.txt" ] && echo "see iteration-C blocks in dispatcher output" > "$OUT/_hints.txt"

rm -f "$URLS"
log "http dispatcher done."
