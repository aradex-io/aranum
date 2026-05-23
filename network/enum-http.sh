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

# Pre-filter the extension flags out of "$@" BEFORE parse_common_args runs.
# parse_common_args (network/_lib.sh) rejects any flag that isn't --targets
# or --output with "unknown arg: ..." → return 1; previously these CLI
# aliases were documented and parsed in a post-call loop that could never be
# reached, so only the env-var form (NO_NUCLEI=1 ...) ever worked from the
# command line. Operators passing `enum-http.sh --no-nuclei ...` saw an
# `unknown arg` error and exit instead of the intended behaviour.
_passthrough=()
for a in "$@"; do
    case "$a" in
        --no-nuclei)      NO_NUCLEI=1 ;;
        --no-ffuf)        NO_FFUF=1 ;;
        --no-whatweb)     NO_WHATWEB=1 ;;
        --probe-only)     WEB_PROBE_ONLY=1 ;;
        *)                _passthrough+=("$a") ;;
    esac
done
set -- "${_passthrough[@]+"${_passthrough[@]}"}"
unset _passthrough

parse_common_args "$@" || exit 1
log "http: $(wc -l < "$TARGETS") targets -> $OUT"

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

# ---------- C.13 Product fingerprint + version checks ----------
# Fan out 8 product-specific probes per live URL. Each detector requires a
# product-specific marker (header pattern, JSON key, or exact body string)
# before emitting a hit — "HTTP 200 on the canonical path" is never sufficient
# (lesson from v0.20.1 two-evidence discipline).
#
# Skip the whole phase with NO_PRODUCT_DETECT=1 (mirrors NO_NUCLEI=1 / NO_FFUF=1).
if [ "${NO_PRODUCT_DETECT:-0}" = "1" ]; then
    log "product-detect skipped (NO_PRODUCT_DETECT=1)"
elif [ -s "$LIVE_URLS" ]; then
    log "C.13 product-fingerprint probes against $(wc -l < "$LIVE_URLS") live URL(s)"

    while read -r url; do
        [ -z "$url" ] && continue
        safe=$(echo "$url" | sed 's|[:/]|_|g')

        # Helper: run one probe and emit status + body + saved headers.
        # Usage: probe_result=$(prod_probe "$url" "$path" "$safe" "$product")
        # Returns body with sentinel appended; headers written to
        # $OUT/prod_${product}_hdr_${safe}.txt
        #
        # Inline below per product to avoid subshell overhead on many URLs.

        # --- 1. Tomcat Manager ---
        # Probe /manager/html — require realm="Tomcat Manager Application" OR
        # body contains distinctive Tomcat Manager string.
        tm_hdr="$OUT/prod_tomcat_hdr_${safe}.txt"
        tm_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$tm_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/manager/html" 2>/dev/null)
        tm_status=$(echo "$tm_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        tm_body=$(echo "$tm_body" | sed '/---HTTP-STATUS:/d')
        if [ "$tm_status" = "401" ] && grep -qi 'realm="Tomcat Manager Application"' "$tm_hdr" 2>/dev/null; then
            hit "Tomcat Manager auth required: ${url}/manager/html"
        elif [ "$tm_status" = "200" ] && (echo "$tm_body" | grep -qi "Tomcat Web Application Manager" || echo "$tm_body" | grep -qi "Manager - HTML Host Manager"); then
            hit "UNAUTH: Tomcat Manager exposed: ${url}"
        fi
        # Also probe /host-manager/text/list
        hm_hdr="$OUT/prod_tomcat_hm_hdr_${safe}.txt"
        hm_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$hm_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/host-manager/text/list" 2>/dev/null)
        hm_status=$(echo "$hm_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        hm_body=$(echo "$hm_body" | sed '/---HTTP-STATUS:/d')
        if [ "$hm_status" = "200" ] && echo "$hm_body" | grep -q "^OK - Listed hosts:"; then
            hit "UNAUTH: Tomcat host-manager exposed: ${url}"
        fi
        throttle_sleep

        # --- 2. Jenkins ---
        jk_hdr="$OUT/prod_jenkins_hdr_${safe}.txt"
        jk_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$jk_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/api/json" 2>/dev/null)
        jk_status=$(echo "$jk_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        jk_body=$(echo "$jk_body" | sed '/---HTTP-STATUS:/d')
        # X-Jenkins header is the definitive marker
        if grep -qi "^X-Jenkins:" "$jk_hdr" 2>/dev/null; then
            jk_version=$(grep -i "^X-Jenkins:" "$jk_hdr" 2>/dev/null | head -1 | sed 's/[Xx]-[Jj]enkins:[[:space:]]*//' | tr -d '\r\n')
            hit "Jenkins detected: ${url} — ${jk_version}"
            if [ "$jk_status" = "200" ] && echo "$jk_body" | grep -q '"_class":"hudson.model.Hudson"'; then
                hit "UNAUTH: Jenkins API exposed: ${url}"
            fi
        fi
        # Probe /asynchPeople/api/json for user enumeration
        jp_hdr="$OUT/prod_jenkins_people_hdr_${safe}.txt"
        jp_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$jp_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/asynchPeople/api/json" 2>/dev/null)
        jp_status=$(echo "$jp_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        jp_body=$(echo "$jp_body" | sed '/---HTTP-STATUS:/d')
        if [ "$jp_status" = "200" ] && echo "$jp_body" | grep -q '"users":'; then
            hit "Jenkins user enumeration exposed: ${url}"
        fi
        # Probe /script for Groovy script console (full RCE if accessible)
        js_hdr="$OUT/prod_jenkins_script_hdr_${safe}.txt"
        js_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$js_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/script" 2>/dev/null)
        js_status=$(echo "$js_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        js_body=$(echo "$js_body" | sed '/---HTTP-STATUS:/d')
        if [ "$js_status" = "200" ] && echo "$js_body" | grep -qi "Groovy script" && echo "$js_body" | grep -qi "console"; then
            hit "CRITICAL: Jenkins Groovy script console reachable: ${url}"
        fi
        throttle_sleep

        # --- 3. GitLab ---
        gl_hdr="$OUT/prod_gitlab_hdr_${safe}.txt"
        gl_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$gl_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/api/v4/version" 2>/dev/null)
        gl_status=$(echo "$gl_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        gl_body=$(echo "$gl_body" | sed '/---HTTP-STATUS:/d')
        # GitLab marker: Server header OR body with both "version" and "revision" JSON keys
        gl_is_gitlab=0
        grep -qi "^Server: GitLab" "$gl_hdr" 2>/dev/null && gl_is_gitlab=1
        if [ "$gl_status" = "200" ] && echo "$gl_body" | grep -q '"version"' && echo "$gl_body" | grep -q '"revision"'; then
            gl_is_gitlab=1
        fi
        if [ "$gl_is_gitlab" = "1" ]; then
            gl_version=$(echo "$gl_body" | grep -oE '"version":"[^"]+"' | head -1 | cut -d'"' -f4)
            hit "GitLab detected: ${url} — ${gl_version}"
            if [ "$gl_status" = "200" ]; then
                hit "UNAUTH: GitLab API exposed: ${url}"
            fi
        fi
        throttle_sleep

        # --- 4. SonarQube ---
        sq_hdr="$OUT/prod_sonarqube_hdr_${safe}.txt"
        sq_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$sq_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/api/server/version" 2>/dev/null)
        sq_status=$(echo "$sq_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        sq_body=$(echo "$sq_body" | sed '/---HTTP-STATUS:/d')
        sq_ver=$(echo "$sq_body" | tr -d '[:space:]')
        if [ "$sq_status" = "200" ] && echo "$sq_ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
            hit "SonarQube detected: ${url} — ${sq_ver}"
            # Probe /api/system/info for unauth system info
            si_hdr="$OUT/prod_sonarqube_si_hdr_${safe}.txt"
            si_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
                --connect-timeout 4 --max-time 8 \
                -D "$si_hdr" \
                -w "\n---HTTP-STATUS:%{http_code}---\n" \
                "${url}/api/system/info" 2>/dev/null)
            si_status=$(echo "$si_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
            si_body=$(echo "$si_body" | sed '/---HTTP-STATUS:/d')
            if [ "$si_status" = "200" ] && echo "$si_body" | grep -q '"System":{'; then
                hit "UNAUTH: SonarQube system info exposed: ${url}"
            fi
        fi
        throttle_sleep

        # --- 5. Grafana ---
        gf_hdr="$OUT/prod_grafana_hdr_${safe}.txt"
        gf_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$gf_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/api/health" 2>/dev/null)
        gf_status=$(echo "$gf_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        gf_body=$(echo "$gf_body" | sed '/---HTTP-STATUS:/d')
        if [ "$gf_status" = "200" ] && echo "$gf_body" | grep -q '"database"' && echo "$gf_body" | grep -q '"version"'; then
            gf_version=$(echo "$gf_body" | grep -oE '"version":"[^"]+"' | head -1 | cut -d'"' -f4)
            hit "Grafana detected: ${url} — ${gf_version}"
            # Probe /api/datasources
            gd_hdr="$OUT/prod_grafana_ds_hdr_${safe}.txt"
            gd_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
                --connect-timeout 4 --max-time 8 \
                -D "$gd_hdr" \
                -w "\n---HTTP-STATUS:%{http_code}---\n" \
                "${url}/api/datasources" 2>/dev/null)
            gd_status=$(echo "$gd_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
            gd_body=$(echo "$gd_body" | sed '/---HTTP-STATUS:/d')
            if [ "$gd_status" = "200" ] && echo "$gd_body" | grep -q '^\['; then
                hit "UNAUTH: Grafana datasources exposed: ${url}"
            fi
        fi
        throttle_sleep

        # --- 6. Prometheus ---
        pm_hdr="$OUT/prod_prometheus_hdr_${safe}.txt"
        pm_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$pm_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/-/healthy" 2>/dev/null)
        pm_status=$(echo "$pm_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        pm_body=$(echo "$pm_body" | sed '/---HTTP-STATUS:/d')
        pm_body_trimmed=$(echo "$pm_body" | tr -d '\r' | sed '/^$/d')
        if [ "$pm_status" = "200" ] && [ "$pm_body_trimmed" = "Prometheus Server is Healthy." ]; then
            hit "Prometheus detected: ${url}"
            # Probe /api/v1/status/buildinfo for version
            pb_hdr="$OUT/prod_prometheus_bi_hdr_${safe}.txt"
            pb_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
                --connect-timeout 4 --max-time 8 \
                -D "$pb_hdr" \
                -w "\n---HTTP-STATUS:%{http_code}---\n" \
                "${url}/api/v1/status/buildinfo" 2>/dev/null)
            pb_status=$(echo "$pb_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
            pb_body=$(echo "$pb_body" | sed '/---HTTP-STATUS:/d')
            if [ "$pb_status" = "200" ] && echo "$pb_body" | grep -q '"status":"success"' && echo "$pb_body" | grep -q '"version":'; then
                pb_version=$(echo "$pb_body" | grep -oE '"version":"[^"]+"' | head -1 | cut -d'"' -f4)
                hit "Prometheus version: ${url} — ${pb_version}"
            fi
            # Probe /api/v1/status/config for unauth config exposure
            pc_hdr="$OUT/prod_prometheus_cfg_hdr_${safe}.txt"
            pc_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
                --connect-timeout 4 --max-time 8 \
                -D "$pc_hdr" \
                -w "\n---HTTP-STATUS:%{http_code}---\n" \
                "${url}/api/v1/status/config" 2>/dev/null)
            pc_status=$(echo "$pc_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
            pc_body=$(echo "$pc_body" | sed '/---HTTP-STATUS:/d')
            if [ "$pc_status" = "200" ] && echo "$pc_body" | grep -q '"status":"success"' && echo "$pc_body" | grep -q '"yaml":'; then
                hit "UNAUTH: Prometheus config exposed: ${url}"
            fi
        fi
        throttle_sleep

        # --- 7. Hadoop NameNode ---
        hn_hdr="$OUT/prod_hadoop_hdr_${safe}.txt"
        hn_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$hn_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/dfshealth.html" 2>/dev/null)
        hn_status=$(echo "$hn_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        hn_body=$(echo "$hn_body" | sed '/---HTTP-STATUS:/d')
        if [ "$hn_status" = "200" ] && echo "$hn_body" | grep -q "Hadoop" && echo "$hn_body" | grep -q "NameNode"; then
            hit "Hadoop NameNode UI exposed: ${url}"
        fi
        # Probe /jmx
        hj_hdr="$OUT/prod_hadoop_jmx_hdr_${safe}.txt"
        hj_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$hj_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/jmx" 2>/dev/null)
        hj_status=$(echo "$hj_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        hj_body=$(echo "$hj_body" | sed '/---HTTP-STATUS:/d')
        if [ "$hj_status" = "200" ] && echo "$hj_body" | grep -q '"beans"' && echo "$hj_body" | grep -q '"java.lang:type=Runtime"'; then
            hit "Hadoop JMX endpoint exposed: ${url}"
        fi
        throttle_sleep

        # --- 8. Spark UI ---
        sp_hdr="$OUT/prod_spark_hdr_${safe}.txt"
        sp_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$sp_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/api/v1/applications" 2>/dev/null)
        sp_status=$(echo "$sp_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        sp_body=$(echo "$sp_body" | sed '/---HTTP-STATUS:/d')
        if [ "$sp_status" = "200" ] \
            && grep -qi "^Server: Jetty" "$sp_hdr" 2>/dev/null \
            && (echo "$sp_body" | grep -q '"sparkUser"' || echo "$sp_body" | grep -q '"appId"'); then
            hit "Spark UI applications API exposed: ${url}"
        fi
        throttle_sleep

        # --- 9. VMware vCenter ---
        # Two-evidence gate: SDK namespace marker OR vSphere Client title.
        # Neither probe fires a hit on bare HTTP 200 — the product-specific
        # marker string must be present in the response body.

        # SDK endpoint: expects <namespace>urn:vim25</namespace>
        vc_sdk_hdr="$OUT/prod_vcenter_sdk_hdr_${safe}.txt"
        vc_sdk_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$vc_sdk_hdr" \
            "${url}/sdk/vimServiceVersions.xml" 2>/dev/null)
        if echo "$vc_sdk_body" | grep -q "urn:vim25"; then
            hit "VMware vCenter SDK reachable: ${url}"
        fi

        # UI endpoint: expects <title>vSphere Client</title>
        vc_ui_hdr="$OUT/prod_vcenter_ui_hdr_${safe}.txt"
        vc_ui_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$vc_ui_hdr" \
            "${url}/ui/" 2>/dev/null)
        if echo "$vc_ui_body" | grep -qi "vSphere Client"; then
            hit "VMware vCenter UI: ${url}"
        fi

        throttle_sleep

        # --- 10. I-D BMC vendor fingerprinting ---
        # Out-of-band management consoles. Each detector requires a vendor-
        # specific marker in body AND a confirming header pattern, OR an
        # exact resource path that only that vendor serves.
        bmc_root_hdr="$OUT/prod_bmc_root_hdr_${safe}.txt"
        bmc_root_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$bmc_root_hdr" \
            "${url}/" 2>/dev/null)

        # HPE iLO: Server: HP-iLO-Server or body contains "iLO Management Engine" /
        # /redfish/v1/ with HP Integrated Lights-Out signature.
        if grep -qiE '^server:[[:space:]]*hp[-_]?ilo' "$bmc_root_hdr" 2>/dev/null \
           || echo "$bmc_root_body" | grep -qiE '(iLO [0-9]+|HP Integrated Lights-Out|HPE Integrated Lights-Out)'; then
            ilo_version=$(grep -oiE 'iLO ?[0-9]+' "$bmc_root_hdr" "$bmc_root_body" 2>/dev/null | head -1 || true)
            hit "BMC HPE iLO detected: ${url} — version=${ilo_version:-?}"
        fi

        # Dell iDRAC: body contains "iDRAC" + "Integrated Dell Remote Access Controller"
        # OR resource path /restgui/start.html (iDRAC 9+) returns 200.
        if echo "$bmc_root_body" | grep -qE 'Integrated Dell Remote Access Controller' \
           || echo "$bmc_root_body" | grep -qE '"iDRAC[0-9]?"' \
           || curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --connect-timeout 3 --max-time 6 \
               -o /dev/null -w '%{http_code}' "${url}/restgui/start.html" 2>/dev/null | grep -q '^200$'; then
            hit "BMC Dell iDRAC detected: ${url}"
        fi

        # Supermicro IPMI/BMC: body contains "ATEN International" (the OEM that
        # produces Supermicro's IPMI firmware) AND specific JS asset paths.
        if echo "$bmc_root_body" | grep -qiE '(ATEN International|Supermicro|SMC[ _]?BMC|/cgi/login\.cgi)' \
           && curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --connect-timeout 3 --max-time 6 \
               -o /dev/null -w '%{http_code}' "${url}/cgi/login.cgi" 2>/dev/null | grep -qE '^(200|302|401)$'; then
            hit "BMC Supermicro IPMI detected: ${url}"
        fi

        # Lenovo XCC/IMM: body contains "Lenovo XClarity Controller" OR
        # "Integrated Management Module" with a Lenovo-specific marker.
        if echo "$bmc_root_body" | grep -qE '(Lenovo XClarity Controller|XClarity Controller|Integrated Management Module II|IBM[[:space:]]+Integrated[[:space:]]+Management[[:space:]]+Module)'; then
            hit "BMC Lenovo XCC/IMM detected: ${url}"
        fi

        # Cisco CIMC: body contains "Cisco Integrated Management Controller"
        # AND /software/ or /flex/ asset path returns 200.
        if echo "$bmc_root_body" | grep -qE '(Cisco Integrated Management Controller|CIMC[[:space:]]+Login)'; then
            hit "BMC Cisco CIMC detected: ${url}"
        fi

        throttle_sleep

        # --- 11. I-J VPN concentrator fingerprinting ---
        # Vendor SSL VPN portals — login pages with vendor-specific body markers.
        # All detection-only; no credential probing.

        # Cisco AnyConnect / ASA SSL VPN: /+CSCOE+/logon.html or
        # /+CSCOU+/* assets. Body contains "AnyConnect Secure Mobility Client"
        # or +webvpn+ markers.
        cisco_anyconnect=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/+CSCOE+/logon.html" 2>/dev/null)
        if echo "$cisco_anyconnect" | grep -qE '(AnyConnect|webvpn_logon|cisco_logon|CSCOE)'; then
            hit "VPN Cisco AnyConnect/ASA SSL VPN detected: ${url}"
        fi

        # Fortinet SSL VPN: /remote/login or /sslvpn/portal — body contains
        # "FortiGate" or "Fortinet" or the canonical login JS path
        # /remote/fgt_lang. CVE-2022-42475 / CVE-2023-27997 reachability.
        fortinet=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/remote/login" 2>/dev/null)
        if echo "$fortinet" | grep -qE '(FortiGate|Fortinet|fgt_lang|/sslvpn/|tos\.cgi)'; then
            hit "VPN Fortinet SSL VPN detected: ${url}"
        fi

        # Palo Alto GlobalProtect: /global-protect/login.esp returns the
        # canonical portal page. CVE-2024-3400 reachability.
        palo=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/global-protect/login.esp" 2>/dev/null)
        if echo "$palo" | grep -qE '(GlobalProtect Portal|globalprotect|Palo Alto Networks)'; then
            hit "VPN Palo Alto GlobalProtect detected: ${url}"
        fi

        # Pulse Secure / Ivanti Connect Secure: /dana-na/auth/url_default/welcome.cgi
        # CVE-2023-46805 + CVE-2024-21887 reachability.
        pulse=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/dana-na/auth/url_default/welcome.cgi" 2>/dev/null)
        if echo "$pulse" | grep -qE '(Pulse Secure|Ivanti Connect Secure|dana-na|/dana/)'; then
            hit "VPN Pulse/Ivanti Connect Secure detected: ${url}"
        fi

        # Citrix NetScaler Gateway: /vpn/index.html — body contains
        # "Citrix Gateway" or "NetScaler". CVE-2023-3519 / CVE-2023-4966 era.
        citrix=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/vpn/index.html" 2>/dev/null)
        if echo "$citrix" | grep -qE '(Citrix Gateway|NetScaler Gateway|NetScaler ADC|/logon/LogonPoint/)'; then
            hit "VPN Citrix NetScaler Gateway detected: ${url}"
        fi

        # SonicWall SMA / NetExtender: /__api__/v1 or /cgi-bin/welcome with
        # canonical SonicWall banner. CVE-2024-40766 era.
        sonicwall=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/cgi-bin/welcome" 2>/dev/null)
        if echo "$sonicwall" | grep -qE '(SonicWall|NetExtender|sonicwall_swl|sma1000|sma100)'; then
            hit "VPN SonicWall SMA/NetExtender detected: ${url}"
        fi

        throttle_sleep

        # --- 12. VMware ESXi host (NOT vCenter) ---
        # Discriminator from block 9: title contains "VMware Host Client"
        # (vCenter is "vSphere Client"). Probe /ui/ — same path, different marker.
        esxi_ui_hdr="$OUT/prod_esxi_ui_hdr_${safe}.txt"
        esxi_ui_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$esxi_ui_hdr" \
            "${url}/ui/" 2>/dev/null)
        if echo "$esxi_ui_body" | grep -qi "VMware Host Client"; then
            hit "Hypervisor VMware ESXi host detected: ${url}"
        fi
        throttle_sleep

        # --- 13. Proxmox VE ---
        # Probe /api2/json/version — two-evidence: JSON contains "data":
        # AND data has all three of "release":, "version":, "repoid": keys.
        # If the endpoint returns data without auth, also emit UNAUTH signal.
        pve_hdr="$OUT/prod_proxmox_hdr_${safe}.txt"
        pve_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$pve_hdr" \
            -w "\n---HTTP-STATUS:%{http_code}---\n" \
            "${url}/api2/json/version" 2>/dev/null)
        pve_status=$(echo "$pve_body" | grep -oE 'HTTP-STATUS:[0-9]+' | tail -1 | cut -d: -f2)
        pve_body=$(echo "$pve_body" | sed '/---HTTP-STATUS:/d')
        if [ "$pve_status" = "200" ] \
           && echo "$pve_body" | grep -q '"data":' \
           && echo "$pve_body" | grep -q '"release":' \
           && echo "$pve_body" | grep -q '"version":' \
           && echo "$pve_body" | grep -q '"repoid":'; then
            version=$(echo "$pve_body" | grep -oE '"version":"[^"]+"' | head -1 | cut -d'"' -f4)
            hit "Hypervisor Proxmox VE detected: ${url} — version=${version:-?}"
            hit "UNAUTH: Proxmox version API exposed: ${url}"
        fi
        throttle_sleep

        # --- 14. Nutanix Prism ---
        # Probe /console/ with headers — two-evidence: Set-Cookie header
        # contains NTNX_IGW_SESSION AND body contains "Nutanix" or "Prism".
        ntnx_hdr="$OUT/prod_nutanix_hdr_${safe}.txt"
        ntnx_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$ntnx_hdr" \
            "${url}/console/" 2>/dev/null)
        if grep -qiE 'Set-Cookie:.*NTNX_IGW_SESSION' "$ntnx_hdr" 2>/dev/null \
           && (echo "$ntnx_body" | grep -qiE '(Nutanix|Prism)'); then
            hit "Hypervisor Nutanix Prism detected: ${url}"
        fi
        throttle_sleep

        # --- 15. OpenStack Keystone ---
        # Probe /v3 — two-evidence: JSON envelope with "version":{ AND
        # contains "status":"stable"|"beta"|"deprecated" AND contains "rel":"self".
        ks_hdr="$OUT/prod_keystone_hdr_${safe}.txt"
        ks_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$ks_hdr" \
            "${url}/v3" 2>/dev/null)
        if echo "$ks_body" | grep -q '"version":{' \
           && echo "$ks_body" | grep -qE '"status":"(stable|beta|deprecated)"' \
           && echo "$ks_body" | grep -q '"rel":"self"'; then
            kid=$(echo "$ks_body" | grep -oE '"id":"v[^"]+"' | head -1 | cut -d'"' -f4)
            hit "OpenStack Keystone detected: ${url} — id=${kid:-?}"
        fi
        throttle_sleep

        # --- 16. Gerrit ---
        # /config/server/version returns the version. Gerrit prefixes every
        # JSON response with the literal XSSI guard `)]}'` followed by newline.
        # Two-evidence: that prefix must be present AND the body must contain a
        # quoted version-like string. The XSSI prefix is unique to Gerrit's
        # REST-style endpoints — no other product ships it.
        ger_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/config/server/version" 2>/dev/null)
        if echo "$ger_body" | head -c 5 | grep -q ")]}'" \
           && echo "$ger_body" | grep -qE '"[0-9]+\.[0-9]+(\.[0-9]+)?(-[A-Za-z0-9.-]+)?"'; then
            ger_ver=$(echo "$ger_body" | grep -oE '"[0-9]+\.[0-9]+(\.[0-9]+)?[A-Za-z0-9.-]*"' | head -1 | tr -d '"')
            hit "Source/CI Gerrit detected: ${url} — version=${ger_ver:-?}"
        fi
        throttle_sleep

        # --- 17. Atlassian Confluence ---
        # Two routes: header X-Confluence-Request-Time on /; OR /server-info.action
        # returning <version>X.Y.Z</version>.
        conf_root_hdr="$OUT/prod_confluence_root_hdr_${safe}.txt"
        conf_root_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            -D "$conf_root_hdr" \
            "${url}/" 2>/dev/null)
        conf_is=0
        if grep -qiE '^x-confluence-request-time:' "$conf_root_hdr" 2>/dev/null \
           && echo "$conf_root_body" | grep -qi "Confluence"; then
            conf_is=1
        fi
        conf_ver=""
        if [ "$conf_is" = 0 ]; then
            conf_si_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
                --connect-timeout 4 --max-time 8 \
                "${url}/server-info.action" 2>/dev/null)
            if echo "$conf_si_body" | grep -qE '<version>[0-9]+\.[0-9]+'; then
                conf_is=1
                conf_ver=$(echo "$conf_si_body" | grep -oE '<version>[^<]+' | head -1 | sed 's/<version>//')
            fi
        fi
        if [ "$conf_is" = 1 ]; then
            hit "Source/CI Atlassian Confluence detected: ${url} — version=${conf_ver:-?}"
        fi
        throttle_sleep

        # --- 18. Atlassian Jira ---
        # /rest/api/2/serverInfo is unauth on most Jira installs by design.
        # Two-evidence: response must contain ALL THREE of "baseUrl":, "versionNumbers":, "deploymentType":
        # The closed schema is unique to Jira's serverInfo endpoint.
        jira_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/rest/api/2/serverInfo" 2>/dev/null)
        if echo "$jira_body" | grep -q '"baseUrl":' \
           && echo "$jira_body" | grep -q '"versionNumbers":' \
           && echo "$jira_body" | grep -q '"deploymentType":'; then
            jira_ver=$(echo "$jira_body" | grep -oE '"version":"[^"]+"' | head -1 | cut -d'"' -f4)
            hit "Source/CI Atlassian Jira detected: ${url} — version=${jira_ver:-?}"
            hit "UNAUTH: Jira serverInfo exposed: ${url}"
        fi
        throttle_sleep

        # --- 19. Atlassian Bamboo ---
        # /rest/api/latest/info returns XML or JSON depending on Accept header.
        # Two-evidence: response contains literal "Bamboo" AND either
        # <version>X.Y.Z</version> OR "version":"X.Y.Z" AND
        # <buildDate> OR "buildDate":
        bam_body=$(curl -ks -A "$(curl_ua)" $(curl_proxy_arg) \
            --connect-timeout 4 --max-time 8 \
            "${url}/rest/api/latest/info" 2>/dev/null)
        if echo "$bam_body" | grep -q "Bamboo" \
           && (echo "$bam_body" | grep -qE '<version>[0-9]+\.[0-9]+' \
               || echo "$bam_body" | grep -qE '"version":"[0-9]+\.[0-9]+') \
           && (echo "$bam_body" | grep -q '<buildDate>' \
               || echo "$bam_body" | grep -q '"buildDate":'); then
            bam_ver=$(echo "$bam_body" | grep -oE '<version>[^<]+|"version":"[^"]+' | head -1 | sed 's/<version>//;s/"version":"//')
            hit "Source/CI Atlassian Bamboo detected: ${url} — version=${bam_ver:-?}"
        fi
        throttle_sleep

    done < "$LIVE_URLS"
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
