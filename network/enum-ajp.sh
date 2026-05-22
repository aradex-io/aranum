#!/usr/bin/env bash
# enum-ajp.sh — AJP / Tomcat enumeration (port 8009).
#
# AJP (Apache JServ Protocol) is a binary wire protocol between a front-end
# proxy (Apache httpd, nginx via mod_proxy_ajp) and a backend Tomcat instance.
# Default Tomcat 7.x / 8.x / 9.x bind AJP on 0.0.0.0 — reachable from outside
# without explicit allowance. Combined with a writable upload path this is
# unauthenticated RCE (Ghostcat CVE-2020-1938).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "ajp: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — ajp dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- nmap AJP scripts ----------
    nmap -sT -p "$port" \
        --script ajp-headers,ajp-methods,ajp-auth,ajp-brute \
        --script-timeout 30 \
        $(throttle_nmap_args) \
        "$ip" -oN "$OUT/$ip/ajp_${port}.txt" 2>/dev/null || true

    # ---------- detect Tomcat presence ----------
    if grep -qi 'Tomcat' "$OUT/$ip/ajp_${port}.txt" 2>/dev/null; then
        hit "AJP/Tomcat detected: $ip:$port"
    fi

    # ---------- auth check ----------
    if grep -qi 'ajp-auth.*Authentication: Required' "$OUT/$ip/ajp_${port}.txt" 2>/dev/null; then
        # Auth is required — note it but no unauth finding
        miss "AJP auth required: $ip:$port"
    else
        # No auth required line — treat as unauthenticated AJP
        if grep -qi 'AJP' "$OUT/$ip/ajp_${port}.txt" 2>/dev/null || \
           grep -qi 'ajp-headers' "$OUT/$ip/ajp_${port}.txt" 2>/dev/null; then
            hit "UNAUTH: $ip:$port AJP responding without auth"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
AJP follow-ups:
  * CVE-2020-1938 (Ghostcat) file-read / upload-then-include RCE PoC lives in
    https://github.com/00theway/Ghostcat-CNVD-2020-10487 — RUN ONLY AGAINST
    AUTHORIZED TARGETS. There is no first-party nmap NSE for the file-read,
    only the broker enumeration scripts run above.
  * Tomcat config that exposes AJP on 0.0.0.0 (default in 7.x/8.x/9.x pre-fix)
    plus a writable upload path = unauthenticated RCE.
  * Check for connector requireSecret=true (Tomcat 9.0.31+ / 8.5.51+) — absent
    on older installs means any client can connect without a shared secret.
  * Pair with enum-http.sh output: Tomcat manager at /manager/html is a common
    RCE path via WAR upload once AJP confirms the backend server product.
EOF

log "ajp dispatcher done."
