#!/usr/bin/env bash
# enum-sip.sh — SIP (Session Initiation Protocol) enumeration (ports 5060, 5061).
#
# SIP is overwhelmingly UDP on port 5060; port 5061 is SIPS (TLS). Asterisk,
# FreePBX, Cisco CUCM, Avaya, and Polycom all expose SIP. Extension enumeration
# via REGISTER/OPTIONS and credential spray against 4-digit extensions are the
# primary attack paths.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "sip: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — sip dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- nmap SIP scripts (UDP + TCP — SIP runs on both) ----------
    nmap -sU -sT -p "$port" \
        --script sip-methods,sip-enum-users \
        --script-timeout 60 \
        $(throttle_nmap_args) \
        "$ip" -oN "$OUT/$ip/sip_${port}.txt" 2>/dev/null || true

    # ---------- vendor fingerprint from Server / User-Agent lines ----------
    vendor=""
    if [ -s "$OUT/$ip/sip_${port}.txt" ]; then
        if grep -qiE 'Server:.*Asterisk|User-Agent:.*Asterisk' "$OUT/$ip/sip_${port}.txt"; then
            vendor="Asterisk"
        elif grep -qiE 'Server:.*FreePBX|User-Agent:.*FreePBX' "$OUT/$ip/sip_${port}.txt"; then
            vendor="FreePBX"
        elif grep -qiE 'Server:.*CUCM|Cisco.*Unified|User-Agent:.*Cisco' "$OUT/$ip/sip_${port}.txt"; then
            vendor="Cisco CUCM"
        elif grep -qiE 'Server:.*Avaya|User-Agent:.*Avaya' "$OUT/$ip/sip_${port}.txt"; then
            vendor="Avaya"
        elif grep -qiE 'Server:.*Polycom|User-Agent:.*Polycom' "$OUT/$ip/sip_${port}.txt"; then
            vendor="Polycom"
        fi
    fi

    if [ -n "$vendor" ]; then
        hit "SIP service: $ip:$port — $vendor"
    elif grep -qiE '(sip-methods|SIP/)' "$OUT/$ip/sip_${port}.txt" 2>/dev/null; then
        hit "SIP service: $ip:$port — unknown vendor"
    fi

    # ---------- optional svmap (SIPVicious) ----------
    if have svmap; then
        timeout 30 svmap "$ip" \
            > "$OUT/$ip/svmap_${port}.txt" 2>&1 || true
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
SIP follow-ups:
  * Extension brute (4-digit range) with SIPVicious:
    svwar -e100-9999 -m REGISTER <ip>
  * SIPVicious user enum:
    svmap <ip>   (identify SIP servers on subnet)
    svwar -e100-9999 <ip>   (extension enum)
    svcrack -u <ext> -d /usr/share/wordlists/rockyou.txt <ip>  (cred spray — requires auth)
  * Asterisk default credentials: admin/admin, 1000/1000 (extension/password)
  * FreePBX web admin default: admin/admin (on HTTP/443 — cross-reference http targets)
  * Cisco CUCM web admin: typically on 8443/tcp — check https targets
  * Check for SIP NOTIFY / INVITE injection (unauth call injection to extensions)
  * SIP over TLS (5061): check cert validity via openssl s_client -connect <ip>:5061
  * SIP without TLS = cleartext credentials — flag all USER / PASS exchanges
EOF

log "sip dispatcher done."
