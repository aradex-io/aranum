#!/usr/bin/env bash
# enum-vnc.sh — VNC enumeration.
#
# READ-ONLY: nmap NSE + raw banner.
# No vncviewer auto-connect. No password attempt without explicit ENUM_PASS.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "vnc: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

if have nmap; then
    log "nmap vnc-info + vnc-title + realvnc-auth-bypass"
    nmap -Pn -p5800,5900,5901,5902 \
         --script 'vnc-info,vnc-title,realvnc-auth-bypass' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-vnc" >/dev/null 2>&1 || true

    # realvnc-auth-bypass = CVE-2006-2369 — surface separately
    if [ -f "$OUT/nmap-vnc.nmap" ] && grep -q 'realvnc-auth-bypass' "$OUT/nmap-vnc.nmap"; then
        grep -B2 'realvnc-auth-bypass' "$OUT/nmap-vnc.nmap" > "$OUT/_realvnc_bypass.txt" || true
        if [ -s "$OUT/_realvnc_bypass.txt" ]; then
            err "CRITICAL: RealVNC auth bypass (CVE-2006-2369) detected — see _realvnc_bypass.txt"
        fi
    fi
fi

# Raw banner — VNC protocol version is first 12 bytes (e.g. "RFB 003.008\n")
if have nc; then
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        timeout 5 nc -nv -w 3 "$ip" "$port" </dev/null \
            > "$OUT/$ip/banner_${port}.txt" 2>&1 || true
    done < "$TARGETS"
fi

cat > "$OUT/_hints.txt" <<'EOF'
VNC follow-ups:
  * No-auth VNC (security type 1 in vnc-info) -> direct screen access via
    vncviewer <ip>::<port>. Capture screenshots before further interaction.
  * VNC password storage in ~/.vnc/passwd (VNC password obfuscation is a
    known-key DES; vncpwd / vncpasswd-decrypt cracks it offline).
  * Tunneled VNC (HTTP/5800) -> Java applet front-end; serve fingerprint.
EOF

log "vnc dispatcher done."
