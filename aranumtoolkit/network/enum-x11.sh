#!/usr/bin/env bash
# enum-x11.sh — X11 (6000-6009) open-display check.
# READ-ONLY: nmap x11-access probes whether the X server accepts unauth clients
# (screenshot/keylog surface). No screenshotting here — access check only.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "x11: $(wc -l < "$TARGETS") targets -> $OUT"
have nmap || { miss "nmap not installed — x11 dispatcher cannot probe"; exit 0; }
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; mkdir -p "$OUT/$ip"
    out="$OUT/$ip/x11_${port}.txt"
    timeout 25 nmap -Pn "${THROTTLE_NMAP_ARGS[@]}" -p "$port" --script x11-access --script-timeout 15s -oN "$out" "$ip" >/dev/null 2>&1 || true
    if grep -qi 'X server access is granted' "$out" 2>/dev/null; then
        disp=$((port - 6000))
        crit "X11 OPEN DISPLAY: $ip:$port (:$disp) — unauth access (screenshot/keylog)"
    fi
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

X11 follow-ups:
  * Confirm: xdpyinfo -display <ip>:<N>. Capture: xwd -root -display <ip>:<N> |
    xwud, or import -display <ip>:<N> -window root shot.png. Keylog: xspy/xwatchwin.
EOF
log "x11 dispatcher done."
