#!/usr/bin/env bash
# enum-finger.sh — finger (79) user enumeration.
# READ-ONLY: query the finger daemon for logged-in / arbitrary users.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "finger: $(wc -l < "$TARGETS") targets -> $OUT"
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; mkdir -p "$OUT/$ip"
    out="$OUT/$ip/finger_${port}.txt"
    # empty query lists logged-in users; then probe a few common accounts
    { printf '\r\n'; } | timeout 8 nc -w5 "$ip" "$port" > "$out" 2>&1 || true
    for u in root admin test user guest; do
        printf '%s\r\n' "$u" | timeout 6 nc -w4 "$ip" "$port" >> "$out" 2>&1 || true
    done
    if grep -qiE 'Login|Name|Directory|Never logged in|tty' "$out" 2>/dev/null; then
        hit "finger responds with user info: $ip:$port — username/host enumeration"
    fi
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

finger follow-ups:
  * `finger @<ip>` lists logged-in users; `finger user@<ip>` confirms accounts +
    leaks home dir / last-login / .plan. Feed valid names into SSH/SMTP spray lists.
EOF
log "finger dispatcher done."
