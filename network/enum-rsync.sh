#!/usr/bin/env bash
# enum-rsync.sh — rsync daemon enumeration (port 873).
#
# rsync daemons with no auth export module listings to unauthenticated clients.
# Modules named etc, home, root, backup, var, srv, www frequently contain
# sensitive data (SSH keys, passwd files, web configs, database dumps).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "rsync: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have rsync; then
    miss "rsync not installed — rsync dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- list modules (unauthenticated) ----------
    timeout 10 rsync --port="$port" "rsync://$ip/" \
        > "$OUT/$ip/modules_${port}.txt" 2>&1 || true

    # Check for non-empty output that isn't an error line
    module_count=0
    modules_found=""
    if [ -s "$OUT/$ip/modules_${port}.txt" ]; then
        # Filter out lines starting with @ (error) or rsync: (error) or empty
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            # Skip error lines
            echo "$line" | grep -qE '^(@|rsync:)' && continue
            # First whitespace-separated token is the module name
            mod=$(echo "$line" | awk '{print $1}')
            [ -z "$mod" ] && continue
            module_count=$((module_count + 1))
            if [ -z "$modules_found" ]; then
                modules_found="$mod"
            else
                modules_found="$modules_found,$mod"
            fi
        done < "$OUT/$ip/modules_${port}.txt"
    fi

    if [ "$module_count" -gt 0 ]; then
        hit "UNAUTH: rsync unauthenticated modules: $ip:$port — $modules_found"
    fi

    # ---------- per-module listing (up to 10 modules) ----------
    listed=0
    if [ -s "$OUT/$ip/modules_${port}.txt" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            echo "$line" | grep -qE '^(@|rsync:)' && continue
            mod=$(echo "$line" | awk '{print $1}')
            [ -z "$mod" ] && continue
            [ "$listed" -ge 10 ] && break

            timeout 10 rsync --port="$port" "rsync://$ip/$mod/" \
                > "$OUT/$ip/${mod}_listing_${port}.txt" 2>&1 || true
            listed=$((listed + 1))

            # ---------- high-value module check ----------
            if echo "$mod" | grep -qE '^(etc|home|root|backup|var|srv|www)$'; then
                hit "rsync HIGH-VALUE module exposed anonymously: $ip:$port::$mod"
            fi
        done < "$OUT/$ip/modules_${port}.txt"
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
rsync follow-ups:
  * Pull a file: rsync rsync://<ip>/<module>/path/to/file ./local/
  * Pull a tree: rsync -av rsync://<ip>/<module>/ ./local/tree/
  * Check for secrets = or auth users = directives in rsyncd.conf
    (server-side, but often exposed via the etc or root module itself).
  * High-value paths: /etc/passwd, /etc/shadow, /root/.ssh/,
    /home/*/.ssh/authorized_keys, /var/www/ config files, /backup/.
  * rsync module source: /etc/rsyncd.conf — check path = entries
    to understand what filesystem path each module maps to.
EOF

log "rsync dispatcher done."
