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
    # rsync returns 0 only when the daemon greeting succeeded AND it sent a
    # module list. Any non-zero rc means: not an rsync service, auth required,
    # connection refused, or protocol failure — none of which is a finding.
    timeout 10 rsync --port="$port" "rsync://$ip/" \
        > "$OUT/$ip/modules_${port}.txt" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        miss "rsync protocol negotiation failed at $ip:$port (rc=$rc — not an rsync service or auth required)"
        throttle_sleep
        continue
    fi

    # rc=0 from here on: every non-empty line IS a module per rsync's contract
    module_count=0
    modules_found=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        mod=$(echo "$line" | awk '{print $1}')
        [ -z "$mod" ] && continue
        module_count=$((module_count + 1))
        if [ -z "$modules_found" ]; then
            modules_found="$mod"
        else
            modules_found="$modules_found,$mod"
        fi
    done < "$OUT/$ip/modules_${port}.txt"

    if [ "$module_count" -gt 0 ]; then
        hit "UNAUTH: rsync unauthenticated modules: $ip:$port — $modules_found"
    fi

    # ---------- per-module listing (up to 10 modules) ----------
    listed=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
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
