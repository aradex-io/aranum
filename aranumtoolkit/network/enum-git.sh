#!/usr/bin/env bash
# enum-git.sh — git daemon (9418) anonymous repo access.
# READ-ONLY: `git ls-remote` / a raw upload-pack ref advertisement. Anonymous
# read = full source + secret history disclosure.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "git: $(wc -l < "$TARGETS") targets -> $OUT"
while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"; mkdir -p "$OUT/$ip"
    out="$OUT/$ip/git_${port}.txt"
    if have git; then
        GIT_TERMINAL_PROMPT=0 timeout 15 git ls-remote "git://$ip:$port/" > "$out" 2>&1 || true
        if [ -s "$out" ] && grep -qE '[0-9a-f]{40}' "$out"; then
            crit "UNAUTH git daemon: $ip:$port — anonymous repo listing (source/secret disclosure)"
        fi
    else
        # raw upload-pack ref advertisement (no git binary)
        printf '0032git-upload-pack /\x00host=%s\x00' "$ip" | timeout 10 nc -w5 "$ip" "$port" > "$out" 2>&1 || true
        grep -qE 'refs/|HEAD' "$out" 2>/dev/null && crit "UNAUTH git daemon: $ip:$port — ref advertisement returned"
    fi
    throttle_sleep
done < "$TARGETS"
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

git daemon follow-ups:
  * Clone anonymously: git clone git://<ip>/<repo>  then trufflehog/gitleaks the
    full history for secrets. Repo names come from the ls-remote path.
EOF
log "git dispatcher done."
