#!/usr/bin/env bash
# enum-vault.sh — HashiCorp Vault enumeration.
#
# Vault API port 8200 (primary), 8201 (cluster replication).
# The /v1/sys/seal-status and /v1/sys/health endpoints are unauthenticated
# and leak version, cluster name, and seal state even on fully-locked vaults.
# An uninitialized Vault is a critical finding — the first caller to
# /v1/sys/init owns the root keys.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "vault: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — vault dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # Try both http and https — operators sometimes terminate TLS upstream
    for scheme in http https; do
        base="${scheme}://${ip}:${port}"

        # ---------- seal-status ----------
        curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
            "$base/v1/sys/seal-status" \
            > "$OUT/$ip/seal_${scheme}_${port}.txt" 2>&1 || true

        if grep -q '"sealed"' "$OUT/$ip/seal_${scheme}_${port}.txt" 2>/dev/null; then
            sealed=$(grep -oE '"sealed"\s*:\s*(true|false)' \
                "$OUT/$ip/seal_${scheme}_${port}.txt" | head -1 \
                | grep -oE 'true|false')
            version=$(grep -oE '"version"\s*:\s*"[^"]*"' \
                "$OUT/$ip/seal_${scheme}_${port}.txt" | head -1 \
                | grep -oE '"[^"]*"$' | tr -d '"')
            cluster=$(grep -oE '"cluster_name"\s*:\s*"[^"]*"' \
                "$OUT/$ip/seal_${scheme}_${port}.txt" | head -1 \
                | grep -oE '"[^"]*"$' | tr -d '"')
            hit "Vault reachable ($scheme): $ip:$port — sealed=${sealed} version=${version} cluster=${cluster}"
        fi

        # ---------- health ----------
        curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
            "$base/v1/sys/health" \
            > "$OUT/$ip/health_${scheme}_${port}.txt" 2>&1 || true

        # ---------- init state ----------
        curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
            "$base/v1/sys/init" \
            > "$OUT/$ip/init_${scheme}_${port}.txt" 2>&1 || true

        if grep -q '"initialized"\s*:\s*false' \
            "$OUT/$ip/init_${scheme}_${port}.txt" 2>/dev/null; then
            hit "Vault NOT INITIALIZED (claim-init opportunity): $ip:$port"
        fi

    done

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Vault follow-ups:
  * Uninitialized Vault: the first caller to POST /v1/sys/init owns the
    root unseal keys. If reached during an engagement, STOP and report
    immediately — do not initialize without explicit written authorization.
  * Sealed Vault still leaks version + cluster topology via /v1/sys/seal-status.
  * List enabled secret engines (requires auth token):
      curl -H "X-Vault-Token: <token>" http://<ip>:8200/v1/sys/mounts
  * Common token sources: VAULT_TOKEN env, ~/.vault-token, k8s service account JWT.
  * Enumerate available auth methods:
      curl http://<ip>:8200/v1/sys/auth
  * Check KV secret list (requires read policy):
      curl -H "X-Vault-Token: <token>" http://<ip>:8200/v1/<path>?list=true
EOF

log "vault dispatcher done."
