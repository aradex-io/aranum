#!/usr/bin/env bash
# enum-platform.sh — Kubernetes-adjacent and workload platform control planes.
#
# Read-side only. Covers Nomad, Portainer, Rancher, and Argo CD fingerprints.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "platform: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

if ! have curl; then
    miss "curl not installed — platform dispatcher cannot probe"
    exit 0
fi

url_host() {
    local ip="$1"
    if [[ "$ip" == *:* ]]; then printf '[%s]' "$ip"; else printf '%s' "$ip"; fi
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    host=$(url_host "$ip")
    mkdir -p "$OUT/$ip"

    schemes=("http")
    case "$port" in
        443|8443|9443) schemes=("https") ;;
        *) schemes=("http" "https") ;;
    esac

    for scheme in "${schemes[@]}"; do
        base="${scheme}://${host}:${port}"
        safe="${scheme}_${port}"

        nomad="$OUT/$ip/nomad_${safe}.json"
        curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
            "$base/v1/status/leader" > "$nomad" 2>&1 || true
        if grep -qE '^"[^"]+:[0-9]+"$' "$nomad" 2>/dev/null; then
            hit "Platform HashiCorp Nomad detected: $base"
            jobs="$OUT/$ip/nomad_jobs_${safe}.json"
            curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
                "$base/v1/jobs" > "$jobs" 2>&1 || true
            if grep -q '"ID"' "$jobs" 2>/dev/null; then
                hit "Platform Nomad UNAUTH job inventory: $base"
            fi
        fi

        portainer="$OUT/$ip/portainer_${safe}.json"
        curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
            "$base/api/status" > "$portainer" 2>&1 || true
        if grep -q '"Version"' "$portainer" 2>/dev/null \
           && grep -q '"InstanceID"' "$portainer" 2>/dev/null; then
            version=$(grep -oE '"Version"[[:space:]]*:[[:space:]]*"[^"]+"' "$portainer" | head -1 | cut -d'"' -f4)
            hit "Platform Portainer detected: $base — version=${version:-?}"
        fi

        rancher="$OUT/$ip/rancher_${safe}.json"
        curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
            "$base/v3/settings/server-version" > "$rancher" 2>&1 || true
        if grep -q '"name"[[:space:]]*:[[:space:]]*"server-version"' "$rancher" 2>/dev/null \
           && grep -q '"value"' "$rancher" 2>/dev/null; then
            version=$(grep -oE '"value"[[:space:]]*:[[:space:]]*"[^"]+"' "$rancher" | head -1 | cut -d'"' -f4)
            hit "Platform Rancher detected: $base — version=${version:-?}"
        fi

        argocd_hdr="$OUT/$ip/argocd_${safe}.headers"
        argocd_body="$OUT/$ip/argocd_${safe}.body"
        curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
            -D "$argocd_hdr" "$base/api/version" > "$argocd_body" 2>&1 || true
        if grep -q '"Version"' "$argocd_body" 2>/dev/null \
           && grep -q '"GitCommit"' "$argocd_body" 2>/dev/null; then
            version=$(grep -oE '"Version"[[:space:]]*:[[:space:]]*"[^"]+"' "$argocd_body" | head -1 | cut -d'"' -f4)
            hit "Platform Argo CD detected: $base — version=${version:-?}"
        elif grep -qi 'argocd' "$argocd_hdr" "$argocd_body" 2>/dev/null; then
            hit "Platform Argo CD detected: $base"
        fi
    done

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Platform follow-ups:
  * Nomad: unauth /v1/jobs exposes workloads, namespaces, image names, env, and
    placement metadata. Do not submit jobs from this dispatcher.
  * Portainer / Rancher / Argo CD: review auth mode, SSO, cluster inventory,
    project/app visibility, and any anonymous API exposure.
  * These systems usually bridge directly to Kubernetes, Docker, or runtime
    credentials. Prioritize them above generic web findings.
EOF

log "platform dispatcher done."
