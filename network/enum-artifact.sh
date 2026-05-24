#!/usr/bin/env bash
# enum-artifact.sh — artifact/package/container registry discovery.
#
# Read-side probes only. Covers Docker Registry v2, Sonatype Nexus,
# JFrog Artifactory, and Harbor surfaces commonly found on 5000/8081/8082.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "artifact: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

if ! have curl; then
    miss "curl not installed — artifact dispatcher cannot probe"
    exit 0
fi

url_host() {
    local ip="$1"
    if [[ "$ip" == *:* ]]; then printf '[%s]' "$ip"; else printf '%s' "$ip"; fi
}

fetch() {
    local url="$1" hdr="$2" body="$3"
    curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
        -D "$hdr" "$url" > "$body" 2>&1 || true
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

        # Docker Registry v2: /v2/ returns 200 "{}" when open, or 401 with
        # Docker-Distribution-API-Version when auth-gated.
        fetch "$base/v2/" "$OUT/$ip/registry_${safe}.headers" "$OUT/$ip/registry_${safe}.body"
        if grep -qi '^docker-distribution-api-version:' "$OUT/$ip/registry_${safe}.headers" 2>/dev/null; then
            status=$(grep -m1 -oE '^HTTP/[0-9.]+ [0-9]+' "$OUT/$ip/registry_${safe}.headers" | awk '{print $2}')
            if [ "$status" = "200" ]; then
                hit "Artifact Docker Registry UNAUTH catalog surface: $base"
            else
                hit "Artifact Docker Registry detected: $base — status=${status:-?}"
            fi
        fi

        # Nexus 3: service/rest/v1/status returns JSON with version/edition,
        # and X-Siesta-FaultId is a Nexus REST fingerprint on failures.
        fetch "$base/service/rest/v1/status" "$OUT/$ip/nexus_${safe}.headers" "$OUT/$ip/nexus_${safe}.json"
        if grep -q '"version"' "$OUT/$ip/nexus_${safe}.json" 2>/dev/null \
           && grep -q '"edition"' "$OUT/$ip/nexus_${safe}.json" 2>/dev/null; then
            version=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$OUT/$ip/nexus_${safe}.json" | head -1 | cut -d'"' -f4)
            hit "Artifact Sonatype Nexus detected: $base — version=${version:-?}"
        fi

        # Artifactory: /artifactory/api/system/version is the stable read-only
        # endpoint on OSS/Pro installs.
        fetch "$base/artifactory/api/system/version" "$OUT/$ip/artifactory_${safe}.headers" "$OUT/$ip/artifactory_${safe}.json"
        if grep -q '"version"' "$OUT/$ip/artifactory_${safe}.json" 2>/dev/null \
           && grep -q '"revision"' "$OUT/$ip/artifactory_${safe}.json" 2>/dev/null; then
            version=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$OUT/$ip/artifactory_${safe}.json" | head -1 | cut -d'"' -f4)
            hit "Artifact JFrog Artifactory detected: $base — version=${version:-?}"
        fi

        # Harbor: /api/v2.0/systeminfo is intentionally public on many builds
        # and exposes version/auth mode.
        fetch "$base/api/v2.0/systeminfo" "$OUT/$ip/harbor_${safe}.headers" "$OUT/$ip/harbor_${safe}.json"
        if grep -q '"harbor_version"' "$OUT/$ip/harbor_${safe}.json" 2>/dev/null; then
            version=$(grep -oE '"harbor_version"[[:space:]]*:[[:space:]]*"[^"]+"' "$OUT/$ip/harbor_${safe}.json" | head -1 | cut -d'"' -f4)
            hit "Artifact Harbor registry detected: $base — version=${version:-?}"
        fi
    done

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Artifact / registry follow-ups:
  * Docker Registry: if /v2/_catalog is unauth, enumerate repositories and tags
    before any pull. Pulling images may be high-volume and should be scoped.
  * Nexus / Artifactory / Harbor: review anonymous browse, repository names,
    container image provenance, CI deploy tokens, and package metadata.
  * Treat writable package/registry access as supply-chain impact, not just
    data exposure.
EOF

log "artifact dispatcher done."
