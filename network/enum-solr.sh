#!/usr/bin/env bash
# enum-solr.sh — Apache Solr enumeration.
#
# Solr admin API is unauthenticated by default in many deployments.
# Exposes search indexes, schema configs, replication endpoints.
#
# Known RCE CVEs (version-range detection only, no exploitation):
#   CVE-2019-17558 — VelocityResponseWriter RCE via params.resource.loader.enabled
#                    (Solr < 8.2.0 with Velocity plugin)
#   CVE-2023-50386 — ConfigSet backup/restore RCE
#                    (Solr < 8.11.4 or 9.0-9.4.0)

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "solr: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — solr dispatcher cannot probe"
    exit 0
fi

# Version comparison helper — returns 0 (true) if $1 < $2
version_lt() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] \
        && [ "$1" != "$2" ]
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- system info ----------
    curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
        "http://$ip:$port/solr/admin/info/system?wt=json" \
        > "$OUT/$ip/system_${port}.txt" 2>&1 || true

    version=""
    if grep -q '"solr-spec-version"' "$OUT/$ip/system_${port}.txt" 2>/dev/null; then
        version=$(grep -oE '"solr-spec-version"\s*:\s*"[^"]*"' \
            "$OUT/$ip/system_${port}.txt" | head -1 \
            | grep -oE '"[^"]*"$' | tr -d '"')
        hit "Solr reachable: $ip:$port — $version"
    fi

    # ---------- cores ----------
    curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
        "http://$ip:$port/solr/admin/cores?wt=json" \
        > "$OUT/$ip/cores_${port}.txt" 2>&1 || true

    if grep -q '"status"' "$OUT/$ip/cores_${port}.txt" 2>/dev/null; then
        core_count=$(grep -oE '"[a-zA-Z0-9_-]+"\s*:\s*\{' \
            "$OUT/$ip/cores_${port}.txt" | grep -v '"status"\|"initFailures"' \
            | wc -l | tr -d ' ')
        if [ "${core_count:-0}" -ge 1 ]; then
            hit "Solr cores exposed: $ip:$port — $core_count cores"
        fi
    fi

    # ---------- version-range CVE signals ----------
    if [ -n "$version" ]; then
        # CVE-2019-17558: Solr < 8.2.0
        if version_lt "$version" "8.2.0"; then
            err "Solr $version < 8.2.0 at $ip:$port — CVE-2019-17558 (VelocityResponseWriter RCE) candidate — verify params.resource.loader.enabled"
        fi

        # CVE-2023-50386: Solr < 8.11.4 OR (>= 9.0 AND < 9.4.1)
        major=$(echo "$version" | cut -d. -f1)
        if version_lt "$version" "8.11.4" && [ "$major" -le 8 ]; then
            err "Solr $version < 8.11.4 at $ip:$port — CVE-2023-50386 (ConfigSet RCE via backup/restore) candidate"
        elif [ "$major" -ge 9 ] && version_lt "$version" "9.4.1"; then
            err "Solr $version in 9.x < 9.4.1 at $ip:$port — CVE-2023-50386 (ConfigSet RCE via backup/restore) candidate"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Solr follow-ups:
  * List configsets:
      curl "http://<ip>:8983/solr/admin/configs?action=LIST&wt=json"
  * List replication endpoints:
      curl "http://<ip>:8983/solr/<core>/replication?command=details&wt=json"
  * CVE-2019-17558 (Velocity RCE, Solr < 8.2.0):
      Enable params.resource.loader.enabled via /solr/<core>/config then
      execute via VelocityResponseWriter. Do NOT run without --rce flag.
  * CVE-2023-50386 (ConfigSet backup/restore RCE, Solr < 8.11.4 / 9.x < 9.4.1):
      Upload malicious configset via /solr/admin/configs then trigger via
      /solr/admin/collections?action=RESTORE. Requires file upload capability.
  * Admin UI exposed at http://<ip>:8983/solr/ — check for schema browser,
    query interface, and JMX metrics endpoint.
EOF

log "solr dispatcher done."
