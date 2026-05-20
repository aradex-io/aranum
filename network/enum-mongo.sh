#!/usr/bin/env bash
# enum-mongo.sh — MongoDB enumeration.
#
# Common finding: pre-3.6 MongoDBs bound to 0.0.0.0 with no auth.
# Even modern installs sometimes ship --noauth in lab containers
# that leaked to production.
#
# Phases:
#   1. nmap mongodb-* NSE
#   2. mongosh (preferred) or mongo client unauth probe
#   3. If unauth: dump database list + per-db collection counts
#   4. If creds present: auth recon (users, roles)
#
# READ-ONLY. No drop/insert/update.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "mongo: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# Detect mongosh (modern) vs legacy mongo client
MONGO_CMD=""
for cand in mongosh mongo; do
    have "$cand" && { MONGO_CMD="$cand"; break; }
done

# ---------- 1. nmap NSE ----------
if have nmap; then
    log "nmap mongodb-info + mongodb-databases"
    nmap -Pn -p27017 --script 'mongodb-info,mongodb-databases' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-mongo" >/dev/null 2>&1 || true
fi

# ---------- 2+3. unauth probe + dump ----------
if [ -n "$MONGO_CMD" ]; then
    log "$MONGO_CMD unauth probe + database/collection enumeration"
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        # Connection string — IPv6 needs brackets per MongoDB URI spec
        host_ref="$ip"
        [[ "$ip" == *:* ]] && host_ref="[$ip]"
        uri="mongodb://${host_ref}:${port}/"

        # Server info
        timeout 8 "$MONGO_CMD" "$uri" --quiet --eval \
            "JSON.stringify(db.adminCommand({serverStatus:1, asserts:0}), null, 2)" \
            > "$OUT/$ip/serverStatus_${port}.txt" 2>&1 || true

        # Database list — works only if anon listDatabases is allowed
        timeout 8 "$MONGO_CMD" "$uri" --quiet --eval \
            "JSON.stringify(db.adminCommand({listDatabases:1}), null, 2)" \
            > "$OUT/$ip/listDatabases_${port}.txt" 2>&1 || true

        if grep -q '"databases"' "$OUT/$ip/listDatabases_${port}.txt" 2>/dev/null \
           && ! grep -qi 'requires authentication\|not authorized' "$OUT/$ip/listDatabases_${port}.txt" 2>/dev/null; then
            hit "UNAUTH: $ip:$port allows listDatabases without credentials"
            # Per-db collection enum (limit to first 10 dbs and 50 collections each)
            dbs=$(python3 -c "
import json, sys
try:
    d = json.load(open('$OUT/$ip/listDatabases_${port}.txt'))
    for x in (d.get('databases') or [])[:10]:
        print(x['name'])
except Exception as e: pass
" 2>/dev/null)
            for db in $dbs; do
                [[ "$db" =~ ^(admin|local|config)$ ]] && continue
                timeout 6 "$MONGO_CMD" "${uri}${db}" --quiet --eval \
                    "db.getCollectionNames().slice(0,50).forEach(function(c){ print(c + ': ' + db.getCollection(c).estimatedDocumentCount()); });" \
                    > "$OUT/$ip/db_${db}_${port}.txt" 2>&1 || true
            done
        fi
    done < "$TARGETS"
else
    miss "neither mongosh nor mongo client installed — skipping unauth probe"
fi

# ---------- 4. authenticated recon ----------
if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && [ -n "$MONGO_CMD" ]; then
    log "$MONGO_CMD authenticated recon"
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        host_ref="$ip"
        [[ "$ip" == *:* ]] && host_ref="[$ip]"
        # URL-encode user/pass crudely (Python urllib.parse.quote)
        enc_user=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ENUM_USER")
        enc_pass=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ENUM_PASS")
        uri="mongodb://${enc_user}:${enc_pass}@${host_ref}:${port}/admin"
        timeout 10 "$MONGO_CMD" "$uri" --quiet --eval \
            "JSON.stringify({usersInfo: db.adminCommand({usersInfo: 1}), rolesInfo: db.adminCommand({rolesInfo: 1})}, null, 2)" \
            > "$OUT/$ip/auth_users_roles_${port}.txt" 2>&1 || true
    done < "$TARGETS"
fi

cat > "$OUT/_hints.txt" <<'EOF'
MongoDB hints:
  * Unauth listDatabases on a prod host == data exfil opportunity. Triage by
    collection size; user/credentials/secrets/orders/payments are the typical
    high-value names.
  * If --enableLocalhostAuthBypass left on, an attacker with 127.0.0.1 SSRF
    can do db.createUser({user:'x', pwd:'y', roles:[{role:'root',db:'admin'}]}).
  * Server-side JavaScript (deprecated post-4.4) may permit $where injection
    in apps that take user input — separate audit.
EOF

log "mongo dispatcher done."
