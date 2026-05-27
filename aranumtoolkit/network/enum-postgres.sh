#!/usr/bin/env bash
# enum-postgres.sh — PostgreSQL enumeration + cred check.
#
# Phases:
#   1. nmap pgsql-* NSE scripts (banner, empty-password)
#   2. trust-auth probe via `psql -U postgres` (no password)
#   3. nxc postgres cred check (if creds present)
#   4. authenticated reconnaissance (version, current_user, roles,
#      pg_read_server_files / COPY PROGRAM superuser-context hints)
#
# READ-ONLY. No SQL that modifies target state.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "postgres: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# ---------- 1. nmap NSE ----------
if have nmap; then
    log "nmap pgsql-info + pgsql-empty-password"
    nmap -Pn -p5432 --script 'pgsql-info,pgsql-empty-password,pgsql-brute' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-pgsql" >/dev/null 2>&1 || true
fi

# ---------- 2. trust-auth probe ----------
if have psql; then
    log "psql trust-auth probe (PGPASSWORD='')"
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        for user in postgres admin app; do
            PGPASSWORD='' PGCONNECT_TIMEOUT=5 \
                timeout 8 psql -h "$ip" -p "$port" -U "$user" -d postgres \
                -At -c "SELECT version();" \
                > "$OUT/$ip/trust_${user}_${port}.txt" 2>&1 || true
            if grep -qi 'PostgreSQL' "$OUT/$ip/trust_${user}_${port}.txt" 2>/dev/null; then
                hit "TRUST AUTH: $ip:$port user=$user (no password required)"
            fi
        done
    done < "$TARGETS"
else
    miss "psql not installed — skipping trust-auth probe"
fi

# ---------- 3. nxc postgres + authenticated recon ----------
if (have nxc || have netexec); then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc postgres (cred check)"
    echo "$IPS" | "$NXC" postgres - "${NXC_ARGS[@]}" \
        > "$OUT/nxc_postgres.txt" 2>&1 || true

    if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && have psql; then
        log "psql authenticated recon"
        while read -r target; do
            [ -z "$target" ] && continue
            read -r ip port <<< "$(split_ipport "$target")"
            mkdir -p "$OUT/$ip"
            PGPASSWORD="$ENUM_PASS" PGCONNECT_TIMEOUT=5 \
                timeout 10 psql -h "$ip" -p "$port" -U "$ENUM_USER" -d postgres -At \
                -c "SELECT version();" \
                -c "SELECT current_user, session_user;" \
                -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles;" \
                -c "SELECT datname FROM pg_database WHERE NOT datistemplate;" \
                > "$OUT/$ip/auth_recon_${port}.txt" 2>&1 || true
        done < "$TARGETS"
    fi
fi

# ---------- 4. hints ----------
cat > "$OUT/_hints.txt" <<'EOF'
Postgres post-auth privilege escalation:
  * Superuser context? -> COPY (SELECT '') TO PROGRAM 'id'  = arbitrary command exec
  * pg_read_server_files / pg_read_binary_file -> filesystem read as the postgres user
  * Untrusted languages (plpython3u, plperlu) installed? -> CREATE FUNCTION ... LANGUAGE plpython3u
  * Large objects (lo_import / lo_export) -> filesystem read/write
  * dblink + foreign-data-wrapper to pivot to other postgres instances
Each requires the auth context to be a superuser or have specific GRANTs — check
the auth_recon output's pg_roles dump first.
EOF

log "postgres dispatcher done."
