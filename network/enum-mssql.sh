#!/usr/bin/env bash
# enum-mssql.sh — MSSQL enumeration / cred check / xp_cmdshell test.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "mssql: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# nmap version + script
if have nmap; then
    log "nmap ms-sql-info + ms-sql-empty-password"
    nmap -Pn -p1433 --script 'ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-mssql" >/dev/null 2>&1 || true
fi

# nxc mssql
if (have nxc || have netexec); then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=""
    if [ -n "${ENUM_USER:-}" ]; then
        NXC_ARGS+=" -u $ENUM_USER"
        if [ -n "${ENUM_HASH:-}" ]; then NXC_ARGS+=" -H $ENUM_HASH"
        elif [ -n "${ENUM_PASS:-}" ]; then NXC_ARGS+=" -p $ENUM_PASS"; fi
        [ -n "${ENUM_DOMAIN:-}" ] && NXC_ARGS+=" -d $ENUM_DOMAIN"
    fi
    log "nxc mssql (cred check + windows-auth + local-auth attempts)"
    # shellcheck disable=SC2086
    echo "$IPS" | $NXC mssql - $NXC_ARGS \
        > "$OUT/nxc_mssql.txt" 2>&1 || true

    if [ -n "${ENUM_USER:-}" ]; then
        log "nxc mssql -q 'SELECT @@VERSION'"
        # shellcheck disable=SC2086
        echo "$IPS" | $NXC mssql - $NXC_ARGS \
            -q 'SELECT @@VERSION; SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER(''sysadmin'');' \
            > "$OUT/nxc_mssql_query.txt" 2>&1 || true
        log "nxc mssql --xp_cmdshell (DO NOT run on prod — only labs/auth)"
        # shellcheck disable=SC2086
        echo "$IPS" | $NXC mssql - $NXC_ARGS \
            -x 'whoami' > "$OUT/nxc_mssql_cmd.txt" 2>&1 || true
    fi
fi

# Impacket mssqlclient.py manual hint
if have mssqlclient.py; then
    echo "Hint: mssqlclient.py -windows-auth ${ENUM_DOMAIN:-DOMAIN}/${ENUM_USER:-USER}:${ENUM_PASS:-PASS}@<ip>" >> "$OUT/_hints.txt"
fi

log "mssql dispatcher done."
