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
    nmap -Pn $(nmap_bound_args) -p1433 --script 'ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-mssql" >/dev/null 2>&1 || true
fi

# UDP 1434 SQL Server Browser — reveals named/dynamic-port instances that a
# 1433-only TCP scan silently misses. A single 0x03 datagram returns a
# ;-delimited ServerName;InstanceName;...;tcp;<port> map. Stdlib socket (python3
# is a required dep), so no nmap NSE dependency.
BROWSER_PORTS=""
if have python3; then
    for ip in $IPS; do
        [ -z "$ip" ] && continue
        resp=$(python3 - "$ip" <<'PY'
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"\x03", (sys.argv[1], 1434))
    data, _ = s.recvfrom(4096)
    sys.stdout.write(data[3:].decode("ascii", "replace"))
except Exception:
    pass
PY
)
        [ -z "$resp" ] && continue
        mkdir -p "$OUT/$ip"
        printf '%s\n' "$resp" > "$OUT/$ip/_sqlbrowser_1434.txt"
        log "  SQL Browser (UDP 1434) responded on $ip — named/dynamic instances present"
        echo "MSSQL SQL Browser (UDP 1434) instances on $ip: $(printf '%s' "$resp" | tr ';' ' ')" >> "$OUT/_hints.txt"
        ports=$(printf '%s' "$resp" | grep -oE 'tcp;[0-9]+' | grep -oE '[0-9]+$' | sort -u)
        for p in $ports; do
            [ "$p" = "1433" ] && continue
            BROWSER_PORTS="$BROWSER_PORTS $ip:$p"
        done
    done
fi
# Probe any dynamic instance ports the browser advertised.
if [ -n "$BROWSER_PORTS" ] && have nmap; then
    for hp in $BROWSER_PORTS; do
        ipx=${hp%:*}; px=${hp#*:}
        mkdir -p "$OUT/$ipx"
        log "  nmap ms-sql-info on discovered instance $ipx:$px"
        nmap -Pn $(nmap_bound_args) -p"$px" --script 'ms-sql-info,ms-sql-ntlm-info' \
             "$ipx" -oN "$OUT/$ipx/nmap-mssql-instance-$px.txt" >/dev/null 2>&1 || true
    done
fi

# nxc mssql
if (have nxc || have netexec); then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc mssql (cred check + windows-auth + local-auth attempts)"
    echo "$IPS" | "$NXC" mssql - "${NXC_ARGS[@]}" \
        > "$OUT/nxc_mssql.txt" 2>&1 || true

    if [ -n "${ENUM_USER:-}" ]; then
        log "nxc mssql -q 'SELECT @@VERSION'"
        echo "$IPS" | "$NXC" mssql - "${NXC_ARGS[@]}" \
            -q 'SELECT @@VERSION; SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER(''sysadmin'');' \
            > "$OUT/nxc_mssql_query.txt" 2>&1 || true
        log "nxc mssql --xp_cmdshell (DO NOT run on prod — only labs/auth)"
        echo "$IPS" | "$NXC" mssql - "${NXC_ARGS[@]}" \
            -x 'whoami' > "$OUT/nxc_mssql_cmd.txt" 2>&1 || true
    fi
fi

# Impacket mssqlclient.py manual hint
if have mssqlclient.py; then
    echo "Hint: mssqlclient.py -windows-auth ${ENUM_DOMAIN:-DOMAIN}/${ENUM_USER:-USER}:${ENUM_PASS:-PASS}@<ip>" >> "$OUT/_hints.txt"
fi

log "mssql dispatcher done."
