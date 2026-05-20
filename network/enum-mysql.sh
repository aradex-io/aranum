#!/usr/bin/env bash
# enum-mysql.sh — MySQL / MariaDB enumeration + cred check.
#
# Phases:
#   1. nmap mysql-* NSE scripts
#   2. Anonymous + root-no-pwd probes via `mysql` client
#   3. nxc mysql cred check (if creds present)
#   4. Authenticated recon — version, current_user, FILE priv check,
#      secure_file_priv inspection (governs INTO OUTFILE)
#
# READ-ONLY. No INSERT / UPDATE / DELETE / DROP.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "mysql: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# ---------- 1. nmap NSE ----------
if have nmap; then
    log "nmap mysql-info + mysql-empty-password + mysql-users"
    nmap -Pn -p3306 --script 'mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-mysql" >/dev/null 2>&1 || true
fi

# ---------- 2. anonymous + root-no-pwd probes ----------
if have mysql; then
    log "mysql client anon + root-no-pwd probes"
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        for user in "" root admin mysql; do
            out_file="$OUT/$ip/anon_${user:-empty}_${port}.txt"
            timeout 8 mysql -h "$ip" -P "$port" -u "${user:-}" --connect-timeout=5 \
                --batch --silent --raw -e "SELECT VERSION(), USER(), CURRENT_USER();" \
                > "$out_file" 2>&1 || true
            if grep -qE '^[0-9]+\.[0-9]+\.' "$out_file" 2>/dev/null; then
                hit "ANON AUTH: $ip:$port user=${user:-<empty>} (no password required)"
            fi
        done
    done < "$TARGETS"
else
    miss "mysql client not installed — skipping anon probes"
fi

# ---------- 3. nxc mysql + authenticated recon ----------
if (have nxc || have netexec); then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc mysql (cred check)"
    echo "$IPS" | "$NXC" mysql - "${NXC_ARGS[@]}" \
        > "$OUT/nxc_mysql.txt" 2>&1 || true

    if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && have mysql; then
        log "mysql authenticated recon (FILE priv + secure_file_priv)"
        while read -r target; do
            [ -z "$target" ] && continue
            read -r ip port <<< "$(split_ipport "$target")"
            mkdir -p "$OUT/$ip"
            timeout 10 mysql -h "$ip" -P "$port" -u "$ENUM_USER" --password="$ENUM_PASS" \
                --connect-timeout=5 --batch --silent --raw \
                -e "SELECT VERSION();
                    SELECT CURRENT_USER();
                    SELECT user, host, plugin FROM mysql.user;
                    SHOW VARIABLES LIKE 'secure_file_priv';
                    SHOW VARIABLES LIKE 'local_infile';
                    SHOW GRANTS;" \
                > "$OUT/$ip/auth_recon_${port}.txt" 2>&1 || true
        done < "$TARGETS"
    fi
fi

# ---------- 4. hints ----------
cat > "$OUT/_hints.txt" <<'EOF'
MySQL post-auth privilege escalation paths:
  * SELECT ... INTO OUTFILE '/path/file' — requires FILE priv AND
    secure_file_priv to be NULL or a writable webroot. Check auth_recon.
  * LOAD DATA LOCAL INFILE — server tells client to read a file (CVE-2019-12086
    territory if client side is mysql-connector with no validation).
  * UDF (user-defined function) RCE — requires INSERT into mysql.func and
    plugin_dir to be writable. Modern hardened defaults block this.
  * Read mysql.user password hashes (mysql_native_password) for offline crack.
Each requires specific GRANTs — review auth_recon.txt SHOW GRANTS output.
EOF

log "mysql dispatcher done."
