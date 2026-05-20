#!/usr/bin/env bash
# enum-kerberos.sh — Kerberos enumeration (user enum via 88/UDP, kerbrute).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "kerberos: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

if [ -z "${ENUM_DOMAIN:-}" ]; then
    miss "kerberos enum needs --domain"
    exit 0
fi

# ---------- 1. kerbrute userenum ----------
if have kerbrute; then
    if [ -f "$OUT/../_users.lst" ]; then
        USERLIST="$OUT/../_users.lst"
    else
        USERLIST="/usr/share/seclists/Usernames/jsmith.txt"
    fi
    if [ -r "$USERLIST" ]; then
        for ip in $IPS; do
            log "kerbrute userenum on $ip ($USERLIST)"
            kerbrute userenum --dc "$ip" -d "$ENUM_DOMAIN" "$USERLIST" \
                > "$OUT/kerbrute_${ip}.txt" 2>&1 || true
        done
    else
        miss "no userlist (place at $OUT/../_users.lst or install seclists)"
    fi
else
    miss "kerbrute not installed (https://github.com/ropnop/kerbrute)"
fi

# ---------- 2. nmap krb5-enum-users ----------
if have nmap; then
    log "nmap krb5-enum-users"
    USERS_ARG=""
    if [ -f "$OUT/../_users.lst" ]; then
        USERS_ARG="--script-args krb5-enum-users.realm=$ENUM_DOMAIN,userdb=$OUT/../_users.lst"
    fi
    # shellcheck disable=SC2086
    nmap -Pn -p88 --script krb5-enum-users $USERS_ARG -iL <(echo "$IPS") \
        -oA "$OUT/nmap-krb-enum" >/dev/null 2>&1 || true
fi

# ---------- 3. SPN roast / AS-REP (delegated to ldap dispatcher results) ----------
log "kerberos dispatcher done. (SPN/AS-REP also handled by enum-ldap.sh)"
