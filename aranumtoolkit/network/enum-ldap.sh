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
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc ldap (users, groups, asreproast, kerberoastable, machine-account quota)"
    echo "$IPS" | "$NXC" ldap - "${NXC_ARGS[@]}" \
        --users --groups --kerberoasting "$OUT/kerberoast.txt" \
        --asreproast "$OUT/asreproast.txt" \
        > "$OUT/nxc_ldap.txt" 2>&1 || true

    # bloodhound-ce collection
    if [ -n "${ENUM_USER:-}" ]; then
        log "nxc ldap --bloodhound (LDAP-only collection)"
        echo "$IPS" | "$NXC" ldap - "${NXC_ARGS[@]}" --bloodhound \
            --collection All --dns-server "${ENUM_DC_IP:-}" \
            > "$OUT/bloodhound.txt" 2>&1 || true
    fi
else
    miss "nxc/netexec not installed"
fi

# ---------- 2. ldapsearch (anonymous + auth) ----------
# IPv6 addresses must be bracketed in the ldap:// URL — see ldap_url() in _lib.sh.
if have ldapsearch; then
    log "ldapsearch (anon naming context + base info)"
    for ip in $IPS; do
        mkdir -p "$OUT/$ip"
        url=$(ldap_url "$ip")
        ldapsearch -x -H "$url" -s base -b '' '(objectclass=*)' \
            > "$OUT/$ip/ldap_rootDSE_anon.txt" 2>&1 || true

        if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ]; then
            BASE_DN=$(echo "$ENUM_DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":"")}')
            log "  $ip: enumerating users / computers / GPOs"
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(objectClass=user)' sAMAccountName description memberOf \
                > "$OUT/$ip/users.txt" 2>&1 || true
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(objectClass=computer)' dNSHostName operatingSystem \
                > "$OUT/$ip/computers.txt" 2>&1 || true
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(servicePrincipalName=*)' sAMAccountName servicePrincipalName \
                > "$OUT/$ip/spns.txt" 2>&1 || true
            # AS-REP roastables
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
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
    DC_FLAG=()
    [ -n "${ENUM_DC_IP:-}" ] && DC_FLAG=(-dc-ip "$ENUM_DC_IP")
    GetUserSPNs.py "${DC_FLAG[@]}" -request "$cred" \
        > "$OUT/impacket_spns.txt" 2>&1 || true
fi
if have GetNPUsers.py && [ -n "${ENUM_DOMAIN:-}" ]; then
    log "impacket GetNPUsers.py (AS-REP roast — no auth needed if user list)"
    DC_FLAG=()
    [ -n "${ENUM_DC_IP:-}" ] && DC_FLAG=(-dc-ip "$ENUM_DC_IP")
    if [ -f "$OUT/_users.lst" ]; then
        GetNPUsers.py "${DC_FLAG[@]}" "$ENUM_DOMAIN/" -usersfile "$OUT/_users.lst" -no-pass -format hashcat \
            > "$OUT/impacket_asrep.txt" 2>&1 || true
    fi
fi

# ---------- 4. BloodHound full collection (D1.2 — ADR-004 D1) ----------
# bloodhound-python is the actively-maintained Linux-attacker-side ingestor.
# We do NOT include the Session collection method by default — that requires
# admin reach on remote machines and produces too much noise on first run.
# Operator can opt into deeper collection by re-running manually with -c All.
if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ] && [ -n "${ENUM_DC_IP:-}" ]; then
    BHP=""
    have bloodhound-python && BHP="bloodhound-python"
    [ -z "$BHP" ] && have bloodhound.py && BHP="bloodhound.py"
    if [ -n "$BHP" ]; then
        log "$BHP — full graph collection (Default method — no Session)"
        BH_OUT="$OUT/$ENUM_DC_IP"
        mkdir -p "$BH_OUT"
        ( cd "$BH_OUT" && \
            "$BHP" -u "$ENUM_USER" -p "$ENUM_PASS" -d "$ENUM_DOMAIN" \
                   -ns "$ENUM_DC_IP" -c Default --zip \
                   > "$OUT/bloodhound_python.txt" 2>&1 ) || true
        # Surface the zip explicitly so report.py picks it up as HIGH-grade signal
        if ls "$BH_OUT"/*.zip >/dev/null 2>&1; then
            zip_name=$(ls -t "$BH_OUT"/*.zip 2>/dev/null | head -1)
            hit "BloodHound collection: $zip_name"
            echo "BLOODHOUND_ZIP: $zip_name" > "$OUT/_bloodhound_signal.txt"
        fi
    else
        log "[skip] bloodhound-python not installed — pipx install bloodhound-py (or bloodhound-python)"
    fi
fi

# ---------- 5. AD CS enumeration via Certipy (D1.2 — ADR-004 D2) ----------
# Certipy 'find' walks the CA + template config and identifies ESC1-11
# misconfigurations. JSON output enables clean classification in report.py.
if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ] && [ -n "${ENUM_DC_IP:-}" ]; then
    CERTIPY=""
    have certipy   && CERTIPY="certipy"
    [ -z "$CERTIPY" ] && have certipy-ad && CERTIPY="certipy-ad"
    if [ -n "$CERTIPY" ]; then
        log "$CERTIPY find — AD CS ESC1-11 enumeration"
        CERTIPY_OUT="$OUT/$ENUM_DC_IP"
        mkdir -p "$CERTIPY_OUT"
        ( cd "$CERTIPY_OUT" && \
            "$CERTIPY" find -u "$ENUM_USER@$ENUM_DOMAIN" -p "$ENUM_PASS" \
                      -dc-ip "$ENUM_DC_IP" -text -json \
                      -output certipy \
                      > "$OUT/certipy.txt" 2>&1 ) || true
        # Quick CRITICAL surface for any ESC* finding
        if ls "$CERTIPY_OUT/certipy_"*.txt >/dev/null 2>&1; then
            if grep -qE 'ESC[0-9]+' "$CERTIPY_OUT/certipy_"*.txt 2>/dev/null; then
                err "CRITICAL: Certipy found AD CS misconfiguration(s) — see $CERTIPY_OUT/certipy_*.txt"
            fi
        fi
    else
        log "[skip] certipy not installed — pipx install certipy-ad"
    fi
fi

# ---------- 6. Kerberos delegation enumeration (D1.2) ----------
# Constrained: TRUSTED_FOR_DELEGATION flag (UAC bit 524288)
# Unconstrained: TRUSTED_TO_AUTH_FOR_DELEGATION (16777216)
# RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity attribute populated
# Pre-D1, the operator had to run these queries by hand.
if have ldapsearch && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ]; then
    BASE_DN=$(echo "$ENUM_DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":"")}')
    for ip in $IPS; do
        mkdir -p "$OUT/$ip"
        url=$(ldap_url "$ip")
        log "  $ip: Kerberos delegation enum (unconstrained / constrained / RBCD)"
        {
            echo "=== UNCONSTRAINED DELEGATION (UAC bit 524288) — owners can impersonate any user authing TO them ==="
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(userAccountControl:1.2.840.113556.1.4.803:=524288)' \
                sAMAccountName dNSHostName servicePrincipalName 2>/dev/null
            echo
            echo "=== CONSTRAINED DELEGATION (msDS-AllowedToDelegateTo present) ==="
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(msDS-AllowedToDelegateTo=*)' \
                sAMAccountName msDS-AllowedToDelegateTo 2>/dev/null
            echo
            echo "=== RESOURCE-BASED CONSTRAINED DELEGATION (msDS-AllowedToActOnBehalfOfOtherIdentity present) ==="
            ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
                -b "$BASE_DN" '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
                sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity 2>/dev/null
        } > "$OUT/$ip/delegation.txt" 2>&1 || true
        # Surface counts
        unc=$(grep -c '^sAMAccountName: ' <(awk '/UNCONSTRAINED/,/CONSTRAINED DELEGATION/' "$OUT/$ip/delegation.txt") 2>/dev/null || echo 0)
        if [ "$unc" -gt 0 ]; then
            err "HIGH: $ip has $unc account(s) with UNCONSTRAINED DELEGATION — see $ip/delegation.txt"
        fi
    done
fi

# ---------- 7. Pre-2000 computer-account weak-password probe (D1.2) ----------
# Computer accounts created with "Pre-Windows 2000 compatible access" group
# often have their password set to the hostname-lowercase (no $ suffix). This
# is the classic "msDS-MachineAccountQuota + reused-password" finding.
# We can't try-auth-and-confirm from here (that's a write), but we CAN list
# computer accounts whose userAccountControl has WORKSTATION_TRUST_ACCOUNT
# (4096) set — those are the candidates.
if have ldapsearch && [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DOMAIN:-}" ]; then
    BASE_DN=$(echo "$ENUM_DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":"")}')
    for ip in $IPS; do
        url=$(ldap_url "$ip")
        log "  $ip: pre-2000 computer-account candidate listing"
        ldapsearch -x -H "$url" -D "$ENUM_USER@$ENUM_DOMAIN" -w "$ENUM_PASS" \
            -b "$BASE_DN" '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096))' \
            sAMAccountName whenCreated pwdLastSet \
            > "$OUT/$ip/pre2000_candidates.txt" 2>&1 || true
        # Hint at how to test (operator-gated; refuses to spray)
        {
            echo "# Pre-2000 weak-pw probe (operator-opt-in only — DO NOT spray without authz)"
            echo "# For each <HOSTNAME>\$ in pre2000_candidates.txt try:"
            echo "#   nxc smb $ip -u '<HOSTNAME>\$' -p '<hostname-lowercase>'"
            echo "# Success means the computer account password was never changed from setup."
        } > "$OUT/$ip/_pre2000_hint.txt"
    done
fi

log "ldap dispatcher done."
