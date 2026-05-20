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

log "smb dispatcher done."
