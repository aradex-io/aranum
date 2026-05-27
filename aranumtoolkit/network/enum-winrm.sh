#!/usr/bin/env bash
# enum-winrm.sh — WinRM enumeration / cred validation.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "winrm: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

if have nxc || have netexec; then
    NXC=$(command -v nxc || command -v netexec)
    NXC_ARGS=()
    nxc_creds_array NXC_ARGS

    log "nxc winrm (cred check)"
    echo "$IPS" | "$NXC" winrm - "${NXC_ARGS[@]}" > "$OUT/nxc_winrm.txt" 2>&1 || true

    if [ -n "${ENUM_USER:-}" ]; then
        log "nxc winrm -x 'whoami /priv' (priv enumeration on accepting hosts)"
        echo "$IPS" | "$NXC" winrm - "${NXC_ARGS[@]}" -x 'whoami /priv && whoami /groups && hostname' \
            > "$OUT/nxc_winrm_whoami.txt" 2>&1 || true
    fi
else
    miss "nxc/netexec not installed"
fi

# evil-winrm test for hosts that NXC reports +
if have evil-winrm && [ -n "${ENUM_USER:-}" ]; then
    log "evil-winrm: skipping auto-spawn (interactive). Successful hosts in $OUT/nxc_winrm.txt"
    echo "Hint: evil-winrm -i <ip> -u $ENUM_USER -p $ENUM_PASS" >> "$OUT/_hints.txt"
fi

log "winrm dispatcher done."
