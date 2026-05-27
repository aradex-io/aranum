#!/usr/bin/env bash
# pwnkit-check.sh — CVE-2021-4034 (pkexec memory-corruption local privesc).
# Vulnerable: polkit < 0.120 (also packaged as pkexec via polkit-pkla-compat).
# Detection: presence of pkexec setuid binary + version string check.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_WARN=""; C_HDR=""; }

printf "%s== CVE-2021-4034 PwnKit check ==%s\n" "$C_HDR" "$C_RST"

PKEXEC=$(command -v pkexec 2>/dev/null)
if [ -z "$PKEXEC" ]; then
    printf "  pkexec not on PATH — not vulnerable.\n"
    exit 0
fi

ls -l "$PKEXEC"
if [ -u "$PKEXEC" ]; then
    printf "%s[+]%s pkexec is setuid (root)\n" "$C_HIT" "$C_RST"
else
    printf "  pkexec present but NOT setuid — exploit requires setuid bit.\n"
    exit 0
fi

# Try to get version from the package manager (most reliable signal)
VER=""
if command -v rpm >/dev/null 2>&1; then
    VER=$(rpm -q --queryformat '%{VERSION}' polkit 2>/dev/null)
elif command -v dpkg >/dev/null 2>&1; then
    VER=$(dpkg-query -W -f='${Version}' policykit-1 2>/dev/null)
fi

if [ -n "$VER" ]; then
    printf "  polkit package version: %s\n" "$VER"
    # Compare numerically against 0.120 (the fixed release).
    lowest=$(printf '%s\n%s\n' "$VER" "0.120" | sort -V | head -1)
    if [ "$lowest" != "0.120" ]; then
        printf "%s[+] CRITICAL: polkit %s < 0.120 — PwnKit vulnerable%s\n" "$C_HIT" "$VER" "$C_RST"
        printf "  PoC: github.com/berdav/CVE-2021-4034 (compile + run, no args)\n"
    else
        printf "  polkit %s >= 0.120 — patched.\n" "$VER"
    fi
else
    printf "%s[?]%s polkit version not parseable from package manager — manual check.\n" "$C_WARN" "$C_RST"
    printf "  Try: pkexec --version  (also: file %s | grep 'not stripped' may help)\n" "$PKEXEC"
fi
