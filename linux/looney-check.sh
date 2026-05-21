#!/usr/bin/env bash
# looney-check.sh — CVE-2023-4911 (glibc ld.so GLIBC_TUNABLES local privesc).
# Vulnerable: glibc 2.34 .. 2.38 (fixed in 2.39 / backports starting 2023-09).
# Detection: glibc version pin via ldd / package manager + setuid binary presence.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_WARN=""; C_HDR=""; }

printf "%s== CVE-2023-4911 Looney Tunables check ==%s\n" "$C_HDR" "$C_RST"

# Pull glibc version from ldd (canonical) — fallback to package manager.
VER=""
if command -v ldd >/dev/null 2>&1; then
    VER=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
fi
if [ -z "$VER" ] && command -v rpm >/dev/null 2>&1; then
    VER=$(rpm -q --queryformat '%{VERSION}' glibc 2>/dev/null)
fi
if [ -z "$VER" ] && command -v dpkg >/dev/null 2>&1; then
    VER=$(dpkg-query -W -f='${Version}' libc6 2>/dev/null | sed 's/-.*//')
fi

if [ -z "$VER" ]; then
    printf "%s[?]%s glibc version not detectable — manual check via 'ldd --version'\n" "$C_WARN" "$C_RST"
    exit 0
fi
printf "  glibc version: %s\n" "$VER"

# Vulnerable window: 2.34 (inclusive) .. 2.38 (inclusive)
lo=$(printf '%s\n%s\n' "$VER" "2.34" | sort -V | head -1)
hi=$(printf '%s\n%s\n' "$VER" "2.39" | sort -V | head -1)
if [ "$lo" = "2.34" ] && [ "$hi" != "2.39" ]; then
    printf "%s[+] CRITICAL: glibc %s in vulnerable window 2.34-2.38 — Looney Tunables%s\n" "$C_HIT" "$VER" "$C_RST"
    printf "  Setuid binaries that link libc.so are the targets. Check for sudo/su/passwd:\n"
    for b in /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/mount /usr/bin/chsh; do
        [ -u "$b" ] && printf "    setuid: %s\n" "$b"
    done
    printf "  PoC: github.com/leesh3288/CVE-2023-4911\n"
else
    printf "  glibc %s outside vulnerable window 2.34-2.38 — not Looney-vulnerable.\n" "$VER"
fi

# Mitigations may be applied even with vulnerable version — note env hardening.
if [ -f /proc/sys/kernel/randomize_va_space ]; then
    aslr=$(cat /proc/sys/kernel/randomize_va_space)
    printf "  ASLR: %s (0=off, 1=partial, 2=full)\n" "$aslr"
fi
