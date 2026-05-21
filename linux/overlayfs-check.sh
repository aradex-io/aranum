#!/usr/bin/env bash
# overlayfs-check.sh — CVE-2023-0386 (overlayfs uid/gid mapping local privesc).
# Vulnerable: Linux 5.11+ on distros that backported overlayfs without the fix.
# Notably: Ubuntu HWE kernels 5.15.0-{60-86}, 6.2.0-{20-32}, 6.5.x pre-patch.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_WARN=""; C_HDR=""; }

printf "%s== CVE-2023-0386 overlayfs uid/gid mapping check ==%s\n" "$C_HDR" "$C_RST"

KERNEL=$(uname -r)
printf "  Kernel: %s\n" "$KERNEL"

# Unprivileged user namespace + overlayfs both required.
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    uuc=$(cat /proc/sys/kernel/unprivileged_userns_clone)
    printf "  unprivileged_userns_clone: %s (1=allowed, 0=blocked)\n" "$uuc"
fi
if grep -q '^overlay\|^overlayfs' /proc/filesystems 2>/dev/null; then
    printf "  overlayfs module: loaded\n"
else
    printf "  overlayfs module: NOT loaded — not directly exploitable from this host.\n"
fi

# Ubuntu-specific vulnerable-kernel ranges (the most-impacted distro):
case "$KERNEL" in
    5.15.0-*-generic)
        sub=$(echo "$KERNEL" | grep -oE '5\.15\.0-[0-9]+' | head -1 | awk -F- '{print $2}')
        if [ -n "$sub" ] && [ "$sub" -ge 60 ] && [ "$sub" -le 86 ]; then
            printf "%s[+] CRITICAL: kernel %s in Ubuntu HWE 5.15.0-{60..86} — CVE-2023-0386 vulnerable%s\n" "$C_HIT" "$KERNEL" "$C_RST"
        fi
        ;;
    6.2.0-*-generic)
        sub=$(echo "$KERNEL" | grep -oE '6\.2\.0-[0-9]+' | head -1 | awk -F- '{print $2}')
        if [ -n "$sub" ] && [ "$sub" -ge 20 ] && [ "$sub" -le 32 ]; then
            printf "%s[+] CRITICAL: kernel %s in Ubuntu HWE 6.2.0-{20..32} — CVE-2023-0386 vulnerable%s\n" "$C_HIT" "$KERNEL" "$C_RST"
        fi
        ;;
    *)
        printf "%s[?]%s Kernel %s not in the well-documented Ubuntu HWE vulnerable ranges.\n" "$C_WARN" "$C_RST" "$KERNEL"
        printf "  Check distro changelog for backport status (PoC: github.com/xkaneiki/CVE-2023-0386).\n"
        ;;
esac
