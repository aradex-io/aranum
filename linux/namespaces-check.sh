#!/usr/bin/env bash
# namespaces-check.sh — unprivileged user-namespace creation surface. Many
# Linux kernel CVEs require an unprivileged user namespace to exploit
# (CVE-2022-0185, CVE-2022-25636, CVE-2023-32233 nftables, etc.). If the host
# allows unprivileged userns, every legitimate user can craft the precondition.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_WARN=""; C_HDR=""; }

printf "%s== Unprivileged user-namespace creation check ==%s\n" "$C_HDR" "$C_RST"

KERNEL=$(uname -r)
printf "  Kernel: %s\n" "$KERNEL"

# Distro-canonical knobs:
for knob in /proc/sys/kernel/unprivileged_userns_clone \
            /proc/sys/user/max_user_namespaces \
            /proc/sys/kernel/apparmor_restrict_unprivileged_userns; do
    if [ -r "$knob" ]; then
        printf "  %s: %s\n" "$knob" "$(cat "$knob")"
    fi
done

# Empirical test: try to actually unshare a userns from the current shell.
# `unshare -rU -- /bin/true` is harmless — exits immediately if it works.
if command -v unshare >/dev/null 2>&1; then
    if unshare -rU -- /bin/true 2>/dev/null; then
        printf "%s[+] HIGH: unshare -rU succeeded — unprivileged userns creation works%s\n" "$C_HIT" "$C_RST"
        printf "  Precondition for many recent kernel CVE PoCs (CVE-2022-0185, CVE-2023-32233, etc.)\n"
    else
        printf "  unshare -rU failed — userns creation is blocked for current user.\n"
    fi
else
    printf "%s[?]%s 'unshare' missing — install util-linux to confirm.\n" "$C_WARN" "$C_RST"
fi
