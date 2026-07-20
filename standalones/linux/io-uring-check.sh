#!/usr/bin/env bash
# io-uring-check.sh — io_uring availability + restrictions. io_uring has been
# the source of multiple privesc CVEs (CVE-2022-1786, CVE-2022-29582,
# CVE-2023-2598, CVE-2024-0582). If io_uring is reachable to unprivileged
# users on a kernel that backported the fixes incompletely, it's worth flagging.
#
# NO-DEPENDENCY: this runs on bare hosts (only /bin/sh + coreutils). It does NOT
# call python or issue the io_uring_setup syscall (the old ctypes probe silently
# no-oped on exactly the minimal hosts this toolkit targets, and hardcoded the
# x86_64 syscall number). The verdict is derived entirely from read-only /proc +
# uname signals.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_HDR=""; }

printf "%s== io_uring availability check ==%s\n" "$C_HDR" "$C_RST"

KERNEL=$(uname -r)
printf "  Kernel: %s\n" "$KERNEL"

# Parse major.minor from `uname -r` (e.g. 6.8.0-94-generic -> 6 8). io_uring
# landed in 5.1; the system-wide gate sysctl landed in 6.6.
kmajor=${KERNEL%%.*}
krest=${KERNEL#*.}; kminor=${krest%%.*}
# sanitize to digits so the arithmetic tests below can't error on odd version strings
case "$kmajor" in ''|*[!0-9]*) kmajor=0 ;; esac
case "$kminor" in ''|*[!0-9]*) kminor=0 ;; esac

present="no"
if [ "$kmajor" -gt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -ge 1 ]; }; then
    present="yes"
fi

# sysctl kernel.io_uring_disabled — added in 6.6 to gate io_uring system-wide.
#  0 = allowed for everyone
#  1 = allowed only with CAP_SYS_ADMIN (or io_uring_group)
#  2 = disabled completely
io_disabled=""
if [ -r /proc/sys/kernel/io_uring_disabled ]; then
    io_disabled=$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null)
    printf "  /proc/sys/kernel/io_uring_disabled: %s\n" "$io_disabled"
else
    printf "  /proc/sys/kernel/io_uring_disabled: (absent — kernel < 6.6 or CONFIG off)\n"
fi

# Do we hold CAP_SYS_ADMIN? Decode CapEff (hex) from /proc/self/status, test bit 21.
# Pure shell arithmetic — no external tools beyond grep.
has_cap_sys_admin="no"
capeff=$(grep -m1 '^CapEff:' /proc/self/status 2>/dev/null | tr -dc '0-9a-fA-F')
if [ -n "$capeff" ]; then
    if [ "$(( 0x$capeff & (1 << 21) ))" -ne 0 ] 2>/dev/null; then
        has_cap_sys_admin="yes"
    fi
fi

# Secondary confirmation the code path is compiled in, when kallsyms is readable
# (usually kptr_restrict hides addresses but the symbol names may still show).
kallsyms_hit=""
if [ -r /proc/kallsyms ]; then
    grep -qm1 ' io_uring_setup' /proc/kallsyms 2>/dev/null && kallsyms_hit="yes"
fi
[ -n "$kallsyms_hit" ] && printf "  io_uring_setup symbol present in /proc/kallsyms\n"

printf "  io_uring compiled/available (by kernel version): %s\n" "$present"

# Verdict — reachable to an unprivileged user when the feature is present AND not
# gated away by the sysctl (0/absent) AND we don't already hold CAP_SYS_ADMIN
# (which would make the "unprivileged" framing moot).
if [ "$present" != "yes" ]; then
    printf "  io_uring not present on this kernel (< 5.1) — not an unprivileged surface.\n"
elif [ "$io_disabled" = "2" ]; then
    printf "  Disabled system-wide by sysctl (=2) — blocked.\n"
elif [ "$io_disabled" = "1" ]; then
    if [ "$has_cap_sys_admin" = "yes" ]; then
        printf "%s[+] io_uring gated to CAP_SYS_ADMIN (=1) but current context HOLDS CAP_SYS_ADMIN — reachable%s\n" "$C_HIT" "$C_RST"
    else
        printf "  CAP_SYS_ADMIN required (sysctl=1) and not held — unprivileged exploit chain unlikely.\n"
    fi
else
    # io_disabled=0 or absent (kernel < 6.6, no gate) => reachable to unprivileged users.
    printf "%s[+] HIGH: io_uring reachable to current user — known CVE surface%s\n" "$C_HIT" "$C_RST"
    printf "  Check kernel against: CVE-2022-1786, CVE-2022-29582, CVE-2023-2598, CVE-2024-0582.\n"
fi
