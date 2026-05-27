#!/usr/bin/env bash
# io-uring-check.sh — io_uring availability + restrictions. io_uring has been
# the source of multiple privesc CVEs (CVE-2022-1786, CVE-2022-29582,
# CVE-2023-2598, CVE-2024-0582). If io_uring is reachable to unprivileged
# users on a kernel that backported the fixes incompletely, it's worth flagging.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_HDR=""; }

printf "%s== io_uring availability check ==%s\n" "$C_HDR" "$C_RST"

KERNEL=$(uname -r)
printf "  Kernel: %s\n" "$KERNEL"

# sysctl kernel.io_uring_disabled — added in 6.6 to gate io_uring system-wide.
#  0 = allowed for everyone
#  1 = allowed only with CAP_SYS_ADMIN (or io_uring_group)
#  2 = disabled completely
io_disabled=""
if [ -r /proc/sys/kernel/io_uring_disabled ]; then
    io_disabled=$(cat /proc/sys/kernel/io_uring_disabled)
    printf "  /proc/sys/kernel/io_uring_disabled: %s\n" "$io_disabled"
fi

# Try a tiny io_uring_setup syscall via python to confirm reachability.
# This is purely detection — opens then immediately closes the ring fd.
reachable="no"
if command -v python3 >/dev/null 2>&1; then
    reachable=$(python3 -c "
import ctypes, ctypes.util, os
libc = ctypes.CDLL(ctypes.util.find_library('c'))
class Params(ctypes.Structure):
    _fields_ = [('sq_entries', ctypes.c_uint32),
                ('cq_entries', ctypes.c_uint32),
                ('flags',      ctypes.c_uint32),
                ('sq_thread_cpu', ctypes.c_uint32),
                ('sq_thread_idle', ctypes.c_uint32),
                ('features',   ctypes.c_uint32),
                ('wq_fd',      ctypes.c_uint32),
                ('resv',       ctypes.c_uint32 * 3),
                ('sq_off',     ctypes.c_uint64 * 8),
                ('cq_off',     ctypes.c_uint64 * 8)]
p = Params()
# Syscall 425 = __NR_io_uring_setup on x86_64
fd = libc.syscall(425, 1, ctypes.byref(p))
if fd >= 0:
    os.close(fd); print('yes')
else:
    print('no')
" 2>/dev/null)
fi
printf "  io_uring_setup() reachable to current user: %s\n" "$reachable"

# Verdict
if [ "$reachable" = "yes" ]; then
    if [ "$io_disabled" = "2" ]; then
        printf "  Disabled by sysctl — reachability check is stale (cache?), treat as blocked.\n"
    elif [ "$io_disabled" = "1" ]; then
        printf "  CAP_SYS_ADMIN required — unprivileged exploit chain unlikely.\n"
    else
        printf "%s[+] HIGH: io_uring reachable to current user — known CVE surface%s\n" "$C_HIT" "$C_RST"
        printf "  Check kernel against: CVE-2022-1786, CVE-2022-29582, CVE-2023-2598, CVE-2024-0582.\n"
    fi
else
    printf "  io_uring not reachable to current user (syscall returned error).\n"
fi
