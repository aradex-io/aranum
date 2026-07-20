#!/usr/bin/env bash
# proc-hardening-check.sh — read-only host hardening audit (sysctl + LSM + /proc).
# CIS/Lynis-style: reports weak kernel/proc hardening knobs that widen the local
# attack surface (many are LPE preconditions). Pure /proc + /sys reads — NO
# dependencies, NO writes, safe on a bare minimal host (busybox/dash/read-only rootfs).
#
# Every weak setting is printed as "HARDENING: <detail>" so report.py can grade it.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;33m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_HDR=""; }

hdr()  { printf "%s== %s ==%s\n" "$C_HDR" "$1" "$C_RST"; }
flag() { printf "%s[!] HARDENING: %s%s\n" "$C_HIT" "$1" "$C_RST"; }
okln() { printf "  [ok] %s\n" "$1"; }

# check_sysctl PATH WEAK_REGEX MESSAGE — flag when the value matches WEAK_REGEX.
check_sysctl() {
    path="$1"; weak="$2"; msg="$3"
    if [ ! -r "$path" ]; then
        printf "  [?] %s unreadable\n" "$path"
        return
    fi
    val=$(cat "$path" 2>/dev/null)
    if printf '%s' "$val" | grep -qE "$weak"; then
        flag "$msg (value=$val)"
    else
        okln "$path=$val"
    fi
}

hdr "sysctl hardening"
check_sysctl /proc/sys/kernel/yama/ptrace_scope       '^0$'        "ptrace_scope=0 — unrestricted ptrace (same-uid process injection)"
check_sysctl /proc/sys/kernel/dmesg_restrict          '^0$'        "dmesg_restrict=0 — kernel log readable (KASLR/info-leak aid)"
check_sysctl /proc/sys/kernel/kptr_restrict           '^0$'        "kptr_restrict=0 — kernel pointers exposed in /proc"
check_sysctl /proc/sys/kernel/perf_event_paranoid     '^(-1|0|1)$' "perf_event_paranoid<2 — perf subsystem exposed to unprivileged users"
check_sysctl /proc/sys/kernel/unprivileged_bpf_disabled '^0$'      "unprivileged_bpf_disabled=0 — unprivileged eBPF allowed (widens kernel CVE surface)"
check_sysctl /proc/sys/kernel/kexec_load_disabled     '^0$'        "kexec_load_disabled=0 — kexec permitted"
check_sysctl /proc/sys/kernel/randomize_va_space      '^(0|1)$'    "randomize_va_space<2 — weak/partial ASLR"
check_sysctl /proc/sys/fs/protected_symlinks          '^0$'        "fs.protected_symlinks=0 — symlink-race hardening off"
check_sysctl /proc/sys/fs/protected_hardlinks         '^0$'        "fs.protected_hardlinks=0 — hardlink hardening off"
check_sysctl /proc/sys/fs/protected_fifos             '^0$'        "fs.protected_fifos=0 — FIFO-in-sticky-dir hardening off"
check_sysctl /proc/sys/fs/protected_regular           '^0$'        "fs.protected_regular=0 — regular-file-in-sticky-dir hardening off"
check_sysctl /proc/sys/fs/suid_dumpable               '^(1|2)$'    "fs.suid_dumpable!=0 — setuid core dumps enabled (credential leak)"

echo
hdr "LSM / MAC posture"
if [ -r /sys/kernel/security/lsm ]; then
    printf "  active LSMs: %s\n" "$(cat /sys/kernel/security/lsm 2>/dev/null)"
else
    printf "  /sys/kernel/security/lsm unreadable (LSM state unknown)\n"
fi
if command -v getenforce >/dev/null 2>&1; then
    se=$(getenforce 2>/dev/null)
    printf "  SELinux: %s\n" "$se"
    case "$se" in Permissive|Disabled) flag "SELinux $se — MAC not enforcing" ;; esac
elif [ -r /sys/fs/selinux/enforce ]; then
    en=$(cat /sys/fs/selinux/enforce 2>/dev/null)
    printf "  SELinux enforce: %s\n" "$en"
    [ "$en" = "0" ] && flag "SELinux enforce=0 — MAC not enforcing"
fi
if [ -r /proc/self/attr/current ]; then
    ctx=$(tr -d '\0' < /proc/self/attr/current 2>/dev/null)
    printf "  self MAC context: %s\n" "${ctx:-none}"
    [ -z "$ctx" ] || [ "$ctx" = "unconfined" ] && flag "process MAC context '${ctx:-none}' — unconfined"
fi
if command -v aa-status >/dev/null 2>&1; then
    if aa-status --enabled 2>/dev/null; then printf "  AppArmor: enabled\n"; else flag "AppArmor present but not enabled"; fi
fi

echo
hdr "/proc mount hardening (hidepid)"
if grep -qE ' /proc [^ ]*proc[^ ]* .*hidepid=[12]' /proc/mounts 2>/dev/null; then
    printf "  /proc hidepid: %s\n" "$(grep -E ' /proc ' /proc/mounts | grep -oE 'hidepid=[0-9]+' | head -1)"
else
    flag "/proc mounted without hidepid — other users' process cmdlines/env are visible"
fi
