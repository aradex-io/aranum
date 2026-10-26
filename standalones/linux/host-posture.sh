#!/usr/bin/env bash
# host-posture.sh - read-only localhost hardening posture collector (aranum PLAN-001 D3.2).
#
# Emits one line per check, strict ASCII framing parsed by network/report.py:
#     POSTURE|<check-id>|<PASS|FAIL|WARN|INFO|NA|ERR>|<detail>
# ERR = the check could not run (permission, missing data) - never a PASS.
# Every check reads local files / local state only: no network, no writes, no
# package-cache refresh. Safe to pipe over SSH stdin after linenum-fast.sh: the
# body is one function invoked with stdin from /dev/null, so no command can
# consume the script stream, and nothing here depends on the caller's shell
# options. Check ids and their KB guidance live in network/finding-kb.json
# (`checks`); the posture-KB coverage gate keeps the two in sync.
#
# ARANUM_POSTURE_ROOT=<dir>  read every file under <dir> instead of / (hermetic
#                            tests); command-based checks then report NA, except
#                            service state, which reads ARANUM_POSTURE_SERVICES
#                            (space-separated active unit names).
# Authorized testing only.

__aranum_posture_main() {
    set +e
    set -u
    local R="${ARANUM_POSTURE_ROOT:-}"
    R="${R%/}"
    local HERMETIC=0
    [[ -n "$R" ]] && HERMETIC=1
    local MYUID
    MYUID="$(id -u 2>/dev/null || echo 0)"
    local NONROOT=0
    (( HERMETIC == 0 )) && [[ "$MYUID" != "0" ]] && NONROOT=1

    printf '== aranum host posture (linux) ==\n'

    # --- helpers ---------------------------------------------------------------
    _p_emit() {  # id status detail - detail flattened to one safe line
        local d="$3"
        d="${d//|/ }"
        d="${d//[[:cntrl:]]/ }"
        printf 'POSTURE|%s|%s|%s\n' "$1" "$2" "$d"
    }
    _p_read() {  # first line of a file under the root, NUL-stripped; rc 1 if unreadable
        local f="$R$1"
        [[ -r "$f" && -f "$f" ]] || return 1
        head -n 1 "$f" 2>/dev/null | tr -d '\0' | tr -d '\r'
    }
    _p_sysctl() {  # value of /proc/sys/<path>, trimmed
        local v
        v="$(_p_read "/proc/sys/$1")" || return 1
        v="${v//[[:space:]]/ }"
        printf '%s' "${v%% *}"
    }
    _p_mode() {  # octal mode of a path under the root
        stat -L -c '%a' "$R$1" 2>/dev/null
    }
    _p_cmd() {  # run a local command quietly; never under the hermetic root
        (( HERMETIC == 1 )) && return 127
        command -v "$1" >/dev/null 2>&1 || return 127
        "$@" </dev/null 2>/dev/null
    }
    _p_svc() {  # 0 active, 1 inactive, 2 unknown
        local u
        if (( HERMETIC == 1 )); then
            [[ -n "${ARANUM_POSTURE_SERVICES+x}" ]] || return 2
            for u in ${ARANUM_POSTURE_SERVICES}; do
                [[ "$u" == "$1" ]] && return 0
            done
            return 1
        fi
        if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
            systemctl is-active --quiet "$1" </dev/null 2>/dev/null && return 0
            return 1
        fi
        if command -v pgrep >/dev/null 2>&1; then
            pgrep -x "$1" >/dev/null 2>&1 && return 0
            return 1
        fi
        return 2
    }
    _p_any_svc() {  # first active service name among args; rc 0 found, 1 none, 2 unknown
        local s rc unknown=0
        for s in "$@"; do
            _p_svc "$s"; rc=$?
            if (( rc == 0 )); then printf '%s' "$s"; return 0; fi
            (( rc == 2 )) && unknown=1
        done
        (( unknown == 1 )) && return 2
        return 1
    }
    _p_kv() {  # value for KEY in a "KEY value" style file (login.defs), first match
        local f="$R$1"
        [[ -r "$f" ]] || return 1
        awk -v k="$2" '$1==k {print $2; exit}' "$f" 2>/dev/null
    }

    # --- patching ----------------------------------------------------------------
    local osname kern
    osname="$(awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2); print $2; exit}' "$R/etc/os-release" 2>/dev/null)"
    kern="$(_p_read /proc/sys/kernel/osrelease)"
    _p_emit LIN-OS-RELEASE INFO "os=${osname:-unknown} kernel=${kern:-unknown}"

    local family=""
    if [[ -d "$R/etc/apt" ]]; then family=deb
    elif [[ -d "$R/etc/dnf" || -f "$R/etc/yum.conf" ]]; then family=rpm
    fi

    local sim total sec
    if (( HERMETIC == 1 )); then
        _p_emit LIN-PKG-SECUPDATES NA "package manager not queried under ARANUM_POSTURE_ROOT"
    elif command -v apt-get >/dev/null 2>&1; then
        if sim="$(LC_ALL=C timeout 90 apt-get -s -o Debug::NoLocking=1 upgrade </dev/null 2>/dev/null)"; then
            total="$(printf '%s\n' "$sim" | grep -c '^Inst ')"
            sec="$(printf '%s\n' "$sim" | grep '^Inst ' | grep -ciE '[-/]security|Debian-Security')"
            if (( sec > 0 )); then _p_emit LIN-PKG-SECUPDATES FAIL "security=$sec total=$total (apt cache; not refreshed)"
            elif (( total > 0 )); then _p_emit LIN-PKG-SECUPDATES WARN "security=0 total=$total (apt cache; not refreshed)"
            else _p_emit LIN-PKG-SECUPDATES PASS "no pending upgrades in apt cache (cache not refreshed)"
            fi
        else
            _p_emit LIN-PKG-SECUPDATES ERR "apt-get -s upgrade failed"
        fi
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        local pm=dnf
        command -v dnf >/dev/null 2>&1 || pm=yum
        if sim="$(timeout 90 "$pm" -C -q updateinfo list --security </dev/null 2>/dev/null)"; then
            sec="$(printf '%s\n' "$sim" | grep -c '[^[:space:]]')"
            total="$(timeout 90 "$pm" -C -q check-update </dev/null 2>/dev/null | grep -c '^[[:alnum:]]')"
            if (( sec > 0 )); then _p_emit LIN-PKG-SECUPDATES FAIL "security=$sec total=$total ($pm cache; not refreshed)"
            elif (( total > 0 )); then _p_emit LIN-PKG-SECUPDATES WARN "security=0 total=$total ($pm cache; not refreshed)"
            else _p_emit LIN-PKG-SECUPDATES PASS "no pending updates in $pm cache (cache not refreshed)"
            fi
        else
            _p_emit LIN-PKG-SECUPDATES ERR "$pm -C updateinfo failed (empty cache?)"
        fi
    else
        _p_emit LIN-PKG-SECUPDATES NA "no supported package manager (apt/dnf/yum)"
    fi

    if [[ "$family" == deb ]]; then
        if grep -hqsE '^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' "$R"/etc/apt/apt.conf.d/* 2>/dev/null; then
            _p_emit LIN-PKG-AUTOUPDATE PASS "unattended-upgrades enabled"
        else
            _p_emit LIN-PKG-AUTOUPDATE WARN "APT::Periodic::Unattended-Upgrade not enabled"
        fi
    elif [[ "$family" == rpm ]]; then
        if ls "$R"/etc/systemd/system/timers.target.wants/dnf-automatic*.timer >/dev/null 2>&1; then
            _p_emit LIN-PKG-AUTOUPDATE PASS "dnf-automatic timer enabled"
        else
            _p_emit LIN-PKG-AUTOUPDATE WARN "dnf-automatic timer not enabled"
        fi
    else
        _p_emit LIN-PKG-AUTOUPDATE NA "unknown package family"
    fi

    if [[ -e "$R/var/run/reboot-required" || -e "$R/run/reboot-required" ]]; then
        _p_emit LIN-REBOOT-REQUIRED WARN "reboot-required flag present"
    elif [[ "$family" == deb ]]; then
        _p_emit LIN-REBOOT-REQUIRED PASS "no reboot-required flag"
    elif _p_cmd needs-restarting -r >/dev/null; then
        _p_emit LIN-REBOOT-REQUIRED PASS "needs-restarting -r: no reboot needed"
    elif (( $? == 1 )); then
        _p_emit LIN-REBOOT-REQUIRED WARN "needs-restarting -r: reboot needed"
    else
        _p_emit LIN-REBOOT-REQUIRED NA "no reboot indicator for this distro"
    fi

    # --- kernel sysctls --------------------------------------------------------------
    local v v2 v3
    if v="$(_p_sysctl kernel/yama/ptrace_scope)"; then
        if [[ "$v" == 0 ]]; then _p_emit LIN-SYSCTL-PTRACE WARN "kernel.yama.ptrace_scope=0"
        else _p_emit LIN-SYSCTL-PTRACE PASS "kernel.yama.ptrace_scope=$v"; fi
    else _p_emit LIN-SYSCTL-PTRACE NA "yama not present"; fi

    if v="$(_p_sysctl kernel/kptr_restrict)"; then
        if [[ "$v" == 0 ]]; then _p_emit LIN-SYSCTL-KPTR WARN "kernel.kptr_restrict=0"
        else _p_emit LIN-SYSCTL-KPTR PASS "kernel.kptr_restrict=$v"; fi
    else _p_emit LIN-SYSCTL-KPTR ERR "kernel.kptr_restrict unreadable"; fi

    if v="$(_p_sysctl kernel/dmesg_restrict)"; then
        if [[ "$v" == 0 ]]; then _p_emit LIN-SYSCTL-DMESG WARN "kernel.dmesg_restrict=0"
        else _p_emit LIN-SYSCTL-DMESG PASS "kernel.dmesg_restrict=$v"; fi
    else _p_emit LIN-SYSCTL-DMESG ERR "kernel.dmesg_restrict unreadable"; fi

    if v="$(_p_sysctl kernel/unprivileged_bpf_disabled)"; then
        if [[ "$v" == 0 ]]; then _p_emit LIN-SYSCTL-BPF WARN "kernel.unprivileged_bpf_disabled=0"
        else _p_emit LIN-SYSCTL-BPF PASS "kernel.unprivileged_bpf_disabled=$v"; fi
    else _p_emit LIN-SYSCTL-BPF NA "unprivileged_bpf_disabled not present"; fi

    v="$(_p_sysctl kernel/apparmor_restrict_unprivileged_userns)"
    v2="$(_p_sysctl kernel/unprivileged_userns_clone)"
    v3="$(_p_sysctl user/max_user_namespaces)"
    if [[ "$v" == 1 ]]; then _p_emit LIN-SYSCTL-USERNS PASS "apparmor_restrict_unprivileged_userns=1"
    elif [[ "$v2" == 0 ]]; then _p_emit LIN-SYSCTL-USERNS PASS "kernel.unprivileged_userns_clone=0"
    elif [[ "$v3" == 0 ]]; then _p_emit LIN-SYSCTL-USERNS PASS "user.max_user_namespaces=0"
    elif [[ -n "$v2$v3" ]]; then _p_emit LIN-SYSCTL-USERNS WARN "unprivileged userns allowed (clone=${v2:-n/a} max=${v3:-n/a})"
    else _p_emit LIN-SYSCTL-USERNS ERR "userns sysctls unreadable"; fi

    if v="$(_p_sysctl kernel/randomize_va_space)"; then
        if [[ "$v" == 2 ]]; then _p_emit LIN-SYSCTL-ASLR PASS "kernel.randomize_va_space=2"
        else _p_emit LIN-SYSCTL-ASLR FAIL "kernel.randomize_va_space=$v"; fi
    else _p_emit LIN-SYSCTL-ASLR ERR "kernel.randomize_va_space unreadable"; fi

    if v="$(_p_sysctl fs/suid_dumpable)"; then
        if [[ "$v" == 0 ]]; then _p_emit LIN-SYSCTL-SUIDDUMP PASS "fs.suid_dumpable=0"
        else _p_emit LIN-SYSCTL-SUIDDUMP WARN "fs.suid_dumpable=$v"; fi
    else _p_emit LIN-SYSCTL-SUIDDUMP ERR "fs.suid_dumpable unreadable"; fi

    v="$(_p_sysctl fs/protected_symlinks)"; v2="$(_p_sysctl fs/protected_hardlinks)"
    if [[ -z "$v" || -z "$v2" ]]; then _p_emit LIN-SYSCTL-PROTLINKS ERR "fs.protected_* unreadable"
    elif [[ "$v" == 0 || "$v2" == 0 ]]; then _p_emit LIN-SYSCTL-PROTLINKS WARN "protected_symlinks=$v protected_hardlinks=$v2"
    else _p_emit LIN-SYSCTL-PROTLINKS PASS "protected_symlinks=$v protected_hardlinks=$v2"; fi

    if v="$(_p_sysctl kernel/perf_event_paranoid)"; then
        if [[ "$v" =~ ^-?[0-9]+$ ]] && (( v < 2 )); then _p_emit LIN-SYSCTL-PERF WARN "kernel.perf_event_paranoid=$v"
        else _p_emit LIN-SYSCTL-PERF PASS "kernel.perf_event_paranoid=$v"; fi
    else _p_emit LIN-SYSCTL-PERF NA "perf_event_paranoid not present"; fi

    if v="$(_p_sysctl net/ipv4/ip_forward)"; then
        if [[ "$v" == 1 ]]; then _p_emit LIN-SYSCTL-IPFWD WARN "net.ipv4.ip_forward=1"
        else _p_emit LIN-SYSCTL-IPFWD PASS "net.ipv4.ip_forward=$v"; fi
    else _p_emit LIN-SYSCTL-IPFWD ERR "net.ipv4.ip_forward unreadable"; fi

    # --- MAC / firewall ---------------------------------------------------------------
    local lsm
    lsm="$(_p_read /sys/kernel/security/lsm)"
    v="$(_p_read /sys/fs/selinux/enforce)"
    v2="$(_p_read /sys/module/apparmor/parameters/enabled)"
    if [[ "$v" == 1 ]]; then _p_emit LIN-LSM-MAC PASS "selinux enforcing"
    elif [[ "$v2" == Y ]]; then _p_emit LIN-LSM-MAC PASS "apparmor enabled"
    elif [[ "$v" == 0 ]]; then _p_emit LIN-LSM-MAC WARN "selinux permissive; lsm=${lsm:-unknown}"
    else _p_emit LIN-LSM-MAC WARN "no enforcing MAC; lsm=${lsm:-unknown}"; fi

    local fw rc
    if grep -qsE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' "$R/etc/ufw/ufw.conf"; then
        _p_emit LIN-FIREWALL PASS "ufw ENABLED=yes"
    else
        fw="$(_p_any_svc firewalld nftables iptables netfilter-persistent ufw)"; rc=$?
        if (( rc == 0 )); then _p_emit LIN-FIREWALL PASS "$fw active"
        elif (( HERMETIC == 0 )) && [[ "$MYUID" == 0 ]] && command -v nft >/dev/null 2>&1; then
            if nft list ruleset </dev/null 2>/dev/null | grep -q 'hook input'; then
                _p_emit LIN-FIREWALL PASS "nft input hook present"
            else
                _p_emit LIN-FIREWALL WARN "no firewall service active and no nft input hook"
            fi
        elif (( rc == 2 )); then _p_emit LIN-FIREWALL ERR "service state unknown"
        elif (( NONROOT == 1 )); then _p_emit LIN-FIREWALL ERR "no firewall service active; raw ruleset needs root"
        else _p_emit LIN-FIREWALL WARN "no firewall service active"; fi
    fi

    # --- SSH ------------------------------------------------------------------------
    _p_ssh_lines() {  # $1 file (real path), $2 depth: "keyword value" lines, Match blocks skipped
        local file="$1" depth="$2" line kw rest pat inc inmatch=0
        [[ -r "$file" ]] || return 0
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="${line//$'\r'/}"
            read -r kw rest <<<"$line"
            [[ -z "$kw" ]] && continue
            if [[ "$kw" == *=* ]]; then rest="${kw#*=} $rest"; kw="${kw%%=*}"; fi
            rest="${rest#=}"; rest="${rest# }"
            kw="${kw,,}"
            if [[ "$kw" == match ]]; then inmatch=1; continue; fi
            (( inmatch == 1 )) && continue
            if [[ "$kw" == include ]]; then
                (( depth < 4 )) || continue
                for pat in $rest; do
                    [[ "$pat" == /* ]] || pat="/etc/ssh/$pat"
                    for inc in "$R"$pat; do
                        [[ -f "$inc" ]] && _p_ssh_lines "$inc" $((depth + 1))
                    done
                done
                continue
            fi
            printf '%s %s\n' "$kw" "$rest"
        done < "$file"
    }
    local sshcfg="" sshsrc=""
    if [[ -f "$R/etc/ssh/sshd_config" ]]; then
        if (( HERMETIC == 0 )) && [[ "$MYUID" == 0 ]] && command -v sshd >/dev/null 2>&1; then
            sshcfg="$(sshd -T </dev/null 2>/dev/null)" && sshsrc="sshd -T"
        fi
        if [[ -z "$sshsrc" ]]; then
            sshcfg="$(_p_ssh_lines "$R/etc/ssh/sshd_config" 0)"
            sshsrc="sshd_config"
        fi
    fi
    _p_ssh() { printf '%s\n' "$sshcfg" | awk -v k="$1" 'tolower($1)==k {$1=""; sub(/^ +/,""); print tolower($0); exit}'; }
    if [[ -z "$sshsrc" ]]; then
        local sid
        for sid in LIN-SSH-ROOTLOGIN LIN-SSH-PASSAUTH LIN-SSH-EMPTYPW LIN-SSH-X11 LIN-SSH-MAXAUTH LIN-SSH-CIPHERS; do
            _p_emit "$sid" NA "no sshd_config"
        done
    else
        v="$(_p_ssh permitrootlogin)"
        if [[ "$v" == yes ]]; then _p_emit LIN-SSH-ROOTLOGIN FAIL "PermitRootLogin yes ($sshsrc)"
        else _p_emit LIN-SSH-ROOTLOGIN PASS "PermitRootLogin ${v:-default} ($sshsrc)"; fi
        v="$(_p_ssh passwordauthentication)"
        if [[ "$v" == no ]]; then _p_emit LIN-SSH-PASSAUTH PASS "PasswordAuthentication no ($sshsrc)"
        else _p_emit LIN-SSH-PASSAUTH WARN "PasswordAuthentication ${v:-default yes} ($sshsrc)"; fi
        v="$(_p_ssh permitemptypasswords)"
        if [[ "$v" == yes ]]; then _p_emit LIN-SSH-EMPTYPW FAIL "PermitEmptyPasswords yes ($sshsrc)"
        else _p_emit LIN-SSH-EMPTYPW PASS "PermitEmptyPasswords ${v:-default no} ($sshsrc)"; fi
        v="$(_p_ssh x11forwarding)"
        if [[ "$v" == yes ]]; then _p_emit LIN-SSH-X11 WARN "X11Forwarding yes ($sshsrc)"
        else _p_emit LIN-SSH-X11 PASS "X11Forwarding ${v:-default no} ($sshsrc)"; fi
        v="$(_p_ssh maxauthtries)"
        [[ "$v" =~ ^[0-9]+$ ]] || v=6
        if (( v > 4 )); then _p_emit LIN-SSH-MAXAUTH WARN "MaxAuthTries $v ($sshsrc)"
        else _p_emit LIN-SSH-MAXAUTH PASS "MaxAuthTries $v ($sshsrc)"; fi
        local algs weak
        algs="$(_p_ssh ciphers),$(_p_ssh macs),$(_p_ssh kexalgorithms)"
        weak="$(printf '%s\n' "$algs" | tr ', ' '\n\n' \
            | grep -E -- '-cbc$|^arcfour|3des|hmac-md5|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1' \
            | sort -u | head -6 | tr '\n' ' ')"
        if [[ -n "$weak" ]]; then _p_emit LIN-SSH-CIPHERS WARN "weak algorithms: ${weak% } ($sshsrc)"
        else _p_emit LIN-SSH-CIPHERS PASS "no weak ciphers/MACs/KEX configured ($sshsrc)"; fi
    fi

    local k m bad="" nkeys=0
    for k in "$R"/etc/ssh/ssh_host_*_key; do
        [[ -f "$k" ]] || continue
        nkeys=$((nkeys + 1))
        m="$(stat -c '%a' "$k" 2>/dev/null)"
        if [[ -n "$m" ]] && (( (8#$m & 8#044) != 0 )); then bad="$bad ${k##*/}($m)"
        elif (( NONROOT == 1 )) && [[ -r "$k" ]]; then bad="$bad ${k##*/}(readable-by-uid-$MYUID)"; fi
    done
    if (( nkeys == 0 )); then _p_emit LIN-SSH-HOSTKEY-PERMS NA "no ssh host keys"
    elif [[ -n "$bad" ]]; then _p_emit LIN-SSH-HOSTKEY-PERMS FAIL "exposed:$bad"
    else _p_emit LIN-SSH-HOSTKEY-PERMS PASS "$nkeys host keys restricted"; fi

    # --- accounts -------------------------------------------------------------------
    if [[ -r "$R/etc/passwd" ]]; then
        v="$(awk -F: '$3=="0" && $1!="root" {printf "%s ", $1}' "$R/etc/passwd")"
        if [[ -n "$v" ]]; then _p_emit LIN-ACCT-UID0 FAIL "uid 0: ${v% }"
        else _p_emit LIN-ACCT-UID0 PASS "only root has uid 0"; fi
    else _p_emit LIN-ACCT-UID0 ERR "/etc/passwd unreadable"; fi

    if [[ -r "$R/etc/shadow" ]]; then
        v="$(awk -F: 'NF>1 && $2=="" {printf "%s ", $1}' "$R/etc/shadow")"
        if [[ -n "$v" ]]; then _p_emit LIN-ACCT-EMPTYPW FAIL "empty password: ${v% }"
        else _p_emit LIN-ACCT-EMPTYPW PASS "no empty password fields"; fi
    elif [[ -e "$R/etc/shadow" ]]; then _p_emit LIN-ACCT-EMPTYPW ERR "/etc/shadow not readable (run as root)"
    else _p_emit LIN-ACCT-EMPTYPW ERR "/etc/shadow absent"; fi

    if [[ ! -e "$R/etc/sudoers" ]] && { (( HERMETIC == 1 )) || ! command -v sudo >/dev/null 2>&1; }; then
        _p_emit LIN-ACCT-NOPASSWD NA "sudo not installed"
    elif [[ -r "$R/etc/sudoers" ]]; then
        local nrules=0 sf
        for sf in "$R/etc/sudoers" "$R"/etc/sudoers.d/*; do
            [[ -f "$sf" && -r "$sf" ]] || continue
            nrules=$(( nrules + $(grep -vE '^[[:space:]]*#' "$sf" 2>/dev/null | grep -c 'NOPASSWD') ))
        done
        if (( nrules > 0 )); then _p_emit LIN-ACCT-NOPASSWD WARN "$nrules NOPASSWD rule(s)"
        else _p_emit LIN-ACCT-NOPASSWD PASS "no NOPASSWD rules"; fi
    else _p_emit LIN-ACCT-NOPASSWD ERR "sudoers not readable (run as root)"; fi

    if [[ -r "$R/etc/group" ]]; then
        v="$(awk -F: '$1=="sudo"||$1=="wheel"||$1=="admin" {printf "%s=%s ", $1, ($4==""?"(none)":$4)}' "$R/etc/group")"
        v="${v% }"
        _p_emit LIN-ACCT-ADMINS INFO "${v:-no sudo/wheel/admin group}"
    else _p_emit LIN-ACCT-ADMINS ERR "/etc/group unreadable"; fi

    if [[ -r "$R/etc/login.defs" ]]; then
        v="$(_p_kv /etc/login.defs UMASK)"
        if [[ -z "$v" ]]; then _p_emit LIN-ACCT-UMASK PASS "UMASK unset (default 022)"
        elif [[ "$v" =~ ^0?[0-7]{3}$ ]] && (( (8#$v & 8#022) == 8#022 )); then _p_emit LIN-ACCT-UMASK PASS "UMASK $v"
        else _p_emit LIN-ACCT-UMASK WARN "UMASK $v grants group/other write"; fi
        v="$(_p_kv /etc/login.defs PASS_MAX_DAYS)"
        if [[ "$v" =~ ^[0-9]+$ ]] && (( v <= 365 )); then _p_emit LIN-ACCT-AGING PASS "PASS_MAX_DAYS $v"
        else _p_emit LIN-ACCT-AGING WARN "PASS_MAX_DAYS ${v:-unset}"; fi
    else
        _p_emit LIN-ACCT-UMASK NA "no /etc/login.defs"
        _p_emit LIN-ACCT-AGING NA "no /etc/login.defs"
    fi

    # --- filesystem ------------------------------------------------------------------
    local f
    bad=""
    for f in /etc/shadow /etc/gshadow; do
        m="$(_p_mode "$f")"
        [[ -n "$m" ]] && (( (8#$m & 8#006) != 0 )) && bad="$bad $f($m)"
    done
    if [[ -n "$bad" ]]; then _p_emit LIN-FILE-SHADOW FAIL "world-accessible:$bad"
    elif [[ -e "$R/etc/shadow" ]]; then _p_emit LIN-FILE-SHADOW PASS "shadow $(_p_mode /etc/shadow)"
    else _p_emit LIN-FILE-SHADOW NA "/etc/shadow absent"; fi

    bad=""
    for f in /etc/passwd /etc/group; do
        m="$(_p_mode "$f")"
        [[ -n "$m" ]] && (( (8#$m & 8#022) != 0 )) && bad="$bad $f($m)"
    done
    if [[ -n "$bad" ]]; then _p_emit LIN-FILE-PASSWD FAIL "group/other-writable:$bad"
    elif [[ -e "$R/etc/passwd" ]]; then _p_emit LIN-FILE-PASSWD PASS "passwd $(_p_mode /etc/passwd)"
    else _p_emit LIN-FILE-PASSWD ERR "/etc/passwd absent"; fi

    local mounts="$R/proc/mounts" opts miss o
    [[ -r "$mounts" ]] || mounts="$R/proc/self/mounts"
    if [[ -r "$mounts" ]]; then
        opts="$(awk '$2=="/tmp" {o=$4} END {print o}' "$mounts")"
        if [[ -z "$opts" ]]; then _p_emit LIN-MNT-TMP WARN "/tmp is not a separate mount"
        else
            miss=""
            for o in nosuid nodev; do [[ ",$opts," == *",$o,"* ]] || miss="$miss $o"; done
            if [[ -n "$miss" ]]; then _p_emit LIN-MNT-TMP WARN "/tmp missing:$miss"
            else _p_emit LIN-MNT-TMP PASS "/tmp $opts"; fi
        fi
        opts="$(awk '$2=="/dev/shm" {o=$4} END {print o}' "$mounts")"
        if [[ -z "$opts" ]]; then _p_emit LIN-MNT-SHM NA "/dev/shm not mounted"
        else
            miss=""
            for o in noexec nosuid; do [[ ",$opts," == *",$o,"* ]] || miss="$miss $o"; done
            if [[ -n "$miss" ]]; then _p_emit LIN-MNT-SHM WARN "/dev/shm missing:$miss"
            else _p_emit LIN-MNT-SHM PASS "/dev/shm $opts"; fi
        fi
    else
        _p_emit LIN-MNT-TMP ERR "mount table unreadable"
        _p_emit LIN-MNT-SHM ERR "mount table unreadable"
    fi

    local pathlist="" envpath d
    (( HERMETIC == 0 )) && pathlist="${PATH:-}"
    envpath="$(awk -F= '$1=="PATH" {gsub(/"/,"",$2); print $2; exit}' "$R/etc/environment" 2>/dev/null)"
    [[ -n "$envpath" ]] && pathlist="$pathlist:$envpath"
    bad=""
    local seen=""
    local IFS_SAVE="$IFS"
    IFS=:
    for d in $pathlist; do
        IFS="$IFS_SAVE"
        if [[ "$d" == "." ]]; then bad="$bad .(relative)"; IFS=:; continue; fi
        [[ -z "$d" || "$d" != /* ]] && { IFS=:; continue; }
        [[ " $seen " == *" $d "* ]] && { IFS=:; continue; }
        seen="$seen $d"
        m="$(_p_mode "$d")"
        if [[ -n "$m" ]] && (( (8#$m & 8#002) != 0 )) && (( (8#$m & 8#1000) == 0 )); then bad="$bad $d($m)"; fi
        IFS=:
    done
    IFS="$IFS_SAVE"
    if [[ -z "$pathlist" ]]; then _p_emit LIN-PATH-WW NA "no PATH to evaluate"
    elif [[ -n "$bad" ]]; then _p_emit LIN-PATH-WW FAIL "writable PATH entries:$bad"
    else _p_emit LIN-PATH-WW PASS "no world-writable PATH directories"; fi

    bad="$(find "$R/etc/crontab" "$R/etc/cron.d" "$R/etc/cron.hourly" "$R/etc/cron.daily" \
               "$R/etc/cron.weekly" "$R/etc/cron.monthly" -maxdepth 1 \( -type f -o -type d \) \
               -perm -0002 2>/dev/null | head -3 | sed "s#^$R##" | tr '\n' ' ')"
    if [[ -n "$bad" ]]; then _p_emit LIN-CRON-PERMS FAIL "world-writable: ${bad% }"
    elif [[ -e "$R/etc/crontab" || -d "$R/etc/cron.d" ]]; then _p_emit LIN-CRON-PERMS PASS "cron paths not world-writable"
    else _p_emit LIN-CRON-PERMS NA "no system cron configuration"; fi

    # --- logging / time ----------------------------------------------------------------
    _p_svc auditd; rc=$?
    if (( rc == 0 )); then _p_emit LIN-LOG-AUDITD PASS "auditd active"
    elif (( rc == 1 )); then _p_emit LIN-LOG-AUDITD WARN "auditd not active"
    else _p_emit LIN-LOG-AUDITD NA "service state unknown"; fi

    fw="$(_p_any_svc rsyslog syslog-ng syslog)"; rc=$?
    if (( rc == 0 )); then _p_emit LIN-LOG-SYSLOG PASS "$fw active"
    else
        v="$(awk -F= '$1 ~ /^[[:space:]]*Storage/ {gsub(/[[:space:]]/,"",$2); s=$2} END {print s}' "$R/etc/systemd/journald.conf" 2>/dev/null)"
        if [[ "$v" == persistent ]] || { [[ -z "$v" || "$v" == auto ]] && [[ -d "$R/var/log/journal" ]]; }; then
            _p_emit LIN-LOG-SYSLOG PASS "journald persistent storage"
        elif (( rc == 2 )) && [[ ! -e "$R/etc/systemd/journald.conf" ]]; then
            _p_emit LIN-LOG-SYSLOG NA "logging state unknown"
        else
            _p_emit LIN-LOG-SYSLOG WARN "no syslog daemon and journald not persistent (Storage=${v:-auto})"
        fi
    fi

    fw="$(_p_any_svc chronyd chrony systemd-timesyncd ntpd ntp ntpsec)"; rc=$?
    if (( rc == 0 )); then _p_emit LIN-TIME-SYNC PASS "$fw active"
    elif (( rc == 1 )); then _p_emit LIN-TIME-SYNC WARN "no time sync service active"
    else _p_emit LIN-TIME-SYNC NA "service state unknown"; fi

    # --- boot / services ----------------------------------------------------------------
    local sbf
    if [[ ! -d "$R/sys/firmware/efi" ]]; then
        _p_emit LIN-BOOT-SECUREBOOT INFO "legacy BIOS boot (no EFI)"
    else
        sbf=""
        for f in "$R"/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c; do
            [[ -r "$f" ]] && sbf="$f"
        done
        if [[ -n "$sbf" ]]; then
            v="$(od -An -tu1 -j4 -N1 "$sbf" 2>/dev/null | tr -d ' ')"
            if [[ "$v" == 1 ]]; then _p_emit LIN-BOOT-SECUREBOOT PASS "SecureBoot enabled"
            elif [[ "$v" == 0 ]]; then _p_emit LIN-BOOT-SECUREBOOT WARN "SecureBoot disabled"
            else _p_emit LIN-BOOT-SECUREBOOT ERR "SecureBoot efivar unparseable"; fi
        elif v="$(_p_cmd mokutil --sb-state)"; then
            case "$v" in
                *enabled*) _p_emit LIN-BOOT-SECUREBOOT PASS "SecureBoot enabled (mokutil)" ;;
                *disabled*) _p_emit LIN-BOOT-SECUREBOOT WARN "SecureBoot disabled (mokutil)" ;;
                *) _p_emit LIN-BOOT-SECUREBOOT ERR "mokutil output unrecognised" ;;
            esac
        else _p_emit LIN-BOOT-SECUREBOOT ERR "SecureBoot state unreadable"; fi
    fi

    if v="$(_p_cmd systemctl --failed --no-legend --plain)"; then
        _p_emit LIN-SVC-FAILED INFO "failed_units=$(printf '%s\n' "$v" | grep -c '[^[:space:]]')"
    else _p_emit LIN-SVC-FAILED NA "systemctl unavailable"; fi

    local sock=""
    for f in /var/run/docker.sock /run/docker.sock; do
        [[ -S "$R$f" || -e "$R$f" ]] && { sock="$f"; break; }
    done
    if [[ -z "$sock" ]]; then _p_emit LIN-CTR-DOCKERSOCK NA "no docker socket"
    else
        m="$(_p_mode "$sock")"
        if [[ -n "$m" ]] && (( (8#$m & 8#002) != 0 )); then _p_emit LIN-CTR-DOCKERSOCK FAIL "$sock world-writable ($m)"
        elif (( NONROOT == 1 )) && [[ -w "$sock" ]]; then _p_emit LIN-CTR-DOCKERSOCK FAIL "$sock writable by uid $MYUID (root-equivalent)"
        else _p_emit LIN-CTR-DOCKERSOCK PASS "$sock mode ${m:-?}"; fi
    fi

    # --- directory membership (localhost only; no DC query) -------------------------------
    local realm via=""
    realm="$(_p_cmd realm list --name-only | head -1)"
    [[ -n "$realm" ]] && via="realm"
    if [[ -z "$realm" ]]; then
        realm="$(awk -F= '$1 ~ /^[[:space:]]*default_realm/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$R/etc/krb5.conf" 2>/dev/null)"
        [[ -n "$realm" ]] && via="krb5.conf"
    fi
    if [[ -e "$R/etc/sssd/sssd.conf" ]]; then via="${via:+$via+}sssd"
    elif grep -qsiE '^[[:space:]]*security[[:space:]]*=[[:space:]]*ads' "$R/etc/samba/smb.conf"; then via="${via:+$via+}winbind"; fi
    if [[ "$via" == *sssd* || "$via" == *winbind* || "$via" == realm* ]]; then
        _p_emit LIN-AD-JOINED INFO "joined realm=${realm:-unknown} via=$via"
    elif [[ -n "$realm" ]]; then _p_emit LIN-AD-JOINED INFO "kerberos client only realm=$realm"
    else _p_emit LIN-AD-JOINED INFO "not joined"; fi

    if [[ -e "$R/etc/krb5.keytab" ]]; then
        m="$(_p_mode /etc/krb5.keytab)"
        if [[ -n "$m" ]] && (( (8#$m & 8#004) != 0 )); then _p_emit LIN-AD-KEYTAB FAIL "/etc/krb5.keytab world-readable ($m)"
        elif (( NONROOT == 1 )) && [[ -r "$R/etc/krb5.keytab" ]]; then _p_emit LIN-AD-KEYTAB FAIL "/etc/krb5.keytab readable by uid $MYUID"
        else _p_emit LIN-AD-KEYTAB PASS "/etc/krb5.keytab mode ${m:-?}"; fi
    else _p_emit LIN-AD-KEYTAB NA "no host keytab"; fi

    return 0
}
__aranum_posture_main "$@" </dev/null
