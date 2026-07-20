#!/usr/bin/env bash
# writable-files.sh — find writable files that lead to privesc.
set -u

echo "=== /etc sensitive ==="
# NOTE: /etc/ld.so.conf.d/ (dir + *.conf) is included — a writable file there adds
# an attacker-controlled library search path consulted by every dynamically-linked
# root-run binary, a direct LD_* privesc the older list missed.
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/* /etc/hosts.allow /etc/pam.d/* /etc/profile /etc/bash.bashrc /etc/environment /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.conf.d/*; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && printf "\033[1;32m[+] WRITABLE:\033[0m %s\n" "$f"
done

echo
echo "=== /etc/systemd unit + drop-in files ==="
# Broadened beyond *.service: a writable .timer/.socket/.mount/.path or drop-in
# override (.d/*.conf) yields root code-exec just like a service. Covers system
# and user trees + /run/systemd.
find /etc/systemd /run/systemd /usr/lib/systemd \
    \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.mount' -o -name '*.path' -o -name '*.conf' \) \
    -writable 2>/dev/null
echo "--- writable ExecStart=/EnvironmentFile= targets of root units ---"
# A root-run unit pointing at a writable binary/script is exploitable even when
# the unit file itself is root-owned.
grep -rhoE '^(ExecStart[^=]*|EnvironmentFile[^=]*)=.*' /etc/systemd /usr/lib/systemd 2>/dev/null \
    | sed -E 's/^[^=]*=[-+@!]*//; s/ .*//' | sort -u | while read -r tgt; do
        [ -n "$tgt" ] && [ -f "$tgt" ] && [ -w "$tgt" ] && printf "\033[1;32m[+] WRITABLE unit target:\033[0m %s\n" "$tgt"
    done

echo
echo "=== Init scripts ==="
find /etc/init.d /etc/rc.d -type f -writable 2>/dev/null

echo
echo "=== Writable dirs in PATH ==="
IFS=':' read -ra DIRS <<< "$PATH"
for d in "${DIRS[@]}"; do
    # Flag '.', empty ('' -> current dir), and relative PATH elements regardless of
    # instantaneous writability — a classic CIS finding (root running a command
    # from CWD or a relative dir is hijackable).
    case "$d" in
        ""|.) printf "\033[1;33m[!] PATH contains current/empty dir (hijackable):\033[0m '%s'\n" "$d" ;;
        /*)   [ -w "$d" ] && printf "\033[1;32m[+] WRITABLE PATH dir:\033[0m %s\n" "$d" ;;
        *)    printf "\033[1;33m[!] PATH contains relative dir (hijackable):\033[0m '%s'\n" "$d" ;;
    esac
done

echo
echo "=== World-writable files in /etc, /opt, /usr/local, /srv (top 50) ==="
find /etc /opt /usr/local /srv -xdev -type f -perm -o+w 2>/dev/null | head -50

echo
echo "=== World-writable dirs (top 30) ==="
find / -xdev -type d -perm -o+w \( -not -path '/proc/*' -not -path '/sys/*' -not -path '/tmp' -not -path '/var/tmp' -not -path '/dev/shm' \) 2>/dev/null | head -30

echo
echo "=== Files owned by current user in odd locations ==="
USER=$(id -un)
find /etc /usr /opt /var -xdev -user "$USER" 2>/dev/null | head -50
