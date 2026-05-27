#!/usr/bin/env bash
# writable-files.sh — find writable files that lead to privesc.
set -u

echo "=== /etc sensitive ==="
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/* /etc/hosts.allow /etc/pam.d/* /etc/profile /etc/bash.bashrc /etc/environment /etc/ld.so.preload /etc/ld.so.conf; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && printf "\033[1;32m[+] WRITABLE:\033[0m %s\n" "$f"
done

echo
echo "=== /etc/systemd unit files ==="
find /etc/systemd /usr/lib/systemd -name '*.service' -writable 2>/dev/null

echo
echo "=== Init scripts ==="
find /etc/init.d /etc/rc.d -type f -writable 2>/dev/null

echo
echo "=== Writable dirs in PATH ==="
IFS=':' read -ra DIRS <<< "$PATH"
for d in "${DIRS[@]}"; do [ -w "$d" ] && printf "\033[1;32m[+]\033[0m %s\n" "$d"; done

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
