#!/usr/bin/env bash
# apt-source-check.sh — writable apt configuration / hooks. Apt runs hooks as
# root during package install, and reads cache + sources from writable paths
# under /etc/apt/. If any of these are writable by an unprivileged user
# AND root ever runs `apt-get update / install`, the operator wins root.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;32m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_HDR=""; }

printf "%s== APT writable-config + hooks check ==%s\n" "$C_HDR" "$C_RST"

if ! command -v apt-get >/dev/null 2>&1; then
    printf "  apt-get not present — not a Debian/Ubuntu-family system.\n"
    exit 0
fi

# Apt hook directories (each runs scripts as root during install/update)
hook_dirs=(/etc/apt/apt.conf.d /etc/apt/apt.conf /etc/apt/preferences.d
           /etc/apt/sources.list.d /var/lib/apt /var/cache/apt /var/lib/dpkg)
hits=0
for d in "${hook_dirs[@]}"; do
    if [ -e "$d" ]; then
        # World/group writable directory
        if find "$d" -maxdepth 0 -type d \( -perm -o=w -o -perm -g=w \) 2>/dev/null | grep -q .; then
            printf "%s[+]%s WRITABLE: %s — root runs scripts from here on apt operations\n" "$C_HIT" "$C_RST" "$d"
            hits=$((hits + 1))
        fi
        # Writable files inside
        if find "$d" -maxdepth 2 -type f \( -perm -o=w -o -perm -g=w \) 2>/dev/null | head -5 | grep -q .; then
            find "$d" -maxdepth 2 -type f \( -perm -o=w -o -perm -g=w \) 2>/dev/null | head -5 | while read -r f; do
                printf "%s[+]%s WRITABLE file: %s\n" "$C_HIT" "$C_RST" "$f"
                hits=$((hits + 1))
            done
        fi
    fi
done

# sources.list itself
if [ -w /etc/apt/sources.list ]; then
    printf "%s[+]%s /etc/apt/sources.list WRITABLE — could redirect to attacker repo\n" "$C_HIT" "$C_RST"
    hits=$((hits + 1))
fi

# apt-get hook env: APT_CONFIG (operator-supplied config) — usually not set,
# but if it points to a writable file, that's a privesc surface.
if [ -n "${APT_CONFIG:-}" ]; then
    printf "  APT_CONFIG=$APT_CONFIG\n"
    [ -w "$APT_CONFIG" ] && printf "%s[+]%s APT_CONFIG file WRITABLE\n" "$C_HIT" "$C_RST"
fi

[ "$hits" -eq 0 ] && printf "  No writable apt config / hook surface to current user.\n"
