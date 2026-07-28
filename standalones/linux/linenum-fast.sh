#!/usr/bin/env bash
# linenum-fast.sh — fast no-dep Linux privesc enumerator.
# Quiet by default; pass -v for verbose ls listings.
# Usage: ./linenum-fast.sh [-v] [-o outfile]

set -uo pipefail
VERBOSE=0
OUT=""
while getopts "vo:h" opt; do
  case "$opt" in
    v) VERBOSE=1 ;;
    o) OUT="$OPTARG" ;;
    h) echo "Usage: $0 [-v] [-o outfile]"; exit 0 ;;
    *) echo "Usage: $0 [-v] [-o outfile]" >&2; exit 2 ;;
  esac
done

if [ -n "$OUT" ]; then exec > >(tee -a "$OUT") 2>&1; fi

C_RST=$'\033[0m'; C_HDR=$'\033[1;36m'; C_HIT=$'\033[1;32m'; C_WARN=$'\033[1;33m'
[ -t 1 ] || { C_RST=""; C_HDR=""; C_HIT=""; C_WARN=""; }

hdr() { printf "\n%s===[ %s ]===%s\n" "$C_HDR" "$1" "$C_RST"; }
hit() { printf "%s[+]%s %s\n" "$C_HIT" "$C_RST" "$1"; }
warn(){ printf "%s[!]%s %s\n" "$C_WARN" "$C_RST" "$1"; }

# ---------- SYSTEM ----------
hdr "SYSTEM"
uname -a
[ -f /etc/os-release ] && cat /etc/os-release
[ -f /etc/lsb-release ] && cat /etc/lsb-release
echo "Hostname: $(hostname)"
echo "Uptime  : $(uptime -p 2>/dev/null || uptime)"
echo "Kernel  : $(uname -r)"
ARCH=$(uname -m); echo "Arch    : $ARCH"

# Kernel exploit hints (date-cutoff style — coarse signal)
KVER=$(uname -r | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
# Dot-anchored minor patterns so e.g. 6.15.0 lands in the 6.1x bucket, not 6.[0-5].
case "$KVER" in
  2.6.*|3.[0-9]|3.[0-9].*|3.10.*|3.11.*|3.12.*|3.13.*) warn "Kernel $KVER — likely DirtyCow / overlayfs / family" ;;
  4.[0-9].*|4.1[0-9].*) warn "Kernel $KVER — check eBPF (CVE-2017-16995), DirtyCow late-3.x, 4.x-LTS LPEs" ;;
  5.[0-9].*) warn "Kernel $KVER — pwnkit/Looney/nf_tables/io_uring/ksmbd era" ;;
  5.1[0-5].*) warn "Kernel $KVER — DirtyPipe (CVE-2022-0847 <5.16.11/5.15.25), nf_tables, StackRot" ;;
  5.1[6-9].*|6.[0-5].*) warn "Kernel $KVER — nf_tables (CVE-2024-1086), OverlayFS/GameOver(lay), io_uring" ;;
  6.[6-9].*|6.1[0-9].*) warn "Kernel $KVER — recent LPEs; check io_uring_disabled sysctl + nf_tables" ;;
esac

# ---------- USER / GROUPS ----------
hdr "USER / GROUPS"
id
groups
echo "Logged-in users:"; who
echo "Last logins:"; last -an 2>/dev/null | head -10

# Dangerous group memberships
for g in docker lxd lxc disk video adm sudo wheel root shadow systemd-journal kvm; do
  if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx "$g"; then
    case "$g" in
      docker|lxd|lxc) hit "$g — container-escape to root" ;;
      disk)          hit "$g — read raw block devices /dev/sda* — debugfs / dump shadow" ;;
      video)         hit "$g — /dev/fb0 — screen scrape" ;;
      adm)           hit "$g — read /var/log/* including auth.log" ;;
      shadow)        hit "$g — read /etc/shadow" ;;
      kvm)           hit "$g — /dev/kvm — guest escape territory" ;;
      systemd-journal) hit "$g — read all journal entries" ;;
      *)             echo "  member of $g" ;;
    esac
  fi
done

# ---------- SUDO ----------
hdr "SUDO"
sudo -V 2>/dev/null | head -1
# Keep the pN patchlevel so the 1.9.17 vs 1.9.17p1 (fixed) distinction holds.
SUDO_VER=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)
# Coarse triage (see sudo-enum.sh for sort -V range-accurate signals). `;;&`
# is the bash "fall through to test the next pattern" terminator.
case "$SUDO_VER" in
  1.8.2|1.8.3*|1.8.4*|1.8.5*|1.8.6*|1.8.7*|1.8.8*|1.8.9*|1.8.10*|1.8.11*|1.8.12*|1.8.13*|1.8.14*|1.8.15*|1.8.16*|1.8.17*|1.8.18*|1.8.19*|1.8.20*|1.8.21*|1.8.22*|1.8.23*|1.8.24*|1.8.25*|1.8.26*|1.8.27*|1.8.28*|1.8.29*|1.8.30*|1.8.31*|1.9.0|1.9.1|1.9.2|1.9.3|1.9.4|1.9.5*)
    warn "sudo $SUDO_VER — possibly CVE-2021-3156 (Baron Samedit)" ;;&
  1.8.[0-9]|1.8.1[0-9]|1.8.2[0-9])
    warn "sudo $SUDO_VER — also check CVE-2019-14287 (sudo -u#-1)" ;;&
  1.9.14*|1.9.15*|1.9.16*|1.9.17)
    warn "sudo $SUDO_VER — check CVE-2025-32463 (--chroot) / CVE-2025-32462 (--host), fixed 1.9.17p1" ;;
esac
sudo -n -l 2>/dev/null
[ $? -ne 0 ] && echo "  (sudo -l requires password; cannot enumerate without it)"

# ---------- SUID / SGID ----------
hdr "SUID / SGID binaries"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %g %p\n' 2>/dev/null |
    grep -Ev '/(snap|usr/lib/(snapd|gvfs|virtualbox|sssd))' | sort -u

# ---------- CAPABILITIES ----------
hdr "CAPABILITIES"
if command -v getcap >/dev/null; then
    getcap -r / 2>/dev/null | grep -v '^$'
else
    echo "getcap not installed — try: find / -type f -exec getcap {} + 2>/dev/null"
fi

# ---------- CRON ----------
hdr "CRON"
ls -la /etc/cron* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null
cat /etc/crontab 2>/dev/null
for f in /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -e "$f" ] || continue
    if [ -w "$f" ]; then hit "WRITABLE cron: $f"; else [ "$VERBOSE" = "1" ] && echo "$f"; fi
done

# ---------- WRITABLE /ETC and PATH ----------
hdr "Writable sensitive files"
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/* /etc/hosts.allow /etc/hosts.deny /etc/cron.allow; do
    [ -e "$f" ] || continue
    [ -w "$f" ] && hit "WRITABLE: $f"
done
echo "PATH=$PATH"
IFS=':' read -ra DIRS <<< "$PATH"
for d in "${DIRS[@]}"; do [ -w "$d" ] && hit "WRITABLE PATH dir: $d"; done

# ---------- LD_PRELOAD / LD_LIBRARY_PATH / sudo env_keep ----------
hdr "LD_* environment"
env | grep -E '^LD_'
sudo -n -l 2>/dev/null | grep -E 'env_keep|env_reset' | head -5

# ---------- WORLD-WRITABLE ----------
hdr "World-writable files in standard dirs (top 50)"
find /etc /usr/local/etc /opt /srv /home -xdev -type f -perm -o+w 2>/dev/null | head -50

# ---------- SSH ----------
hdr "SSH keys / configs"
ls -la /root/.ssh/ "$HOME/.ssh/" 2>/dev/null
find / -name 'id_rsa*' -o -name 'id_ecdsa*' -o -name 'id_ed25519*' 2>/dev/null | head -20
[ -f "$HOME/.ssh/authorized_keys" ] && wc -l "$HOME/.ssh/authorized_keys"

# ---------- HISTORY / DOTFILES ----------
hdr "Shell histories"
for f in /root/.bash_history /root/.zsh_history "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.mysql_history" "$HOME/.psql_history" "$HOME/.python_history" "$HOME/.local/share/fish/fish_history"; do
    if [ -r "$f" ]; then
        echo "--- $f ---"
        grep -Ei 'pass(wd|word)|secret|token|api[_-]?key|export.*KEY|curl.*-u' "$f" 2>/dev/null | head -20
    fi
done

# ---------- NETWORK / SERVICES ----------
hdr "Listening services"
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null
hdr "Active connections"
ss -tnp 2>/dev/null | head -20

# ---------- NFS exports ----------
hdr "NFS exports / mounts"
[ -f /etc/exports ] && cat /etc/exports
mount | grep -E 'nfs|cifs'
[ -f /etc/fstab ] && cat /etc/fstab

# ---------- DOCKER / CONTAINERS ----------
hdr "Container indicators"
[ -e /.dockerenv ] && warn "/.dockerenv present — inside Docker"
[ -f /proc/1/cgroup ] && grep -E 'docker|kubepods|containerd|lxc' /proc/1/cgroup
[ -S /var/run/docker.sock ] && {
    ls -la /var/run/docker.sock
    [ -r /var/run/docker.sock ] && hit "docker.sock READABLE — docker run -v /:/mnt --rm -it alpine chroot /mnt"
}

# ---------- INTERESTING WRITABLE BINARIES ----------
hdr "Service files & writable binaries in /etc/systemd"
find /etc/systemd /usr/lib/systemd -name '*.service' -writable 2>/dev/null | head -20
find /etc/init.d -type f -writable 2>/dev/null | head -20

# ---------- BACKUPS ----------
hdr "Backup files (.bak/.old/.swp/.save)"
find / -xdev \( -name '*.bak' -o -name '*.old' -o -name '*.swp' -o -name '*.save' \) -readable 2>/dev/null | head -30

# ---------- THICK-CLIENT / WORKSTATION APPS ----------
# Inlined per ADR-002 D1 (no source/dot-import so bulk-enum can stdin-pipe this
# file). Full standalone: standalones/linux/thickclient-hunt.sh. READ-ONLY:
# presence + path + why-it-matters; THICKCLIENT-* markers are report.py-graded.
hdr "THICK-CLIENT / WORKSTATION APPS (creds/config at rest)"
TC_HOME="${HOME:-/root}"
tc_present() { [ -e "$2" ] && hit "$1: $2 — $3"; }

# SSH/SFTP client material (private keys + FileZilla cleartext site manager)
tc_present "THICKCLIENT-SSHKEY-AT-REST" "$TC_HOME/.ssh/config" \
  "ssh_config — Host aliases/IdentityFile/ProxyJump map to reachable hosts"
for k in "$TC_HOME"/.ssh/id_* "$TC_HOME"/.ssh/*.pem; do
  [ -f "$k" ] || continue
  case "$k" in *.pub) continue ;; esac
  if head -c 40 "$k" 2>/dev/null | grep -q 'PRIVATE KEY'; then
    enc="unencrypted"; grep -q 'ENCRYPTED' "$k" 2>/dev/null && enc="passphrase-encrypted"
    hit "THICKCLIENT-SSHKEY-AT-REST: $k — private key ($enc); feed to ssh-key-triage.py"
  fi
done
for fz in "$TC_HOME/.config/filezilla/sitemanager.xml" "$TC_HOME/.filezilla/sitemanager.xml"; do
  tc_present "THICKCLIENT-SAVED-SESSION" "$fz" "FileZilla site manager — Host/User + Base64/cleartext Pass"
done

# VPN profiles
for v in "$TC_HOME/.config/openvpn" /etc/openvpn "$TC_HOME/.cisco" \
         "$TC_HOME/.config/wireguard" /etc/wireguard \
         /etc/NetworkManager/system-connections; do
  tc_present "THICKCLIENT-VPN-PROFILE" "$v" "VPN/network profile store — server, certs, sometimes inline creds"
done
find "$TC_HOME" -maxdepth 3 -name '*.ovpn' 2>/dev/null | head -10 | while IFS= read -r f; do
  hit "THICKCLIENT-VPN-PROFILE: $f — OpenVPN profile in user tree"
done

# DB client creds (cleartext .pgpass/.my.cnf, DBeaver static-key store)
for db in "$TC_HOME/.pgpass" "$TC_HOME/.my.cnf" "$TC_HOME/.mylogin.cnf"; do
  tc_present "THICKCLIENT-CRED-AT-REST" "$db" "DB client cleartext credential store"
done
find "$TC_HOME/.local/share/DBeaverData" "$TC_HOME/.config/DBeaverData" \
     -maxdepth 4 -name 'credentials-config.json' 2>/dev/null | head -3 | while IFS= read -r f; do
  hit "THICKCLIENT-CRED-AT-REST: $f — DBeaver creds (AES/static-key, decryptable offline)"
done

# Browser saved-login stores (presence only, no decryption)
for b in "$TC_HOME/.config/google-chrome" "$TC_HOME/.config/chromium" \
         "$TC_HOME/.config/microsoft-edge" "$TC_HOME/.config/BraveSoftware"; do
  [ -d "$b" ] || continue
  find "$b" -maxdepth 3 -name 'Login Data' 2>/dev/null | head -5 | while IFS= read -r f; do
    hit "THICKCLIENT-BROWSER-LOGINDB: $f — Chromium Login Data (AES-GCM key in Local State/keyring)"
  done
done
find "$TC_HOME/.mozilla/firefox" -maxdepth 2 -name 'logins.json' 2>/dev/null | head -5 | while IFS= read -r f; do
  hit "THICKCLIENT-BROWSER-LOGINDB: $f — Firefox saved logins (NSS key4.db + this file)"
done

# Keyrings + Electron apps
for kr in "$TC_HOME/.local/share/keyrings" "$TC_HOME/.local/share/kwalletd" "$TC_HOME/.password-store"; do
  tc_present "THICKCLIENT-KEYRING" "$kr" "local secret store — unlocks with the user's login key"
done
for e in /opt/*/resources/app.asar "$TC_HOME"/.config/*/resources/app.asar; do
  [ -f "$e" ] && hit "THICKCLIENT-ELECTRON: $e — Electron app.asar; asar extract for embedded API keys"
done

# Hardcoded secrets in ~/.config app trees (bounded; generic cred rule also fires)
find "$TC_HOME/.config" -maxdepth 4 -type f \
     \( -name '*.ini' -o -name '*.xml' -o -name '*.json' -o -name '*.conf' -o -name '*.yaml' -o -name '*.yml' \) 2>/dev/null |
  head -150 | while IFS= read -r f; do
    [ -r "$f" ] || continue
    grep -aiHE '(pass(word|wd)?|secret|api[_-]?key|token|connection[_-]?string)[[:space:]]*[=:][[:space:]]*[^[:space:]"'"'"']{4,}' "$f" 2>/dev/null | head -2
  done | head -30 | while IFS= read -r line; do hit "THICKCLIENT-CONFIG-SECRET: $line"; done

# ---------- DONE ----------
hdr "DONE"
echo "Run with -v for more detail; consider also linpeas / lse / linenum.sh for deeper coverage."
echo "Thick-client detail: standalones/linux/thickclient-hunt.sh"
