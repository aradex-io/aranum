#!/usr/bin/env bash
# thickclient-hunt.sh — Linux workstation / thick-client credential & config
# enumerator. READ-ONLY: reports presence + path + why-it-matters. Never
# decrypts, exfiltrates, or writes to disk (CLAUDE.md §9).
#
# Complements linenum-fast.sh (system privesc) with the "desktop workstation
# with piles of GUI/custom apps and saved connection profiles" surface:
# SSH/SFTP clients, VPN profiles, DB clients, browser login stores, Electron
# apps, keyrings, custom .desktop launchers, and hardcoded secrets in app
# config trees.
#
# Self-contained per ADR-002 D1 (no source/dot-import) so bulk-enum can
# stdin-pipe it. Findings go to stdout in the linenum-fast [+]/[!] style so
# report.py ingests them. New finding-class markers are UPPERCASE-prefixed
# (THICKCLIENT-*) and stable across runs.
#
# Usage: ./thickclient-hunt.sh [-v] [-o outfile]

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

hdr()  { printf "\n%s===[ %s ]===%s\n" "$C_HDR" "$1" "$C_RST"; }
hit()  { printf "%s[+]%s %s\n" "$C_HIT" "$C_RST" "$1"; }
warn() { printf "%s[!]%s %s\n" "$C_WARN" "$C_RST" "$1"; }
miss() { [ "$VERBOSE" = "1" ] && printf "[-] %s\n" "$1"; return 0; }

# Emit a presence finding: hit "MARKER: <path> — <why>" iff path exists.
present() {
  local marker="$1" path="$2" why="$3"
  if [ -e "$path" ]; then hit "$marker: $path — $why"; return 0; fi
  return 1
}

# Cap directory-tree greps so a huge $HOME never hangs a piped bulk run.
GREP_MAX_LINES=40
FIND_MAX=200

# Secret patterns for config-tree scans. Deliberately conservative so the
# generic report.py cred rule (password|secret|api_key|token = value) also
# fires on ini/xml lines.
SECRET_RE='(pass(word|wd)?|secret|api[_-]?key|token|connection[_-]?string|aws_secret|private[_-]?key)[[:space:]]*[=:]'

TARGET_HOME="${HOME:-/root}"

# ---------- GUI APP INVENTORY ----------
hdr "THICK-CLIENT APP INVENTORY"
# Add-on / third-party GUI app dirs (presence/name only). Distro-default
# /usr/share/applications is deliberately excluded — too noisy, no signal.
for d in /opt /var/lib/flatpak/app "$TARGET_HOME/.local/share/flatpak/app" /snap; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -mindepth 1 2>/dev/null | head -"$FIND_MAX" | while IFS= read -r app; do
    hit "THICKCLIENT-APP: $(basename "$app") — installed under $d"
  done
done
# Running GUI processes (X/Wayland clients) — window-bearing binaries.
if command -v ps >/dev/null 2>&1; then
  ps -eo comm= 2>/dev/null | sort -u | grep -Ei \
    'chrome|chromium|firefox|electron|code|slack|discord|teams|thunderbird|dbeaver|filezilla|remmina|putty|keepass|bitwarden|anydesk|teamviewer|mysql-workbench|pgadmin' \
    2>/dev/null | head -30 | while IFS= read -r p; do
      hit "THICKCLIENT-APP: process '$p' running — GUI client with likely saved sessions/creds"
    done
fi

# ---------- SSH / SFTP CLIENTS ----------
hdr "SSH / SFTP CLIENT MATERIAL"
# OpenSSH client config + private keys at rest under this user.
present "THICKCLIENT-SSHKEY-AT-REST" "$TARGET_HOME/.ssh/config" \
  "ssh_config — Host aliases, IdentityFile paths, ProxyJump map to reachable hosts"
for k in "$TARGET_HOME"/.ssh/id_* "$TARGET_HOME"/.ssh/*.pem; do
  [ -f "$k" ] || continue
  case "$k" in *.pub) continue ;; esac
  if head -c 40 "$k" 2>/dev/null | grep -q 'PRIVATE KEY'; then
    enc="unencrypted"
    grep -q 'ENCRYPTED' "$k" 2>/dev/null && enc="passphrase-encrypted"
    hit "THICKCLIENT-SSHKEY-AT-REST: $k — private key ($enc); feed to ssh-key-triage.py"
  fi
done
# PuTTY-on-Linux + FileZilla (FileZilla stores creds in cleartext/base64!).
present "THICKCLIENT-SAVED-SESSION" "$TARGET_HOME/.putty/sessions" \
  "PuTTY saved sessions (hostnames/users, proxy creds)" && \
  { find "$TARGET_HOME/.putty/sessions" -maxdepth 1 -type f 2>/dev/null | head -20 | while IFS= read -r s; do echo "    session: $(basename "$s")"; done; }
for fz in "$TARGET_HOME/.config/filezilla/sitemanager.xml" \
          "$TARGET_HOME/.config/filezilla/recentservers.xml" \
          "$TARGET_HOME/.filezilla/sitemanager.xml"; do
  present "THICKCLIENT-SAVED-SESSION" "$fz" \
    "FileZilla site manager — stores Host/User and Base64/cleartext Pass" && \
    grep -aoE '<(Host|User|Pass|Port)>[^<]*</(Host|User|Pass|Port)>' "$fz" 2>/dev/null | head -"$GREP_MAX_LINES" | sed 's/^/    /'
done

# ---------- VPN PROFILES ----------
hdr "VPN PROFILES"
for v in "$TARGET_HOME/.config/openvpn" /etc/openvpn "$TARGET_HOME/.cisco" \
         "$TARGET_HOME/.config/wireguard" /etc/wireguard \
         /etc/NetworkManager/system-connections \
         "$TARGET_HOME/.local/share/networkmanagement"; do
  present "THICKCLIENT-VPN-PROFILE" "$v" "VPN/network profile store — server, certs, sometimes inline creds" || continue
  find "$v" -maxdepth 2 -type f \( -name '*.ovpn' -o -name '*.conf' -o -name '*.nmconnection' -o -name '*.xml' \) 2>/dev/null | head -20 | while IFS= read -r f; do
    echo "    profile: $f"
    grep -aiE 'auth-user-pass|^PrivateKey|psk|password' "$f" 2>/dev/null | head -3 | sed 's/^/      /'
  done
done
find "$TARGET_HOME" -maxdepth 3 -name '*.ovpn' 2>/dev/null | head -20 | while IFS= read -r f; do
  hit "THICKCLIENT-VPN-PROFILE: $f — OpenVPN profile in user tree"
done

# ---------- DATABASE CLIENTS ----------
hdr "DATABASE CLIENT CREDENTIALS"
for db in "$TARGET_HOME/.pgpass" "$TARGET_HOME/.my.cnf" "$TARGET_HOME/.mylogin.cnf" \
          "$TARGET_HOME/.dbeaver" "$TARGET_HOME/.local/share/DBeaverData" \
          "$TARGET_HOME/.config/DBeaverData" "$TARGET_HOME/.mongorc.js" \
          "$TARGET_HOME/.config/pgadmin"; do
  present "THICKCLIENT-CRED-AT-REST" "$db" "DB client credential/session store"
done
# DBeaver credentials-config.json (AES with a static key — decryptable offline).
find "$TARGET_HOME/.local/share/DBeaverData" "$TARGET_HOME/.config/DBeaverData" \
     -maxdepth 4 -name 'credentials-config.json' 2>/dev/null | head -5 | while IFS= read -r f; do
  hit "THICKCLIENT-CRED-AT-REST: $f — DBeaver creds (AES/static-key, decryptable offline)"
done
# .pgpass / .my.cnf embed cleartext — surface the credential-bearing lines.
for pw in "$TARGET_HOME/.pgpass" "$TARGET_HOME/.my.cnf" "$TARGET_HOME/.mylogin.cnf"; do
  [ -r "$pw" ] || continue
  grep -aiE '^[^#].*(password|:)' "$pw" 2>/dev/null | head -10 | sed "s#^#    $pw: #"
done

# ---------- BROWSER LOGIN STORES ----------
hdr "BROWSER SAVED-LOGIN STORES (presence only)"
for b in "$TARGET_HOME/.config/google-chrome" "$TARGET_HOME/.config/chromium" \
         "$TARGET_HOME/.config/microsoft-edge" "$TARGET_HOME/.config/BraveSoftware"; do
  [ -d "$b" ] || continue
  find "$b" -maxdepth 3 -name 'Login Data' 2>/dev/null | head -10 | while IFS= read -r f; do
    hit "THICKCLIENT-BROWSER-LOGINDB: $f — Chromium Login Data (AES-GCM, key in 'Local State'/keyring)"
  done
done
find "$TARGET_HOME/.mozilla/firefox" -maxdepth 2 -name 'logins.json' 2>/dev/null | head -10 | while IFS= read -r f; do
  hit "THICKCLIENT-BROWSER-LOGINDB: $f — Firefox saved logins (NSS key4.db/key3.db + this file)"
done

# ---------- KEYRINGS / SECRET STORES ----------
hdr "KEYRINGS / SECRET STORES"
for kr in "$TARGET_HOME/.local/share/keyrings" "$TARGET_HOME/.gnupg" \
          "$TARGET_HOME/.local/share/kwalletd" "$TARGET_HOME/.password-store"; do
  present "THICKCLIENT-KEYRING" "$kr" "local secret store — unlocks with the user's login/GPG key"
done

# ---------- ELECTRON APPS ----------
hdr "ELECTRON APPS"
for e in /opt/*/resources/app.asar /usr/lib/*/resources/app.asar \
         "$TARGET_HOME"/.config/*/resources/app.asar; do
  [ -f "$e" ] || continue
  hit "THICKCLIENT-ELECTRON: $e — Electron app.asar; unpack (asar extract) for embedded API keys/endpoints"
done

# ---------- CUSTOM .desktop LAUNCHERS ----------
hdr "CUSTOM .desktop LAUNCHERS"
for dd in "$TARGET_HOME/.local/share/applications" "$TARGET_HOME/.config/autostart"; do
  [ -d "$dd" ] || continue
  find "$dd" -maxdepth 1 -name '*.desktop' 2>/dev/null | head -30 | while IFS= read -r f; do
    exec_line=$(grep -aoE '^Exec=.*' "$f" 2>/dev/null | head -1)
    case "$exec_line" in
      *"$TARGET_HOME"*|*/tmp/*|*/opt/*|*/home/*)
        hit "THICKCLIENT-APP: $f runs '${exec_line#Exec=}' — custom/user-writable launcher target"
        ;;
      *) miss "$f: ${exec_line#Exec=}" ;;
    esac
  done
done

# ---------- HARDCODED SECRETS IN APP CONFIG TREES ----------
hdr "HARDCODED SECRETS IN APP CONFIG (~/.config, dotfiles)"
# Bounded scan: config files only, capped output.
{
  find "$TARGET_HOME/.config" -maxdepth 4 -type f \
       \( -name '*.ini' -o -name '*.xml' -o -name '*.json' -o -name '*.conf' \
          -o -name '*.yaml' -o -name '*.yml' -o -name '*.config' \) 2>/dev/null | head -"$FIND_MAX"
  ls -1 "$TARGET_HOME"/.*rc 2>/dev/null
} | while IFS= read -r f; do
  [ -r "$f" ] || continue
  grep -aiHE "$SECRET_RE" "$f" 2>/dev/null | grep -aivE 'password[[:space:]]*[=:][[:space:]]*(\{|\$|""|''|null|false|true|0)?[[:space:]]*$' | head -3 | while IFS= read -r line; do
    hit "THICKCLIENT-CONFIG-SECRET: $line"
  done
done | head -"$GREP_MAX_LINES"

# ---------- DONE ----------
hdr "DONE"
echo "Read-only thick-client sweep complete. Feed THICKCLIENT-SSHKEY-AT-REST keys to ssh-key-triage.py; decrypt browser/DB/keyring stores operator-side only."
exit 0
