#!/usr/bin/env bash
# cron-enum.sh — system + user cron, flagging writable scripts they invoke.

set -u

echo "=== /etc/crontab ==="
cat /etc/crontab 2>/dev/null

echo
echo "=== /etc/cron.d/* ==="
for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "--- $f ---"; cat "$f"; }; done

echo
echo "=== /etc/cron.{hourly,daily,weekly,monthly} ==="
ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null

echo
echo "=== /var/spool/cron/* (per-user) ==="
ls -la /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null
for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [ -r "$f" ] && { echo "--- $f ---"; cat "$f"; }
done

echo
echo "=== Anacron ==="
cat /etc/anacrontab 2>/dev/null

echo
echo "=== Writable scripts referenced by cron ==="
SCRIPTS=$(grep -horE '/[^ ]+\.(sh|py|pl|rb)' /etc/crontab /etc/cron.d/* /etc/anacrontab 2>/dev/null | sort -u)
for s in $SCRIPTS; do
    [ -e "$s" ] || continue
    if [ -w "$s" ]; then printf "\033[1;32m[+] WRITABLE:\033[0m %s\n" "$s"; else echo "    $s"; fi
done

echo
echo "=== Writable files in cron.{daily,hourly,weekly,monthly} (root-run) ==="
for dir in /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*; do
        [ -e "$f" ] || continue
        [ -w "$f" ] && printf "\033[1;32m[+] WRITABLE cron.d:\033[0m %s\n" "$f"
    done
done

echo
echo "=== at jobs + cron/at access control ==="
for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [ -e "$f" ] && { echo "  $f:"; sed 's/^/    /' "$f" 2>/dev/null; }
done
ls -la /var/spool/cron/atjobs /var/spool/at 2>/dev/null | grep -vE '^total|^d' | head -20
command -v atq >/dev/null 2>&1 && { echo "  atq:"; atq 2>/dev/null | sed 's/^/    /'; }

echo
echo "=== cron command wildcard-injection candidates ==="
# Unquoted globs run by root cron (tar *, chown -R, rsync) are classic wildcard
# injection vectors when the operator can drop files in the working dir.
grep -horE '(tar|rsync|chown|chmod|7z|zip)[^#]*[* ]' /etc/crontab /etc/cron.d/* /etc/cron.daily/* 2>/dev/null \
    | grep -E '\*' | sed 's/^/  /' | head -20

echo
echo "=== systemd timers (modern cron) ==="
systemctl list-timers --all 2>/dev/null | head -40
