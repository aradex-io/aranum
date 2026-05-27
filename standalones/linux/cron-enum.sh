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
echo "=== systemd timers (modern cron) ==="
systemctl list-timers --all 2>/dev/null | head -40
