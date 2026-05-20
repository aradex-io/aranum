#!/usr/bin/env bash
# sudo-enum.sh — sudo version + sudo -l interpretation.
# Calls out NOPASSWD / known-bad sudo versions / dangerous SETENV / dangerous binaries.

set -u

echo "=== sudo version ==="
sudo -V 2>/dev/null | head -3

VER=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "Parsed: $VER"

cve_check() {
    case "$VER" in
        # Baron Samedit — affected: 1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1
        1.8.[2-9]|1.8.[12][0-9]|1.8.3[01]*|1.9.[0-4]|1.9.5p[01]) echo "[!!] CVE-2021-3156 Baron Samedit candidate" ;;
    esac
    case "$VER" in
        # sudo -u#-1
        1.8.[0-9]|1.8.1[0-9]|1.8.2[0-7]) echo "[!!] CVE-2019-14287 (sudo -u#-1) candidate" ;;
    esac
    case "$VER" in
        # CVE-2023-22809 — env var editor escape (1.8.0 - 1.9.12p1)
        1.8.*|1.9.[0-9]|1.9.1[01]|1.9.12*) echo "[!!] CVE-2023-22809 (sudoedit env-var escape) candidate" ;;
    esac
}
cve_check

echo
echo "=== sudo -l (no password) ==="
SUDO_L=$(sudo -n -l 2>/dev/null)
if [ -z "$SUDO_L" ]; then
    echo "(sudo -l requires password — try sudo -l after auth)"
    exit 0
fi
echo "$SUDO_L"

echo
echo "=== Flags ==="
echo "$SUDO_L" | grep -E 'NOPASSWD' && echo "  -> NOPASSWD found"
echo "$SUDO_L" | grep -E 'SETENV'   && echo "  -> SETENV — can set LD_PRELOAD / PYTHONPATH etc."
echo "$SUDO_L" | grep -E '!authenticate' && echo "  -> !authenticate found"

echo
echo "=== GTFOBins matches in allowed commands ==="
GTFO='vim|nano|less|more|man|find|nmap|awk|gawk|env|python|python3|perl|ruby|node|tar|cp|mv|tee|dd|ssh|scp|rsync|busybox|bash|sh|zsh|sed|expect|gdb|strace|ltrace|systemctl|service|apt|apt-get|yum|dnf|pip|pip3|gem|composer|crontab|docker|kubectl|tcpdump|zip|gzip|bzip2|xz'
echo "$SUDO_L" | grep -oE "/[A-Za-z0-9_./-]+\b" | sort -u | while read -r BIN; do
    NAME=$(basename "$BIN")
    if echo "$NAME" | grep -qE "^($GTFO)$"; then
        echo "  [+] $BIN — see https://gtfobins.github.io/gtfobins/$NAME/#sudo"
    fi
done

echo
echo "=== Wildcards / scripts in sudo allowed list (review for arg injection) ==="
echo "$SUDO_L" | grep -E '\*|\$|\.sh|\.py|\.pl|\.rb'
