#!/usr/bin/env bash
# sudo-enum.sh — sudo version + sudo -l interpretation.
# Calls out NOPASSWD / known-bad sudo versions / dangerous SETENV / dangerous binaries.

set -u

echo "=== sudo version ==="
sudo -V 2>/dev/null | head -3

# Keep the pN patchlevel — it is version-significant (e.g. the fix for several
# CVEs is a pN bump like 1.9.17p1) and sort -V orders it correctly.
VER=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)
echo "Parsed: $VER"

# ver_between LOW MID HIGH — true iff LOW <= MID <= HIGH under version sort.
ver_between() {
    [ -n "$2" ] || return 1
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && \
    [ "$(printf '%s\n%s\n' "$2" "$3" | sort -V | head -1)" = "$2" ]
}

cve_check() {
    [ -n "$VER" ] || { echo "(could not parse sudo version — skipping CVE signals)"; return; }
    # Baron Samedit — affected 1.8.2–1.8.31p2 and 1.9.0–1.9.5p1 (fixed 1.9.5p2).
    if ver_between 1.8.2 "$VER" 1.8.31p2 || ver_between 1.9.0 "$VER" 1.9.5p1; then
        echo "[!!] CVE-2021-3156 Baron Samedit candidate"
    fi
    # sudo -u#-1 — affected 1.8.0–1.8.27 (fixed 1.8.28).
    if ver_between 1.8.0 "$VER" 1.8.27; then
        echo "[!!] CVE-2019-14287 (sudo -u#-1) candidate"
    fi
    # sudoedit env-var escape — affected 1.8.0–1.9.12p1 (fixed 1.9.12p2).
    if ver_between 1.8.0 "$VER" 1.9.12p1; then
        echo "[!!] CVE-2023-22809 (sudoedit env-var escape) candidate"
    fi
    # CVE-2025-32463 — `sudo -R/--chroot` local root — affected 1.9.14–1.9.17 (fixed 1.9.17p1).
    if ver_between 1.9.14 "$VER" 1.9.17; then
        echo "[!!] CVE-2025-32463 (sudo --chroot local root) candidate"
    fi
    # CVE-2025-32462 — `sudo -h/--host` honors rules meant for other hosts — affected 1.8.8–1.9.17 (fixed 1.9.17p1).
    if ver_between 1.8.8 "$VER" 1.9.17; then
        echo "[!!] CVE-2025-32462 (sudo --host rule leak) candidate"
    fi
    echo "  (version-based signals — a distro may have backported the fix without bumping the version; confirm the package revision)"
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
