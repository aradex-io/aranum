#!/usr/bin/env bash
# suid-gtfobins.sh — find SUID/SGID binaries and flag known-exploitable ones.
# Uses an offline GTFOBins list (subset, kept current as of 2026-05).

set -u

# Curated subset of GTFOBins SUID-exploitable binaries.
# DATA-PROVENANCE (see aranumtoolkit/docs/DATA-SOURCES.md):
#   dataset: gtfobins-suid-subset
#   source:  https://gtfobins.github.io/ (function=suid)
#   updated: 2026-05
GTFO_SUID="aa-exec ash awk base32 base64 bash busybox bzip2 cat chmod chown chroot cp csh cut date dash dd diff dmsetup docker easy_install ed emacs env eqn expand expect file find flock fmt fold gawk gdb git grep gzip head ionice jjs jq journalctl ksh ksshell ld.so less ln logsave lualatex luatex lwp-download make man mawk more mount mv nano nice nmap node nohup numfmt openvpn paste perl pico pip pr ptx pwsh python rbash readelf rev rlwrap rpm rsync rtorrent run-mailcap rvim screen script sed setarch setfacl setlock sftp shuf socat soelim sort split ssh ssh-keygen ssh-keyscan start-stop-daemon stdbuf strace strings sysctl systemctl tac tail taskset tclsh tdbtool tee telnet tftp tic time timeout tmux top ul unexpand uniq unshare update-alternatives uudecode uuencode vi view vigr vim vimdiff w3m watch wget whois wish xargs xelatex xetex xmodmap xmore xxd xz yash zip zsoelim zsh zstd"

echo "Scanning for SUID/SGID binaries (excluding common safe paths)..."

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    -not -path '/snap/*' \
    -not -path '/usr/lib/snapd/*' \
    -printf '%M %u %g %p\n' 2>/dev/null | sort -u | while read -r line; do
    BIN_PATH=$(echo "$line" | awk '{print $NF}')
    NAME=$(basename "$BIN_PATH")
    # case-insensitive check against curated list
    if echo " $GTFO_SUID " | grep -qiw "$NAME"; then
        printf "\033[1;32m[+] %s\033[0m  -> https://gtfobins.github.io/gtfobins/%s/#suid\n" "$line" "$NAME"
    else
        echo "    $line"
    fi
done

echo
echo "Note: also check the binary's resolved target (file <path>) — sometimes a"
echo "      shell wrapper around a vulnerable interpreter is the actual sink."
