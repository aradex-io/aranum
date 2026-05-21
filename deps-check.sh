#!/usr/bin/env bash
# deps-check.sh — verify enumeration tools.
set -u

R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; N="\033[0m"
[ -t 1 ] || { R=""; G=""; Y=""; N=""; }

check() {
    name="$1"; level="$2"; binary="${3:-$1}"
    if command -v "$binary" >/dev/null 2>&1; then
        v=$($binary --version 2>&1 | head -1 || true)
        printf "${G}[+]${N} %-22s %s\n" "$name" "$v"
    else
        case "$level" in
            req)  printf "${R}[!]${N} %-22s (REQUIRED — install)\n" "$name" ;;
            rec)  printf "${Y}[?]${N} %-22s (recommended)\n" "$name" ;;
            opt)  printf "[ ] %-22s (optional)\n" "$name" ;;
        esac
    fi
}

# E.7 — Version-floor check. Compares `printf '%s\n%s\n' "$a" "$b" | sort -V`
# to determine if the installed version meets the minimum required.
# Usage: version_floor <name> <binary> <min-version> [version-flag-pattern]
version_floor() {
    local name="$1" binary="$2" min="$3" pattern="${4:-[0-9]+\.[0-9]+(\.[0-9]+)?}"
    command -v "$binary" >/dev/null 2>&1 || return 0  # absence already flagged by check()
    local installed
    installed=$("$binary" --version 2>&1 | grep -oE "$pattern" | head -1)
    if [ -z "$installed" ]; then
        printf "  ${Y}?${N}  %-22s installed but version not parseable; manual check\n" "$name"
        return 0
    fi
    local lowest
    lowest=$(printf '%s\n%s\n' "$installed" "$min" | sort -V | head -1)
    if [ "$lowest" = "$min" ]; then
        printf "  ${G}>=${N}  %-22s %s (>= %s required)\n" "$name" "$installed" "$min"
    else
        printf "  ${R}<${N}  %-22s %s (FLOOR %s — upgrade)\n" "$name" "$installed" "$min"
    fi
}

echo "=== REQUIRED ==="
check python3   req
check nmap      req
check curl      req
check dig       req bind-utils-or-dig
check ldapsearch req ldapsearch
check smbclient req
check rpcclient req
check showmount req

echo
echo "=== HIGHLY RECOMMENDED ==="
check nxc                rec  nxc
check netexec            rec  netexec
check enum4linux-ng      rec
check kerbrute           rec
check ssh-audit          rec
check whatweb            rec
check httpx              rec
check ffuf               rec
check onesixtyone        rec
check snmpwalk           rec
check smbmap             rec
check GetUserSPNs.py     rec
check GetNPUsers.py      rec

echo
echo "=== OPTIONAL ==="
check nuclei             opt
check nikto              opt
check evil-winrm         opt
check mssqlclient.py     opt
check rdp-sec-check.pl   opt
check redis-cli          opt
check dnsrecon           opt
check shellcheck         opt  # G.6 — lint gate for `make lint`; pip install shellcheck-py also works
check sshpass            opt  # J.1 — only required for `bulk-enum-linux.sh --pass`; ssh-agent / --key are preferred

# Python: defusedxml hardens nmap-parse.py against XXE / billion-laughs.
# Without it, nmap-parse.py uses a hardened stdlib fallback that pre-scans
# the prolog for dangerous DTD constructs. defusedxml is strictly preferred.
if python3 -c "import defusedxml" 2>/dev/null; then
    v=$(python3 -c "import defusedxml; print(defusedxml.__version__)" 2>/dev/null || true)
    printf "${G}[+]${N} %-22s defusedxml %s (Python)\n" "defusedxml" "$v"
else
    printf "[ ] %-22s (optional Python pkg — pip install defusedxml)\n" "defusedxml"
fi

# Iteration H — jabber/ helpers. Stdlib-only per ADR-001 D4, so no new pip
# deps; we just sanity-check the system tools the dispatcher leans on.
echo
echo "=== JABBER / XMPP (iteration H) ==="
check nc        rec
check openssl   rec
# Python stdlib check — these MUST be importable for jabber-* scripts to run
for mod in socket ssl base64 hashlib hmac urllib.request xml.etree.ElementTree; do
    if python3 -c "import $mod" 2>/dev/null; then
        printf "${G}[+]${N} %-22s (stdlib)\n" "python3:$mod"
    else
        printf "${R}[!]${N} %-22s (REQUIRED stdlib module missing — broken Python install?)\n" "python3:$mod"
    fi
done

echo
echo "=== VERSION FLOORS (iteration E.7) ==="
echo "Older tool versions miss recent features the dispatchers rely on."
version_floor "nxc"               nxc               1.2.0
version_floor "netexec"           netexec           1.2.0
version_floor "kerbrute"          kerbrute          1.0.3   "v[0-9]+\.[0-9]+\.[0-9]+"
version_floor "nuclei"            nuclei            3.2.0
version_floor "ffuf"              ffuf              2.0.0
version_floor "httpx"             httpx             1.6.0
version_floor "redis-cli"         redis-cli         7.0.0
version_floor "mongosh"           mongosh           2.0.0
# Impacket scripts use the Python package version, not a binary flag:
if python3 -c "import impacket" 2>/dev/null; then
    iv=$(python3 -c "import impacket; print(impacket.version.VER_MAJOR if False else impacket.__version__)" 2>/dev/null \
        || python3 -c "from importlib.metadata import version as v; print(v('impacket'))" 2>/dev/null)
    if [ -n "$iv" ]; then
        lowest=$(printf '%s\n%s\n' "$iv" "0.11.0" | sort -V | head -1)
        if [ "$lowest" = "0.11.0" ]; then
            printf "  ${G}>=${N}  %-22s %s (>= 0.11.0 required)\n" "impacket" "$iv"
        else
            printf "  ${R}<${N}  %-22s %s (FLOOR 0.11.0 — pipx upgrade impacket)\n" "impacket" "$iv"
        fi
    fi
fi

echo
echo "Install hints (Fedora/Arch/Debian vary):"
cat <<'EOF'
  pipx install netexec                       # nxc
  pipx install enum4linux-ng
  pipx install impacket
  pip3 install ssh-audit
  go install github.com/ropnop/kerbrute@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/ffuf/ffuf/v2@latest
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  pip3 install defusedxml                   # XXE-hardened XML parsing
EOF
