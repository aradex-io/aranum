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
