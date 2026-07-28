#!/usr/bin/env bash
# deps-check.sh — verify enumeration tools.
set -uo pipefail

R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; N="\033[0m"
[ -t 1 ] || { R=""; G=""; Y=""; N=""; }

# Local copy of aranumtoolkit/network/_lib.sh::have — this script is invoked stand-alone
# (e.g. before any dispatcher is sourced), so we cannot rely on _lib.sh.
have() { command -v "$1" >/dev/null 2>&1; }

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
check parallel           rec  # load-bearing for bulk-enum-linux.sh / auto-enum.sh / enum-smb.sh host fan-out
check psql               opt  # enum-postgres.sh credentialed recon (pg_roles)
check mysql              opt  # enum-mysql.sh credentialed recon (mysql.user / secure_file_priv)
check swaks              opt  # standalones/smtp/smtp-phish-send.sh
check lmutil             opt  # enum-flexnet.sh — FlexNet/FLEXlm `lmstat -a`
check amap               opt  # enum-unknown.sh fallback application fingerprint

# K.1 — pywinrm Python package (only required for bulk-enum-windows.py)
if python3 -c "import winrm" 2>/dev/null; then
    v=$(python3 -c "import winrm; print(getattr(winrm, '__version__', '?'))" 2>/dev/null || true)
    printf "${G}[+]${N} %-22s pywinrm %s (Python)\n" "pywinrm" "$v"
else
    printf "[ ] %-22s (optional Python pkg — pip install pywinrm; required for bulk-enum-windows.py)\n" "pywinrm"
fi

# ADR-006 — impacket enables bulk-enum-windows.py's smb transport (wmiexec).
if python3 -c "import impacket" 2>/dev/null; then
    v=$(python3 -c "import impacket; print(getattr(impacket, '__version__', '?'))" 2>/dev/null || true)
    printf "${G}[+]${N} %-22s impacket %s (Python)\n" "impacket" "$v"
else
    printf "[ ] %-22s (optional Python pkg — pip install impacket; bulk-enum-windows.py smb transport)\n" "impacket"
fi

# ADR-006 — paramiko is the preferred backend for ssh-key-triage.py (ssh-keygen fallback).
if python3 -c "import paramiko" 2>/dev/null; then
    v=$(python3 -c "import paramiko; print(getattr(paramiko, '__version__', '?'))" 2>/dev/null || true)
    printf "${G}[+]${N} %-22s paramiko %s (Python)\n" "paramiko" "$v"
else
    printf "[ ] %-22s (optional Python pkg — pip install 'paramiko>=2.7'; ssh-key-triage.py falls back to ssh-keygen)\n" "paramiko"
fi

echo
echo "=== AD DEPTH (iteration D1 — optional) ==="
check bloodhound-python  opt
check bloodhound.py      opt
check certipy            opt
check certipy-ad         opt
check petitpotam.py      opt
check pwsh               opt   # for standalones/windows/*.ps1 AST parse / smoke 11h

# Python: defusedxml hardens nmap-parse.py against XXE / billion-laughs.
# Without it, nmap-parse.py uses a hardened stdlib fallback that pre-scans
# the prolog for dangerous DTD constructs. defusedxml is strictly preferred.
if python3 -c "import defusedxml" 2>/dev/null; then
    v=$(python3 -c "import defusedxml; print(defusedxml.__version__)" 2>/dev/null || true)
    printf "${G}[+]${N} %-22s defusedxml %s (Python)\n" "defusedxml" "$v"
else
    printf "[ ] %-22s (optional Python pkg — pip install defusedxml)\n" "defusedxml"
fi

# Iteration H — standalones/jabber/ helpers. Stdlib-only per ADR-001 D4, so no new pip
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
echo "=== E1 TIER-1 DISPATCHERS (iteration E1) ==="
# Required for the new dispatchers; rsync is commonly available but worth confirming.
check rsync         req
# mosquitto_sub is from the mosquitto-clients package (Fedora: dnf install mosquitto)
check mosquitto_sub rec  mosquitto_sub
# tnscmd10g — optional Oracle TNS command tool (part of tnscmd10g package or manual install)
check tnscmd10g     opt
# svmap — SIPVicious scanner (optional; pip install sipvicious or pipx install sipvicious)
check svmap         opt
# kafkacat / kcat — optional Kafka enumeration tool (reserved for Tier 2a dispatchers)
check kafkacat      opt
check kcat          opt

echo
echo "=== E2 TIER-2A DISPATCHERS (iteration E2) ==="
# At least one of {kcat, kafkacat} required for enum-kafka.sh
if have kcat || have kafkacat; then
    if have kcat; then
        v=$(kcat -V 2>&1 | head -1 || true)
        printf "${G}[+]${N} %-22s %s\n" "kcat" "$v"
    fi
    if have kafkacat; then
        v=$(kafkacat -V 2>&1 | head -1 || true)
        printf "${G}[+]${N} %-22s %s\n" "kafkacat" "$v"
    fi
else
    printf "${Y}[?]${N} %-22s (one of kcat/kafkacat required for enum-kafka.sh)\n" "kcat/kafkacat"
fi
# cqlsh — optional; improves Cassandra anonymous CQL detection beyond nmap
check cqlsh           opt
# At least one of {nbtscan, nmblookup} for enum-netbios-ns.sh
if have nbtscan || have nmblookup; then
    have nbtscan   && check nbtscan    opt
    have nmblookup && check nmblookup  opt
else
    printf "${Y}[?]${N} %-22s (one of nbtscan/nmblookup required for enum-netbios-ns.sh)\n" "nbtscan/nmblookup"
fi
# At least one of {impacket-rpcdump, rpcdump.py, rpcclient} for enum-msrpc.sh
# Note: rpcclient is already checked in REQUIRED above (from samba/winbind);
# just surface the impacket alternatives here.
if have impacket-rpcdump || have rpcdump.py; then
    have impacket-rpcdump && check impacket-rpcdump  opt
    have rpcdump.py       && check rpcdump.py        opt
else
    printf "[ ] %-22s (optional — impacket-rpcdump or rpcdump.py extends enum-msrpc.sh beyond rpcclient/nmap)\n" "impacket-rpcdump"
fi

echo
echo "=== E4 OPT-IN AGGRESSIVE PROBES (iteration E4) ==="
# These dispatchers are disabled by default and require explicit --ike / --slp /
# --radius flags (or --aggressive). Each dispatcher also env-gates on ENUM_RUN_X=1.
# ike-scan: IKEv1/v2 prober. Fedora: dnf install ike-scan; Debian: apt install ike-scan
check ike-scan       opt
# nmap: already in REQUIRED above; confirmed here for the NSE-based SLP dispatcher.
# enum-slp.sh uses nmap NSE scripts (slp-discovery, slp-info) rather than slptool
# because slptool does not reliably take direct host:port arguments across distros.
check nmap           req
# python3: already in REQUIRED above; confirmed here — enum-radius.sh uses stdlib only.
check python3        req

echo
echo "=== T4 OT/ICS READ-SIDE PROBES (iteration T4) ==="
# OT dispatchers are NEVER auto-routed. They live in standalones/ot/ and require both the
# --ics-confirm flag on standalones/ot/ot-enum.sh AND the typed-confirmation prompt
# (ICS-CONFIRMED). Tools used:
#   - nmap NSE: modbus-discover, s7-info, enip-info, bacnet-info, opcua-info,
#     dnp3-info — already required above; confirmed here for completeness.
#   - python3 stdlib socket — already required above; used by standalones/ot/enum-iec104.sh
#     for the TESTFR (act) APDU probe.
# Anchor: aranumtoolkit/docs/ADR-005-22MAY2026-ot-ics-safety-scope.md
check nmap           req
check python3        req
cat <<'EOF'
[i] T4 OT/ICS dispatchers require typed-confirmation gate (ICS-CONFIRMED).
    Read aranumtoolkit/docs/ADR-005-22MAY2026-ot-ics-safety-scope.md before invoking any
    script in standalones/ot/. NEVER set OT_CONFIRMED=1 directly unless you have
    confirmed engagement OT scope in writing. Use:

        bash standalones/ot/ot-enum.sh --ics-confirm --targets ot-targets.txt --output ./out

EOF

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
