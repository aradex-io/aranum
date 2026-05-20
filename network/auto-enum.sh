#!/usr/bin/env bash
# auto-enum.sh — orchestrate per-service enumeration from nmap output.
#
# Reads nmap output (.xml/.gnmap/.nmap), buckets hosts by service, then runs
# the matching enum-<service>.sh dispatcher with credentials passed through.
#
# Output layout:
#     <outdir>/
#       inventory.json
#       services.txt
#       <service>/<ip>_<port>/*.{txt,xml,json}
#
# All dispatchers are idempotent: rerunning overwrites their own output dirs.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="$SCRIPT_DIR/nmap-parse.py"

# ---------- defaults ----------
INPUT=""
OUTDIR="./enum-results"
USER=""
PASS=""
NTLM_HASH=""
DOMAIN=""
DC_IP=""
PARALLEL=4
ONLY=""
EXCLUDE=""
DRY_RUN=0

usage() {
    cat <<EOF
Usage: $0 -i <nmap-output> [-o <outdir>] [options]

Required:
  -i, --input         nmap output file (.xml | .gnmap | .nmap)

Output:
  -o, --output        results dir (default: ./enum-results)

Auth (optional — falls back to unauth):
  -u, --user          username (CORP\\\\user or user@domain or user)
  -p, --password      password
  -H, --hash          NTLM hash (use instead of password)
  -d, --domain        domain (e.g. CORP.LOCAL)
  --dc-ip             domain controller IP (for Kerberos enum)

Tuning:
  -P, --parallel N    parallel hosts per service (default: 4)
  --only LIST         comma-sep services to run (e.g. smb,ldap,winrm)
  --exclude LIST      comma-sep services to skip
  --dry-run           print plan, don't execute

  -h, --help          show this help

Examples:
  $0 -i scan.xml -o /tmp/enum -u 'CORP\\jay' -p 'Hunter2!' -d CORP.LOCAL --dc-ip 10.0.0.1
  $0 -i scan.gnmap --only smb,winrm
  $0 -i scan.xml -u jay -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

Env knobs (pass-through to dispatchers):
  NO_NUCLEI=1           skip nuclei in http/unknown dispatchers
  NO_FFUF=1             skip ffuf in http dispatcher
  NO_WHATWEB=1          skip whatweb
  WEB_PROBE_ONLY=1      http: httpx-only alive check (implies NO_NUCLEI/NO_FFUF/NO_WHATWEB)
  RUN_NIKTO=1           enable nikto (off by default — slow)
  NUCLEI_TIMEOUT=600    hard wall-clock cap on nuclei (default 600s)
  NUCLEI_RATE=150       nuclei -rate-limit (default 150)
  NUCLEI_TEMPLATES=DIR  override nuclei templates dir (default ~/nuclei-templates)
EOF
}

# ---------- arg parsing ----------
while [ $# -gt 0 ]; do
    case "$1" in
        -i|--input)     INPUT="$2"; shift 2 ;;
        -o|--output)    OUTDIR="$2"; shift 2 ;;
        -u|--user)      USER="$2"; shift 2 ;;
        -p|--password)  PASS="$2"; shift 2 ;;
        -H|--hash)      NTLM_HASH="$2"; shift 2 ;;
        -d|--domain)    DOMAIN="$2"; shift 2 ;;
        --dc-ip)        DC_IP="$2"; shift 2 ;;
        -P|--parallel)  PARALLEL="$2"; shift 2 ;;
        --only)         ONLY="$2"; shift 2 ;;
        --exclude)      EXCLUDE="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "unknown arg: $1"; usage; exit 1 ;;
    esac
done

[ -z "$INPUT" ] && { usage; exit 1; }
[ ! -f "$INPUT" ] && { echo "input not found: $INPUT"; exit 2; }
[ ! -x "$PARSER" ] && chmod +x "$PARSER" 2>/dev/null

mkdir -p "$OUTDIR"

# Export auth so dispatchers see them
export ENUM_USER="$USER" ENUM_PASS="$PASS" ENUM_HASH="$NTLM_HASH"
export ENUM_DOMAIN="$DOMAIN" ENUM_DC_IP="$DC_IP" ENUM_PARALLEL="$PARALLEL"

# ---------- 1. parse ----------
echo "[*] Parsing $INPUT ..."
python3 "$PARSER" "$INPUT" --json > "$OUTDIR/inventory.json" || {
    echo "[!] parser failed"; exit 3
}

# Quick summary
python3 - "$OUTDIR/inventory.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["summary"]
print(f"  Hosts up        : {s['hosts']}")
print(f"  Open ports      : {s['open_ports']}")
print(f"  Service buckets :")
for cat, ips in sorted(s["categories"].items(), key=lambda x: -len(x[1])):
    print(f"    {cat:10s}  {len(ips):4d}")
PY

# ---------- 2. pick services to run ----------
ALL_CATEGORIES=$(python3 - "$OUTDIR/inventory.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cats = list(d["summary"]["categories"].keys())
if d["summary"].get("unknown"):
    cats.append("unknown")
print(" ".join(sorted(cats)))
PY
)

if [ -n "$ONLY" ]; then
    SERVICES=$(echo "$ONLY" | tr ',' ' ')
else
    SERVICES="$ALL_CATEGORIES"
fi
if [ -n "$EXCLUDE" ]; then
    for x in $(echo "$EXCLUDE" | tr ',' ' '); do
        SERVICES=$(echo "$SERVICES" | tr ' ' '\n' | grep -v "^$x$" | tr '\n' ' ')
    done
fi
echo
echo "[*] Will run: $SERVICES"
echo "$SERVICES" | tr ' ' '\n' > "$OUTDIR/services.txt"

# ---------- 3. dispatch ----------
run_dispatcher() {
    local svc="$1"
    local script="$SCRIPT_DIR/enum-${svc}.sh"
    if [ ! -f "$script" ]; then
        echo "[-] no dispatcher for $svc (looked for $script)"; return
    fi
    chmod +x "$script" 2>/dev/null

    local target_file="$OUTDIR/_targets_${svc}.txt"
    if [ "$svc" = "unknown" ]; then
        python3 "$PARSER" "$INPUT" --unknown | sort -u > "$target_file"
    else
        python3 "$PARSER" "$INPUT" --service "$svc" | sort -u > "$target_file"
    fi
    local n; n=$(wc -l < "$target_file")
    [ "$n" -eq 0 ] && { rm -f "$target_file"; return; }
    echo "[*] Service: $svc ($n targets)"
    if [ "$DRY_RUN" = "1" ]; then
        echo "    DRY: $script --targets $target_file --output $OUTDIR/$svc"
        return
    fi
    mkdir -p "$OUTDIR/$svc"
    bash "$script" --targets "$target_file" --output "$OUTDIR/$svc" \
         2>&1 | tee "$OUTDIR/$svc/_dispatcher.log"
}

for svc in $SERVICES; do
    run_dispatcher "$svc"
done

# ---------- 4. summary ----------
echo
echo "=== Enumeration complete ==="
echo "Results: $OUTDIR/"
find "$OUTDIR" -maxdepth 2 -type d | sed "s|$OUTDIR|.|"
