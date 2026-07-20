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
RESUME=0
THROTTLE=0
THROTTLE_EXPLICIT_PARALLEL=0
PROFILE=""
PLAN_ONLY=0
PHASE_FILTER=""
QUEUE_FILE=""
SKIP_LOW_PRIORITY=""
# E4 — opt-in aggressive UDP services accumulator (space-separated)
AGGRESSIVE_ENABLED=""

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
  --resume            skip services that already have a .done marker
                      (set by a prior successful auto-enum.sh run)
  --throttle          gentle-mode for sensitive environments (OT/legacy/lab).
                      Sets ENUM_THROTTLE=1 and applies these defaults to ANY
                      knob the operator did NOT set explicitly:
                        ENUM_PARALLEL    1
                        NUCLEI_RATE      20
                        NO_FFUF          1
                        NO_NIKTO         1
                      Explicit CLI args win — e.g. -P 4 --throttle keeps -P 4
                      and warns. Use --dry-run --throttle to preview the
                      effective environment without scanning.
  --profile NAME      build/use aranumtoolkit/network/plan.py operator profile metadata
  --phase LIST        build/use planner phase filter (e.g. 1,2 or 1-3)
  --plan-only         write plan.json + queue.jsonl + guidance.json and exit
  --queue FILE        dispatch only services/targets present in an existing
                      planner queue.jsonl (dispatchers are still service-batch)
  --skip-low-priority N
                      with --profile/--phase/--queue, skip planner items below N

Opt-in aggressive probes (E4 — disabled by default):
  --ike               enable enum-ike.sh (UDP 500 — IKEv1 main-mode probe).
                      DOUBLY-AGGRESSIVE: aggressive-mode hash-harvest requires
                      also setting ENUM_IKE_AGGRESSIVE_MODE=1.
  --slp               enable enum-slp.sh (UDP 427 — SLP discovery).
                      Amplification surface; NOT for arbitrary internet hosts.
  --radius            enable enum-radius.sh (UDP 1812/1813 — RADIUS probe +
                      BlastRADIUS CVE-2024-3596 precondition check).
  --aggressive        shorthand for --ike --slp --radius (all three).

  OPSEC / aggressive probes: ike, slp, and radius are stripped from the
  auto-derived service list unless explicitly opted in via the flags above.
  Each dispatcher also checks an ENUM_RUN_X=1 env gate (set automatically
  when you use the flag); direct manual invocation without the env var will
  refuse to run and print a reminder.

  -h, --help          show this help

Examples:
  $0 -i scan.xml -o /tmp/enum -u 'CORP\\jay' -p 'Hunter2!' -d CORP.LOCAL --dc-ip 10.0.0.1
  $0 -i scan.gnmap --only smb,winrm
  $0 -i scan.xml -u jay -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  $0 -i scan.xml --ike --radius         (enable IKE + RADIUS aggressive probes)
  $0 -i scan.xml --aggressive           (enable all three aggressive UDP probes)

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
        -P|--parallel)  PARALLEL="$2"; THROTTLE_EXPLICIT_PARALLEL=1; shift 2 ;;
        --only)         ONLY="$2"; shift 2 ;;
        --exclude)      EXCLUDE="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=1; shift ;;
        --resume)       RESUME=1; shift ;;
        --throttle)     THROTTLE=1; shift ;;
        --profile)      PROFILE="$2"; shift 2 ;;
        --phase)        PHASE_FILTER="$2"; shift 2 ;;
        --plan-only)    PLAN_ONLY=1; shift ;;
        --queue)        QUEUE_FILE="$2"; shift 2 ;;
        --skip-low-priority) SKIP_LOW_PRIORITY="$2"; shift 2 ;;
        --ike)          AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED ike"; shift ;;
        --slp)          AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED slp"; shift ;;
        --radius)       AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED radius"; shift ;;
        --aggressive)   AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED ike slp radius"; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "unknown arg: $1"; usage; exit 1 ;;
    esac
done

[ -z "$INPUT" ] && { usage; exit 1; }
[ ! -f "$INPUT" ] && { echo "input not found: $INPUT"; exit 2; }
[ ! -x "$PARSER" ] && chmod +x "$PARSER" 2>/dev/null

mkdir -p "$OUTDIR"

# ---------- planner integration (operator-centric queue/guidance) ----------
# Default behavior is unchanged. The planner is invoked only when the operator
# asks for profile/phase/plan-only behavior, or when a queue file is supplied.
if [ -n "$PROFILE" ] || [ -n "$PHASE_FILTER" ] || [ "$PLAN_ONLY" = 1 ]; then
    PLAN_ARGS=("$INPUT" "--output" "$OUTDIR")
    [ -n "$PROFILE" ] && PLAN_ARGS+=("--profile" "$PROFILE")
    [ -n "$PHASE_FILTER" ] && PLAN_ARGS+=("--phase" "$PHASE_FILTER")
    python3 "$SCRIPT_DIR/plan.py" "${PLAN_ARGS[@]}" || {
        echo "[!] planner failed"; exit 3
    }
    QUEUE_FILE="$OUTDIR/queue.jsonl"
    if [ "$PLAN_ONLY" = 1 ]; then
        echo "[*] plan-only complete:"
        echo "    $OUTDIR/plan.json"
        echo "    $OUTDIR/queue.jsonl"
        echo "    $OUTDIR/guidance.json"
        exit 0
    fi
fi

if [ -n "$QUEUE_FILE" ] && [ ! -f "$QUEUE_FILE" ]; then
    echo "queue file missing: $QUEUE_FILE"; exit 2
fi

# ---------- G.7 --throttle — gentle defaults for sensitive environments ----------
# Rule (per advisor + CLAUDE.md §3 ergonomics): --throttle sets defaults ONLY
# where the operator did NOT explicitly set the knob. Explicit CLI args win.
# Env knobs already set in the parent shell ALSO win — we only fill blanks.
if [ "$THROTTLE" = 1 ]; then
    echo "[*] --throttle: gentle-mode defaults active (CLI args + env take precedence)"
    if [ "$THROTTLE_EXPLICIT_PARALLEL" = 1 ]; then
        echo "    parallel:    $PARALLEL  (operator-explicit; --throttle did not override)"
    else
        PARALLEL=1
        echo "    parallel:    1  (--throttle default; override with -P N)"
    fi
    : "${NUCLEI_RATE:=20}"   ; export NUCLEI_RATE
    : "${NO_FFUF:=1}"        ; export NO_FFUF
    : "${NO_NIKTO:=1}"       ; export NO_NIKTO
    export ENUM_THROTTLE=1
    echo "    NUCLEI_RATE: $NUCLEI_RATE"
    echo "    NO_FFUF:     $NO_FFUF"
    echo "    NO_NIKTO:    $NO_NIKTO"
fi

# Export auth so dispatchers see them
export ENUM_USER="$USER" ENUM_PASS="$PASS" ENUM_HASH="$NTLM_HASH"
export ENUM_DOMAIN="$DOMAIN" ENUM_DC_IP="$DC_IP" ENUM_PARALLEL="$PARALLEL"

# ---------- run.log — central timestamped run journal (E.3) ----------
RUN_LOG="$OUTDIR/run.log"
run_log() { printf "%s  %s\n" "$(date -Iseconds)" "$*" >> "$RUN_LOG"; }
run_log "=== auto-enum run started ==="
run_log "input=$INPUT outdir=$OUTDIR parallel=$PARALLEL resume=$RESUME throttle=$THROTTLE"
run_log "user=${USER:-<none>} domain=${DOMAIN:-<none>} dc_ip=${DC_IP:-<none>}"
# Capture tool versions (best-effort; missing tools are documented in deps-check)
for tool in nmap nxc netexec enum4linux-ng smbclient rpcclient ldapsearch \
            kerbrute ssh-audit whatweb httpx ffuf nuclei nikto onesixtyone \
            snmpwalk smbmap psql mysql mongosh mongo redis-cli curl openssl; do
    if v=$(command -v "$tool" >/dev/null 2>&1 && "$tool" --version 2>&1 | head -1); then
        [ -n "$v" ] && run_log "tool: $tool: $v"
    fi
done

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
if [ -n "$QUEUE_FILE" ]; then
    ALL_CATEGORIES=$(python3 - "$QUEUE_FILE" "$SKIP_LOW_PRIORITY" <<'PY'
import json, sys
queue = sys.argv[1]
min_pri = int(sys.argv[2]) if sys.argv[2] else None
services = []
seen = set()
with open(queue) as f:
    for line in f:
        if not line.strip():
            continue
        item = json.loads(line)
        if min_pri is not None and int(item.get("priority", 0)) < min_pri:
            continue
        svc = item.get("service")
        if svc and svc not in seen:
            seen.add(svc)
            services.append(svc)
print(" ".join(sorted(services)))
PY
)
else
    ALL_CATEGORIES=$(python3 - "$OUTDIR/inventory.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cats = list(d["summary"]["categories"].keys())
if d["summary"].get("unknown"):
    cats.append("unknown")
print(" ".join(sorted(cats)))
PY
)
fi

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
# ---------- E4 — strip aggressive services unless operator opted in ----------
# ike, slp, radius are disabled by default even if nmap found open ports.
# Each flag (--ike / --slp / --radius / --aggressive) adds the name to
# AGGRESSIVE_ENABLED; any not opted-in are stripped from the dispatch list.
# The env gates in each dispatcher are a second independent check.
AGGRESSIVE_SERVICES="ike slp radius"
for svc in $AGGRESSIVE_SERVICES; do
    case " $AGGRESSIVE_ENABLED " in
        *" $svc "*)
            # Opted in — leave in SERVICES, export its env gate
            ;;
        *)
            # Not opted in — strip from SERVICES (may not be present; that's fine)
            if echo "$SERVICES" | tr ' ' '\n' | grep -q "^${svc}$"; then
                echo "[*] Aggressive service '$svc' found in scan but not opted in — use --${svc} or --aggressive to enable"
                SERVICES=$(echo "$SERVICES" | tr ' ' '\n' | grep -v "^${svc}$" | tr '\n' ' ')
            fi
            ;;
    esac
done
# Export env gates for opted-in aggressive services so dispatchers see them
for svc in $AGGRESSIVE_ENABLED; do
    case "$svc" in
        ike)    export ENUM_RUN_IKE=1 ;;
        slp)    export ENUM_RUN_SLP=1 ;;
        radius) export ENUM_RUN_RADIUS=1 ;;
    esac
done

echo
echo "[*] Will run: $SERVICES"
echo "$SERVICES" | tr ' ' '\n' > "$OUTDIR/services.txt"

# ---------- 3. dispatch ----------
# Tracking for the post-run failure tally (E.10).
declare -i RUN_OK=0 RUN_FAIL=0 RUN_SKIP=0
declare -a FAILED_SERVICES=()

run_dispatcher() {
    local svc="$1"
    # T4 — OT/ICS sentinel category. Auto-enum NEVER dispatches to standalones/ot/
    # scripts; the operator must invoke standalones/ot/ot-enum.sh --ics-confirm by hand.
    # We surface the hint inline so the surface-area enumeration captures
    # the OT presence without firing a single probe.
    if [ "$svc" = "ot-untouched" ]; then
        local target_file="$OUTDIR/_targets_ot-untouched.txt"
        python3 "$PARSER" "$INPUT" --service "$svc" 2>/dev/null | sort -u > "$target_file" || true
        local n; n=$(wc -l < "$target_file" 2>/dev/null || echo 0)
        if [ "${n:-0}" -gt 0 ]; then
            echo "[!] OT/ICS ports detected on $n target(s) — auto-enum WILL NOT probe these."
            echo "    See aranumtoolkit/docs/ADR-005-22MAY2026-ot-ics-safety-scope.md."
            echo "    To enumerate: standalones/ot/ot-enum.sh --ics-confirm --targets <file>"
            echo "    See aranumtoolkit/docs/ROADMAP-003-22MAY2026-tier4-ics-enumeration.md."
            run_log "ot-untouched: $n target(s) detected — operator must invoke standalones/ot/ot-enum.sh by hand"
        fi
        rm -f "$target_file"
        RUN_SKIP+=1
        return
    fi

    # A category is dispatched by convention to enum-<category>.sh. When a category
    # name diverges from its dispatcher filename (see service-metadata.json's
    # `dispatcher` field, e.g. https/xmpp -> enum-http.sh/enum-jabber.sh) the repo
    # ships a symlink (enum-https.sh, enum-xmpp.sh) so this lookup still resolves.
    local script="$SCRIPT_DIR/enum-${svc}.sh"
    if [ ! -f "$script" ]; then
        if [ "$svc" = "openfire-admin" ]; then
            echo "[!] $svc detected — manual handling. Openfire admin console (9090/9091)."
            echo "    Detect/exploit CVE-2023-32315 via standalones/jabber/openfire-cve-2023-32315.py"
            echo "    (read standalones/jabber/README.md + ADR-001 first)."
            run_log "manual: $svc — see standalones/jabber/openfire-cve-2023-32315.py"
        else
            echo "[-] no dispatcher for $svc (looked for $script)"
            run_log "skip: $svc (no dispatcher)"
        fi
        RUN_SKIP+=1
        return
    fi
    chmod +x "$script" 2>/dev/null

    local svc_out="$OUTDIR/$svc"
    local done_marker="$svc_out/.done"
    # E.4 — --resume: skip if marker exists
    if [ "$RESUME" = "1" ] && [ -e "$done_marker" ]; then
        echo "[*] Service: $svc — SKIPPED (.done marker present; --resume)"
        run_log "resume-skip: $svc (.done present from $(stat -c %y "$done_marker" 2>/dev/null))"
        RUN_SKIP+=1
        return
    fi

    local target_file="$OUTDIR/_targets_${svc}.txt"
    if [ -n "$QUEUE_FILE" ]; then
        python3 - "$QUEUE_FILE" "$svc" "$SKIP_LOW_PRIORITY" > "$target_file" <<'PY'
import json, sys
queue, service = sys.argv[1], sys.argv[2]
min_pri = int(sys.argv[3]) if sys.argv[3] else None
targets = set()
with open(queue) as f:
    for line in f:
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("service") != service:
            continue
        if min_pri is not None and int(item.get("priority", 0)) < min_pri:
            continue
        target = item.get("target")
        if isinstance(target, dict):
            ip = str(target.get("ip", ""))
            port = target.get("port")
            if ip and port:
                host = f"[{ip}]" if ":" in ip else ip
                targets.add(f"{host}:{port}")
        elif isinstance(target, str) and target:
            targets.add(target)
        elif item.get("target_label"):
            targets.add(str(item["target_label"]))
for t in sorted(targets):
    print(t)
PY
    elif [ "$svc" = "unknown" ]; then
        python3 "$PARSER" "$INPUT" --unknown | sort -u > "$target_file"
    else
        python3 "$PARSER" "$INPUT" --service "$svc" | sort -u > "$target_file"
    fi
    local n; n=$(wc -l < "$target_file")
    [ "$n" -eq 0 ] && { rm -f "$target_file"; return; }
    echo "[*] Service: $svc ($n targets)"
    run_log "dispatch-begin: $svc ($n targets)"
    if [ "$DRY_RUN" = "1" ]; then
        echo "    DRY: $script --targets $target_file --output $svc_out"
        return
    fi
    mkdir -p "$svc_out"
    local t0; t0=$(date +%s)
    # Run + capture rc + propagate to tee'd log
    local rc
    bash "$script" --targets "$target_file" --output "$svc_out" \
         2>&1 | tee "$svc_out/_dispatcher.log"
    rc=${PIPESTATUS[0]}
    local t1; t1=$(date +%s)
    local elapsed=$((t1 - t0))
    run_log "dispatch-end:   $svc rc=$rc elapsed=${elapsed}s"
    if [ "$rc" -eq 0 ]; then
        RUN_OK+=1
        # Stamp the .done marker for --resume on the next run
        echo "$(date -Iseconds)  rc=0  elapsed=${elapsed}s  targets=$n" > "$done_marker"
    else
        RUN_FAIL+=1
        FAILED_SERVICES+=("$svc(rc=$rc)")
    fi
}

for svc in $SERVICES; do
    run_dispatcher "$svc"
done

# ---------- 4. summary ----------
echo
echo "=== Enumeration complete ==="
echo "Results: $OUTDIR/"
find "$OUTDIR" -maxdepth 2 -type d | sed "s|$OUTDIR|.|"

# E.10 — dispatcher failure tally
echo
echo "Dispatcher results: OK=$RUN_OK  FAIL=$RUN_FAIL  SKIP=$RUN_SKIP"
if [ "$RUN_FAIL" -gt 0 ]; then
    printf '\033[1;31m[!]\033[0m %d dispatcher(s) exited non-zero: %s\n' \
        "$RUN_FAIL" "${FAILED_SERVICES[*]}"
    echo "    inspect each <service>/_dispatcher.log for details"
fi
run_log "=== run complete OK=$RUN_OK FAIL=$RUN_FAIL SKIP=$RUN_SKIP ==="

# Hint about report.py
echo
echo "Next: generate the unified findings report:"
echo "  python3 $SCRIPT_DIR/report.py $OUTDIR --label '$(basename "$OUTDIR")'"
