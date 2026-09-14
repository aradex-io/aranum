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
SERVICE_PARALLEL=1   # cross-service concurrency (1 = serial); --service-parallel N
ONLY=""
EXCLUDE=""
PROXY=""
NO_RPC=0
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
  --service-parallel N  run N service dispatchers concurrently (default: 1 =
                      serial). Overlaps disjoint host:port sets; keep 1 for
                      throttled/OT runs. Batched — waits every N launches.
  --only LIST         comma-sep services to run (e.g. smb,ldap,winrm)
  --exclude LIST      comma-sep services to skip
  --proxy HOST:PORT   route web analysis (curl / httpx / nuclei / ffuf / whatweb
                      and the python HTTP tools) through an intercepting proxy,
                      e.g. Burp: --proxy 127.0.0.1:8080. Accepts host:port or a
                      full URL (http://user:pass@host:port, socks5://…). Exports
                      ENUM_PROXY + HTTP(S)_PROXY to every dispatcher.
  --no-rpc            disable RPC enumeration: skip the msrpc dispatcher and set
                      NO_RPC=1 so smb/other dispatchers skip their rpcclient
                      calls (the RPC analogue of excluding web with --exclude http)
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
  --queue FILE        dispatch each selected planner task independently using
                      its exact endpoint, phase, protocol, risk, and priority
  --skip-low-priority N
                      with --profile/--phase/--queue, skip planner items below N

Opt-in aggressive probes (E4 — disabled by default):
  --ike               enable enum-ike.sh (UDP 500 — IKEv1 main-mode probe).
                      DOUBLY-AGGRESSIVE: aggressive-mode hash-harvest requires
                      also setting ENUM_IKE_AGGRESSIVE_MODE=1.
  --slp               enable enum-slp.sh (UDP 427 — SLP discovery).
                      Amplification surface; NOT for arbitrary internet hosts.
  --ntp               enable enum-ntp.sh (UDP 123 — mode-6 readvar + mode-7
                      monlist; CVE-2013-5211 amplification precondition).
  --ssdp              enable enum-ssdp.sh (UDP 1900 — UPnP M-SEARCH discovery;
                      CVE-2020-12695 CallStranger surface).
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
        --service-parallel) SERVICE_PARALLEL="$2"; shift 2 ;;
        --only)         ONLY="$2"; shift 2 ;;
        --exclude)      EXCLUDE="$2"; shift 2 ;;
        --proxy)        PROXY="$2"; shift 2 ;;
        --no-rpc)       NO_RPC=1; shift ;;
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
        --ntp)          AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED ntp"; shift ;;
        --ssdp)         AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED ssdp"; shift ;;
        --aggressive)   AGGRESSIVE_ENABLED="$AGGRESSIVE_ENABLED ike slp radius ntp ssdp"; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "unknown arg: $1"; usage; exit 1 ;;
    esac
done

[ -z "$INPUT" ] && { usage; exit 1; }
[ ! -f "$INPUT" ] && { echo "input not found: $INPUT"; exit 2; }
[ ! -x "$PARSER" ] && chmod +x "$PARSER" 2>/dev/null

for parallel_spec in "$PARALLEL" "$SERVICE_PARALLEL"; do
    if ! [[ "$parallel_spec" =~ ^[0-9]+$ ]] || [ "$parallel_spec" -lt 1 ] || [ "$parallel_spec" -gt 16 ]; then
        echo "parallelism must be an integer in 1..16 (got: $parallel_spec)" >&2
        exit 2
    fi
done

mkdir -p "$OUTDIR" || { echo "cannot create output directory: $OUTDIR" >&2; exit 2; }
[ -d "$OUTDIR" ] || { echo "output path is not a directory: $OUTDIR" >&2; exit 2; }
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_STATE_DIR="$OUTDIR/.run-state-$RUN_ID"
mkdir -p "$RUN_STATE_DIR" || { echo "cannot create run-state directory" >&2; exit 2; }

record_service_result() {
    local service="$1" status="$2" rc="$3" reason="$4"
    python3 - "$RUN_STATE_DIR" "$service" "$status" "$rc" "$reason" <<'PY'
import datetime, json, os, sys, tempfile
root, service, status, rc, reason = sys.argv[1:]
payload = {"service": service, "status": status, "rc": int(rc), "reason": reason,
           "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
fd, tmp = tempfile.mkstemp(prefix=f".{service}.", dir=root, text=True)
try:
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, os.path.join(root, f"{service}.json"))
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
}

record_task_result() {
    local record_key="$1" task_id="$2" service="$3" status="$4" rc="$5" reason="$6"
    python3 - "$RUN_STATE_DIR/task-results" "$record_key" "$task_id" "$service" \
        "$status" "$rc" "$reason" <<'PY'
import datetime, json, os, sys, tempfile
root, record_key, task_id, service, status, rc, reason = sys.argv[1:]
os.makedirs(root, exist_ok=True)
payload = {"task_id": task_id, "service": service, "status": status,
           "rc": int(rc), "reason": reason,
           "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
fd, tmp = tempfile.mkstemp(prefix=f".{record_key}.", dir=root, text=True)
try:
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, os.path.join(root, f"{record_key}.json"))
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
}

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

# Validate and materialize the exact current-run queue before any dispatcher
# state is touched. Schema-incomplete or malformed JSONL fails closed.
ACTIVE_QUEUE=""
if [ -n "$QUEUE_FILE" ]; then
    ACTIVE_QUEUE="$RUN_STATE_DIR/selected-queue.jsonl"
    if ! python3 - "$QUEUE_FILE" "$ACTIVE_QUEUE" "$SKIP_LOW_PRIORITY" \
        "$SCRIPT_DIR/service-metadata.json" <<'PY'
import ipaddress, json, os, re, sys, tempfile
source, destination, minimum, metadata_path = sys.argv[1:]
minimum_priority = int(minimum) if minimum else None
with open(metadata_path, encoding="utf-8") as metadata_fh:
    metadata = json.load(metadata_fh)
service_contracts = metadata.get("services", {})
default_execution = str(metadata.get("defaults", {}).get("task_execution", "monolithic")).lower()
selected, seen = [], {}
source_records = 0
with open(source, encoding="utf-8") as fh:
    for lineno, raw in enumerate(fh, 1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid queue JSON at line {lineno}: {exc}")
        source_records += 1
        if not isinstance(item, dict):
            raise SystemExit(f"invalid queue record at line {lineno}: object required")
        target = item.get("target")
        required = ("task_id", "service", "phase", "risk", "priority")
        missing = [key for key in required if item.get(key) in (None, "")]
        if missing or not isinstance(target, dict):
            raise SystemExit(f"invalid queue record at line {lineno}: missing {missing or ['target object']}")
        ip = str(target.get("ip", "")).strip()
        proto = str(target.get("proto", "")).strip().lower()
        if not ip or not proto:
            raise SystemExit(f"invalid queue target at line {lineno}: ip/proto required")
        try:
            ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            raise SystemExit(f"invalid queue target at line {lineno}: invalid IP address")
        try:
            port, priority = int(target.get("port")), int(item.get("priority"))
        except (TypeError, ValueError):
            raise SystemExit(f"invalid queue target at line {lineno}: integer port/priority required")
        if not 1 <= port <= 65535 or proto not in {"tcp", "udp"} or not 0 <= priority <= 999:
            raise SystemExit(f"invalid queue target at line {lineno}: port/proto out of range")
        task_id = str(item["task_id"])
        service = str(item["service"])
        phase = str(item["phase"])
        risk = str(item["risk"])
        safe_token = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
        if not safe_token.fullmatch(service) or not safe_token.fullmatch(phase) or not safe_token.fullmatch(risk):
            raise SystemExit(f"invalid queue record at line {lineno}: unsafe service/phase/risk token")
        if not task_id.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in task_id):
            raise SystemExit(f"invalid queue record at line {lineno}: unsafe task_id")
        contract = service_contracts.get(service)
        if not isinstance(contract, dict):
            raise SystemExit(f"invalid queue record at line {lineno}: unknown service {service}")
        execution = str(contract.get("task_execution", default_execution)).lower()
        if execution not in {"monolithic", "phased"}:
            raise SystemExit(f"invalid service task_execution for {service}: {execution}")
        declared_phases = {str(p.get("id")) for p in contract.get("phases", [])
                           if isinstance(p, dict) and p.get("id") is not None}
        allowed_phases = declared_phases if execution == "phased" else {"all"}
        if phase not in allowed_phases:
            allowed_display = ",".join(sorted(allowed_phases))
            raise SystemExit(
                f"unsupported queue phase for {service}: {phase} "
                f"(task_execution={execution}; allowed={allowed_display})")
        item["target"] = {**target, "ip": ip, "port": port, "proto": proto}
        item["priority"] = priority
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"))
        if task_id in seen:
            if seen[task_id] != canonical:
                raise SystemExit(f"conflicting duplicate task_id at line {lineno}: {task_id}")
            continue
        seen[task_id] = canonical
        if minimum_priority is None or priority >= minimum_priority:
            selected.append(item)
if source_records == 0:
    raise SystemExit("explicit queue contains no records")
fd, tmp = tempfile.mkstemp(prefix=".selected-queue.", dir=os.path.dirname(destination), text=True)
try:
    with os.fdopen(fd, "w") as out:
        for item in selected:
            out.write(json.dumps(item, sort_keys=True) + "\n")
    os.replace(tmp, destination)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
print(f"[*] Queue records: {source_records}; selected unique tasks: {len(selected)}")
PY
    then
        echo "[!] queue validation failed: $QUEUE_FILE" >&2
        exit 3
    fi
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

# --no-rpc: skip the msrpc dispatcher AND signal rpcclient-using dispatchers
# (enum-smb.sh etc.) to omit their RPC calls. Mirrors disabling web (--exclude http).
if [ "$NO_RPC" = 1 ]; then
    EXCLUDE="${EXCLUDE:+$EXCLUDE,}msrpc"
    export NO_RPC=1
    echo "[*] --no-rpc: msrpc dispatcher excluded; rpcclient calls suppressed (NO_RPC=1)"
fi

# --proxy: route ALL web analysis through an intercepting proxy (Burp/ZAP/etc).
# curl and python-urllib honor HTTP(S)_PROXY natively; ENUM_PROXY drives our
# explicit curl -x helper (_lib.sh) and the -proxy/-x flags in enum-http.sh.
if [ -n "$PROXY" ]; then
    case "$PROXY" in
        http://*|https://*|socks5://*|socks5h://*|socks4://*) PROXY_URL="$PROXY" ;;
        *) PROXY_URL="http://$PROXY" ;;
    esac
    export ENUM_PROXY="$PROXY_URL"
    export HTTP_PROXY="$PROXY_URL"  HTTPS_PROXY="$PROXY_URL"
    export http_proxy="$PROXY_URL"  https_proxy="$PROXY_URL"
    echo "[*] --proxy: web analysis routed through $PROXY_URL (ENUM_PROXY + HTTP(S)_PROXY)"
fi

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
    if ! ALL_CATEGORIES=$(python3 - "$ACTIVE_QUEUE" <<'PY'
import json, sys
queue = sys.argv[1]
services = []
seen = set()
with open(queue) as f:
    for line in f:
        if not line.strip():
            continue
        item = json.loads(line)
        svc = item.get("service")
        if svc and svc not in seen:
            seen.add(svc)
            services.append(svc)
print(" ".join(sorted(services)))
PY
    ); then
        echo "[!] failed to read validated queue" >&2
        exit 3
    fi
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
AGGRESSIVE_SERVICES="ike slp radius ntp ssdp"
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
        ntp)    export ENUM_RUN_NTP=1 ;;
        ssdp)   export ENUM_RUN_SSDP=1 ;;
    esac
done

echo
echo "[*] Will run: $SERVICES"
echo "$SERVICES" | tr ' ' '\n' > "$OUTDIR/services.txt"

# ---------- 3. dispatch ----------
# Tracking for the post-run failure tally (E.10).
declare -i RUN_OK=0 RUN_FAIL=0 RUN_SKIP=0
declare -a FAILED_SERVICES=()

queue_task_rows() {
    local service="$1"
    python3 - "$ACTIVE_QUEUE" "$service" <<'PY'
import hashlib, json, sys
queue, service = sys.argv[1:]
with open(queue, encoding="utf-8") as fh:
    for raw in fh:
        if not raw.strip():
            continue
        item = json.loads(raw)
        if item["service"] != service:
            continue
        target = item["target"]
        ip, port = str(target["ip"]), int(target["port"])
        label = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        key = hashlib.sha256(str(item["task_id"]).encode()).hexdigest()[:20]
        print("\t".join((key, str(item["task_id"]), str(item["phase"]),
                         str(target["proto"]), str(item["risk"]),
                         str(item["priority"]), ip, str(port), label)))
PY
}

record_queue_tasks_status() {
    local service="$1" status="$2" rc="$3" reason="$4"
    local key task_id phase protocol risk priority ip port target_label
    while IFS=$'\t' read -r key task_id phase protocol risk priority ip port target_label; do
        [ -n "$key" ] || continue
        record_task_result "$key" "$task_id" "$service" "$status" "$rc" "$reason"
    done < <(queue_task_rows "$service")
}

run_queue_dispatcher() {
    local svc="$1" script="$2"
    local svc_out="$OUTDIR/$svc"
    if ! mkdir -p "$svc_out" || [ ! -d "$svc_out" ]; then
        record_queue_tasks_status "$svc" "failed" 2 "cannot create service output directory"
        record_service_result "$svc" "failed" 2 "cannot create service output directory"
        return
    fi

    # Queue completion is task-scoped.  A service-wide marker from an older or
    # non-queue run is neither a resume authority nor evidence for unselected
    # endpoints.
    rm -f "$svc_out/.done" "$svc_out/.rc" 2>/dev/null || true
    local selected=0 done_count=0 failed_count=0 skipped_count=0 first_rc=0
    local key task_id phase protocol risk priority ip port target_label
    while IFS=$'\t' read -r key task_id phase protocol risk priority ip port target_label; do
        [ -n "$key" ] || continue
        selected=$((selected + 1))
        local task_out="$svc_out/task-$key"
        local task_targets="$RUN_STATE_DIR/task-$key.targets"
        local task_done="$task_out/.done"
        printf '%s\n' "$target_label" > "$task_targets"

        if [ "$RESUME" = "1" ] && [ -e "$task_done" ]; then
            echo "[*] Task: $task_id — SKIPPED (.done marker present; --resume)"
            record_task_result "$key" "$task_id" "$svc" "skipped" 0 "resume marker"
            skipped_count=$((skipped_count + 1))
            continue
        fi
        [ "$RESUME" = "1" ] || rm -f "$task_done" 2>/dev/null || true
        if [ "$DRY_RUN" = "1" ]; then
            echo "    DRY task: $task_id -> $script --targets $task_targets --output $task_out"
            record_task_result "$key" "$task_id" "$svc" "skipped" 0 "dry run"
            skipped_count=$((skipped_count + 1))
            continue
        fi
        mkdir -p "$task_out" || {
            record_task_result "$key" "$task_id" "$svc" "failed" 2 "cannot create task output directory"
            failed_count=$((failed_count + 1)); [ "$first_rc" -ne 0 ] || first_rc=2
            continue
        }

        echo "[*] Task: $task_id ($target_label $protocol phase=$phase risk=$risk priority=$priority)"
        run_log "task-dispatch-begin: $task_id target=$target_label protocol=$protocol phase=$phase risk=$risk priority=$priority"
        local t0; t0=$(date +%s)
        bash "$script" --targets "$task_targets" --output "$task_out" \
            --task-id "$task_id" --task-service "$svc" --task-phase "$phase" \
            --task-protocol "$protocol" --task-risk "$risk" \
            --task-priority "$priority" --task-target "$target_label" \
            2>&1 | tee "$task_out/_dispatcher.log"
        local rc=${PIPESTATUS[0]}
        local t1; t1=$(date +%s)
        local elapsed=$((t1 - t0))
        run_log "task-dispatch-end: $task_id rc=$rc elapsed=${elapsed}s"
        if [ "$rc" -eq 0 ]; then
            local done_tmp="$task_done.tmp.$$"
            echo "$(date -Iseconds)  task=$task_id  rc=0  elapsed=${elapsed}s" > "$done_tmp" \
                && mv -f "$done_tmp" "$task_done"
            record_task_result "$key" "$task_id" "$svc" "done" 0 "constrained dispatcher completed"
            done_count=$((done_count + 1))
        else
            record_task_result "$key" "$task_id" "$svc" "failed" "$rc" "constrained dispatcher failed"
            failed_count=$((failed_count + 1)); [ "$first_rc" -ne 0 ] || first_rc=$rc
        fi
    done < <(queue_task_rows "$svc")

    if [ "$selected" -eq 0 ]; then
        record_service_result "$svc" "skipped" 0 "zero selected tasks"
    elif [ "$failed_count" -gt 0 ]; then
        echo "$first_rc" > "$svc_out/.rc"
        record_service_result "$svc" "failed" "$first_rc" "$failed_count of $selected constrained tasks failed"
    elif [ "$done_count" -eq 0 ]; then
        echo "0" > "$svc_out/.rc"
        record_service_result "$svc" "skipped" 0 "$skipped_count constrained tasks skipped"
    else
        echo "0" > "$svc_out/.rc"
        record_service_result "$svc" "done" 0 "$done_count constrained tasks completed; $skipped_count skipped"
    fi
}

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
        [ -z "$QUEUE_FILE" ] || record_queue_tasks_status "$svc" "skipped" 0 "manual OT handoff"
        record_service_result "$svc" "skipped" 0 "manual OT handoff"
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
        [ -z "$QUEUE_FILE" ] || record_queue_tasks_status "$svc" "skipped" 0 "no dispatcher"
        record_service_result "$svc" "skipped" 0 "no dispatcher"
        return
    fi
    chmod +x "$script" 2>/dev/null

    if [ -n "$QUEUE_FILE" ]; then
        run_queue_dispatcher "$svc" "$script"
        return
    fi

    local svc_out="$OUTDIR/$svc"
    local done_marker="$svc_out/.done"
    # Legacy .rc is never a current-run record. A non-resume attempt also
    # invalidates prior success before any new work begins.
    rm -f "$svc_out/.rc" 2>/dev/null || true
    # E.4 — --resume: skip if marker exists
    if [ "$RESUME" = "1" ] && [ -e "$done_marker" ]; then
        echo "[*] Service: $svc — SKIPPED (.done marker present; --resume)"
        run_log "resume-skip: $svc (.done present from $(stat -c %y "$done_marker" 2>/dev/null))"
        RUN_SKIP+=1
        record_service_result "$svc" "skipped" 0 "resume marker"
        return
    fi
    [ "$RESUME" = "1" ] || rm -f "$done_marker" 2>/dev/null || true

    local target_file="$OUTDIR/_targets_${svc}.txt"
    if [ "$svc" = "unknown" ]; then
        python3 "$PARSER" "$INPUT" --unknown | sort -u > "$target_file"
    else
        python3 "$PARSER" "$INPUT" --service "$svc" | sort -u > "$target_file"
    fi
    local n; n=$(wc -l < "$target_file")
    [ "$n" -eq 0 ] && { rm -f "$target_file"; RUN_SKIP+=1; record_service_result "$svc" "skipped" 0 "zero selected targets"; return; }
    echo "[*] Service: $svc ($n targets)"
    run_log "dispatch-begin: $svc ($n targets)"
    if [ "$DRY_RUN" = "1" ]; then
        echo "    DRY: $script --targets $target_file --output $svc_out"
        RUN_SKIP+=1
        record_service_result "$svc" "skipped" 0 "dry run"
        return
    fi
    if ! mkdir -p "$svc_out" || [ ! -d "$svc_out" ]; then
        RUN_FAIL+=1
        FAILED_SERVICES+=("$svc(rc=2)")
        record_service_result "$svc" "failed" 2 "cannot create service output directory"
        return
    fi
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
        local done_tmp="$done_marker.tmp.$$"
        echo "$(date -Iseconds)  rc=0  elapsed=${elapsed}s  targets=$n" > "$done_tmp" && mv -f "$done_tmp" "$done_marker"
        record_service_result "$svc" "done" 0 "dispatcher completed"
    else
        RUN_FAIL+=1
        FAILED_SERVICES+=("$svc(rc=$rc)")
        record_service_result "$svc" "failed" "$rc" "dispatcher failed"
    fi
    # Persist rc so the parallel path (backgrounded subshells) can tally outcomes.
    echo "$rc" > "$svc_out/.rc" 2>/dev/null || true
}

# Cross-service dispatch. Default is serial (globals tally directly). With
# --service-parallel N, run N dispatchers concurrently in batches; because the
# backgrounded run_dispatcher runs in a subshell (globals don't propagate), the
# OK/FAIL tally is recomputed from each service's .rc afterward.
if [ "${SERVICE_PARALLEL:-1}" -gt 1 ] 2>/dev/null; then
    echo "[*] cross-service parallelism enabled: $SERVICE_PARALLEL concurrent dispatchers"
    run_log "cross-service parallelism: $SERVICE_PARALLEL"
    running=0
    for svc in $SERVICES; do
        run_dispatcher "$svc" &
        running=$((running + 1))
        if [ "$running" -ge "$SERVICE_PARALLEL" ]; then wait; running=0; fi
    done
    wait
else
    for svc in $SERVICES; do
        run_dispatcher "$svc"
    done
fi

# Aggregate only current-run atomic service records. This is identical for
# serial and background execution, so skip/failure counts cannot disappear in
# a subshell and legacy .rc files cannot contaminate the summary.
RUN_OK=0; RUN_FAIL=0; RUN_SKIP=0; FAILED_SERVICES=()
while IFS=$'\t' read -r result_svc result_status result_rc; do
    [ -n "$result_svc" ] || continue
    case "$result_status" in
        done) RUN_OK=$((RUN_OK + 1)) ;;
        skipped) RUN_SKIP=$((RUN_SKIP + 1)) ;;
        failed) RUN_FAIL=$((RUN_FAIL + 1)); FAILED_SERVICES+=("$result_svc(rc=$result_rc)") ;;
    esac
done < <(python3 - "$RUN_STATE_DIR" <<'PY'
import json, pathlib, sys
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    try: item = json.loads(path.read_text())
    except Exception: continue
    print(f"{item.get('service','')}\t{item.get('status','')}\t{item.get('rc','')}")
PY
)

# Publish a single current-run state snapshot atomically. Queue records retain
# task, phase, risk, priority, endpoint, and protocol rather than reconstructing
# those fields from display strings.
if ! python3 - "$RUN_ID" "$RUN_STATE_DIR" "$OUTDIR/run-state.json" "$ACTIVE_QUEUE" "${QUEUE_FILE:-}" <<'PY'
import datetime, json, os, pathlib, sys, tempfile
run_id, state_dir, run_state_path, active_queue, original_queue = sys.argv[1:]
results = {}
for path in pathlib.Path(state_dir).glob("*.json"):
    try:
        item = json.loads(path.read_text())
    except Exception:
        continue
    results[item["service"]] = item
task_results = {}
for path in (pathlib.Path(state_dir) / "task-results").glob("*.json"):
    try:
        item = json.loads(path.read_text())
    except Exception:
        continue
    task_results[item["task_id"]] = item
payload = {"schema_version": 1, "run_id": run_id,
           "execution_mode": "queue" if active_queue else "service-batch",
           "queue_authoritative": bool(active_queue),
           "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "services": [results[k] for k in sorted(results)]}
def atomic_json(path, value):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".state.", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, indent=2, sort_keys=True); out.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
atomic_json(run_state_path, payload)
if active_queue:
    records = []
    for raw in pathlib.Path(active_queue).read_text().splitlines():
        task = json.loads(raw)
        result = task_results.get(task["task_id"], {"status": "skipped", "rc": 0,
                                                     "reason": "not selected for execution"})
        records.append({"task_id": task["task_id"], "service": task["service"],
                        "phase": task["phase"], "risk": task["risk"],
                        "priority": task["priority"], "target": task["target"],
                        "status": result["status"], "rc": result["rc"],
                        "reason": result.get("reason", ""), "run_id": run_id,
                        "ts": result.get("ts", payload["generated_utc"])})
    state_paths = {os.path.join(os.path.dirname(run_state_path), "queue.state.jsonl"),
                   os.path.join(os.path.dirname(original_queue), "queue.state.jsonl")}
    for state_path in state_paths:
        directory = os.path.dirname(state_path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".queue-state.", dir=directory, text=True)
        try:
            with os.fdopen(fd, "w") as out:
                for record in records: out.write(json.dumps(record, sort_keys=True) + "\n")
            os.replace(tmp, state_path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
PY
then
    echo "[!] failed to publish current-run state" >&2
    exit 3
fi

# A queue snapshot is authoritative to report.py.  Once a real non-queue run
# succeeds in the same output directory, retaining that older snapshot would
# incorrectly hide or reclassify the fresh service-level results.  Preserve it
# for audit, but move it away from the authoritative filename before reporting.
if [ -z "$QUEUE_FILE" ] && [ "$DRY_RUN" = "0" ] && [ "$RUN_FAIL" -eq 0 ]; then
    # report.py consumes both locations: the output-local snapshot and the
    # sibling written next to an operator-supplied queue. Archive both, or the
    # surviving parent snapshot would remain authoritative.
    for QUEUE_STATE_PATH in "$OUTDIR/queue.state.jsonl" \
                            "$(dirname "$OUTDIR")/queue.state.jsonl"; do
        [ -e "$QUEUE_STATE_PATH" ] || continue
        STALE_QUEUE_STATE="$QUEUE_STATE_PATH.stale-$RUN_ID"
        if ! mv -- "$QUEUE_STATE_PATH" "$STALE_QUEUE_STATE"; then
            echo "[!] failed to archive stale queue state: $QUEUE_STATE_PATH" >&2
            exit 3
        fi
        run_log "archived stale queue authority: $STALE_QUEUE_STATE"
    done
fi

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

[ "$RUN_FAIL" -eq 0 ] || exit 4
exit 0
