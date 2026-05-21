#!/usr/bin/env bash
# bulk-enum-linux.sh — run linux/linenum-fast.sh against many hosts in parallel
# via stdin-pipe over SSH. Per ADR-002.
#
# Output layout (mirrors auto-enum.sh):
#     <outdir>/
#       run.log              — central timestamped journal
#       hosts.txt            — copy of the input target list (audit)
#       known_hosts          — engagement-scoped SSH known_hosts silo
#       _summary.tsv         — one row per host (host  rc  elapsed_s  size_kb)
#       <host>/
#         linenum.txt        — raw stdout from linenum-fast.sh
#         linenum.err        — stderr (ssh errors + script warnings)
#         _meta.json         — {rc, started, elapsed_s, ssh_args}
#         .done              — written iff rc=0 (for --resume)
#
# The remote script is NEVER written to disk on the target. stdin-pipe means it
# lives only in the SSH session's bash memory.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LINENUM="$REPO_ROOT/linux/linenum-fast.sh"

# Source shared helpers (curl_ua, throttle_*, etc. — J.4 only needs throttle_*).
# shellcheck source=_lib.sh
. "$SCRIPT_DIR/_lib.sh"

# ---------- defaults ----------
TARGETS=""
OUTDIR="./bulk-enum-results"
SSH_USER=""
SSH_KEY=""
SSH_PASS=""
SSH_PORT="22"
CONNECT_TIMEOUT="10"
PARALLEL=4
THROTTLE=0
THROTTLE_EXPLICIT_PARALLEL=0
DRY_RUN=0
RESUME=0

usage() {
    cat <<EOF
Usage: $0 --targets <file> [-o <outdir>] [options]

Required:
  --targets FILE         one host per line. Format: 'host', 'user@host', or
                         'user@host:port'. Lines starting with '#' are skipped.
                         A bare host uses --user (or current \$USER).

Output:
  -o, --output DIR       results dir (default: $OUTDIR)

Auth (one of, or rely on ssh-agent):
  -u, --user USER        default username for bare-host lines
  -k, --key FILE         SSH private key (-i FILE)
  --pass PASSWORD        password via sshpass (sshpass MUST be installed)
                         WARNING: visible in 'ps'; prefer --key or ssh-agent

Connection:
  --port N               default SSH port (default: $SSH_PORT)
  --connect-timeout SEC  ssh ConnectTimeout (default: $CONNECT_TIMEOUT)
  --ssh-opt 'K=V'        repeatable extra '-o K=V' (e.g. ProxyJump=bastion)

Tuning:
  -P, --parallel N       parallel hosts (default: $PARALLEL, hard-capped at 16
                         to protect operator's local-side resource limits)
  --throttle             gentle mode: collapses to -P 1 + ENUM_THROTTLE_DELAY
                         seconds between hosts. Operator -P wins over default.
  --dry-run              print plan + effective env, don't connect
  --resume               skip hosts that have a .done marker from a prior run

  -h, --help             show this help

Examples:
  $0 --targets prod.txt -u jay -k ~/.ssh/id_rsa -o ./prod
  $0 --targets lab.txt --user lab --pass 'Hunter2!' --throttle -o ./lab
  $0 --targets dev.txt -P 8 --ssh-opt 'ProxyJump=bastion.corp' -o ./dev
  $0 --targets prev.txt --resume -o ./prev    # continue an interrupted run

Per ADR-002:
  - linenum-fast.sh is piped over stdin (never lands on target disk)
  - known_hosts is per-engagement (\$OUTDIR/known_hosts) — not ~/.ssh/known_hosts
  - StrictHostKeyChecking=accept-new on first contact; verified thereafter
  - BatchMode=yes — no interactive prompts; auth must work on first try

After the run:
  network/report.py \$OUTDIR        # findings.json + report.md + report.html
EOF
}

# ---------- arg parsing ----------
EXTRA_SSH_OPTS_ARR=()
while [ $# -gt 0 ]; do
    case "$1" in
        --targets)         TARGETS="$2"; shift 2 ;;
        -o|--output)       OUTDIR="$2"; shift 2 ;;
        -u|--user)         SSH_USER="$2"; shift 2 ;;
        -k|--key)          SSH_KEY="$2"; shift 2 ;;
        --pass)            SSH_PASS="$2"; shift 2 ;;
        --port)            SSH_PORT="$2"; shift 2 ;;
        --connect-timeout) CONNECT_TIMEOUT="$2"; shift 2 ;;
        --ssh-opt)         EXTRA_SSH_OPTS_ARR+=(-o "$2"); shift 2 ;;
        -P|--parallel)     PARALLEL="$2"; THROTTLE_EXPLICIT_PARALLEL=1; shift 2 ;;
        --throttle)        THROTTLE=1; shift ;;
        --dry-run)         DRY_RUN=1; shift ;;
        --resume)          RESUME=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) err "unknown arg: $1"; usage; exit 1 ;;
    esac
done

[ -z "$TARGETS" ] && { usage; exit 1; }
[ ! -f "$TARGETS" ] && { err "targets file not found: $TARGETS"; exit 2; }
[ ! -r "$LINENUM" ] && { err "linenum-fast.sh missing or unreadable: $LINENUM"; exit 2; }

# Resource-cap parallelism — protects local fd limits / process table at scale.
if [ "$PARALLEL" -gt 16 ]; then
    err "parallel capped at 16 (you asked for $PARALLEL); use multiple runs for higher fanout"
    exit 2
fi

# Validate auth combination
if [ -n "$SSH_PASS" ] && ! have sshpass; then
    err "--pass requires sshpass (install: sudo dnf install sshpass / apt install sshpass)"
    exit 2
fi
if [ -n "$SSH_KEY" ] && [ ! -r "$SSH_KEY" ]; then
    err "--key not readable: $SSH_KEY"; exit 2
fi

mkdir -p "$OUTDIR"

# ---------- G.7 --throttle (parity with auto-enum.sh) ----------
if [ "$THROTTLE" = 1 ]; then
    echo "[*] --throttle: gentle-mode defaults active"
    if [ "$THROTTLE_EXPLICIT_PARALLEL" = 1 ]; then
        echo "    parallel:    $PARALLEL  (operator-explicit; --throttle did not override)"
    else
        PARALLEL=1
        echo "    parallel:    1  (--throttle default; override with -P N)"
    fi
    export ENUM_THROTTLE=1
    : "${ENUM_THROTTLE_DELAY:=1}"; export ENUM_THROTTLE_DELAY
    echo "    inter-host delay: ${ENUM_THROTTLE_DELAY}s"
fi

# ---------- run.log ----------
RUN_LOG="$OUTDIR/run.log"
run_log() { printf "%s  %s\n" "$(date -Iseconds)" "$*" >> "$RUN_LOG"; }
run_log "=== bulk-enum-linux run started ==="
run_log "targets=$TARGETS outdir=$OUTDIR parallel=$PARALLEL resume=$RESUME throttle=$THROTTLE"
run_log "user=${SSH_USER:-<bare/agent>} key=${SSH_KEY:-<none>} pass=${SSH_PASS:+<set>}"
run_log "linenum=$LINENUM ($(wc -l < "$LINENUM") lines)"

# Copy the input list to the output dir for audit
cp -- "$TARGETS" "$OUTDIR/hosts.txt"

# Per-engagement known_hosts (ADR-002 D3)
KNOWN_HOSTS="$OUTDIR/known_hosts"
[ -f "$KNOWN_HOSTS" ] || : > "$KNOWN_HOSTS"

# Persist extra ssh -o args to disk so per-host subshells can read them
# without env-var serialization gymnastics. One arg per line.
SSH_EXTRA_FILE="$OUTDIR/.ssh_extra_opts"
: > "$SSH_EXTRA_FILE"
for opt in "${EXTRA_SSH_OPTS_ARR[@]}"; do
    printf '%s\n' "$opt" >> "$SSH_EXTRA_FILE"
done

# ---------- common ssh args ----------
ssh_base_args() {
    local args=(
        -o "BatchMode=yes"
        -o "ConnectTimeout=$CONNECT_TIMEOUT"
        -o "ServerAliveInterval=15"
        -o "ServerAliveCountMax=4"
        -o "StrictHostKeyChecking=accept-new"
        -o "UserKnownHostsFile=$KNOWN_HOSTS"
        -o "LogLevel=ERROR"
    )
    [ -n "$SSH_KEY" ] && args+=(-i "$SSH_KEY")
    if [ -s "$SSH_EXTRA_FILE" ]; then
        while IFS= read -r line; do args+=("$line"); done < "$SSH_EXTRA_FILE"
    fi
    printf '%s\n' "${args[@]}"
}

# Parse a target spec line into "user host port"
parse_spec() {
    local spec="$1"
    local user host port
    # strip comments + whitespace
    spec="${spec%%#*}"
    spec="${spec#"${spec%%[![:space:]]*}"}"
    spec="${spec%"${spec##*[![:space:]]}"}"
    [ -z "$spec" ] && return 1
    if [[ "$spec" == *"@"* ]]; then
        user="${spec%@*}"; rest="${spec#*@}"
    else
        user="${SSH_USER:-$USER}"; rest="$spec"
    fi
    if [[ "$rest" == \[*\]:* ]]; then
        host="${rest#[}"; host="${host%%]:*}"; port="${rest##*]:}"
    elif [[ "$rest" == *:* && "$rest" != *::* ]]; then
        # ipv4:port or hostname:port
        host="${rest%:*}"; port="${rest##*:}"
    else
        host="$rest"; port="$SSH_PORT"
    fi
    printf '%s\t%s\t%s\n' "$user" "$host" "$port"
}

# ---------- per-host execution ----------
run_one_host() {
    local spec="$1"
    local parsed user host port
    parsed=$(parse_spec "$spec") || return 0   # blank / comment line
    IFS=$'\t' read -r user host port <<< "$parsed"

    local hdir="$OUTDIR/$host"
    mkdir -p "$hdir"

    if [ "$RESUME" = 1 ] && [ -e "$hdir/.done" ]; then
        run_log "resume-skip: $host (prior rc=0)"
        return 0
    fi

    # IPv6 addresses must be bracketed in the ssh destination spec —
    # `ssh user@2001:db8::1` is ambiguous (older OpenSSH treats the trailing
    # `:1` as a port); `ssh user@[2001:db8::1]` is unambiguous. IPv4 +
    # hostnames pass through untouched.
    local dest_host="$host"
    [[ "$host" == *:* ]] && dest_host="[$host]"

    if [ "$DRY_RUN" = 1 ]; then
        printf '[DRY] %s@%s:%s  ->  %s/linenum.txt\n' "$user" "$dest_host" "$port" "$hdir"
        run_log "dry-run: $user@$dest_host:$port"
        return 0
    fi

    local ssh_args=()
    while IFS= read -r a; do ssh_args+=("$a"); done < <(ssh_base_args)
    ssh_args+=(-p "$port" "$user@$dest_host")

    local t0 t1 elapsed rc
    t0=$(date +%s)
    run_log "begin: $user@$host:$port"

    if [ -n "$SSH_PASS" ]; then
        SSHPASS="$SSH_PASS" sshpass -e ssh "${ssh_args[@]}" 'bash -s -- -v' \
            < "$LINENUM" > "$hdir/linenum.txt" 2> "$hdir/linenum.err"
    else
        ssh "${ssh_args[@]}" 'bash -s -- -v' \
            < "$LINENUM" > "$hdir/linenum.txt" 2> "$hdir/linenum.err"
    fi
    rc=$?

    t1=$(date +%s); elapsed=$((t1 - t0))
    run_log "end: $user@$host:$port rc=$rc elapsed=${elapsed}s"

    # Write _meta.json (small enough to hand-build; no python dep on the operator's box)
    cat > "$hdir/_meta.json" <<META
{
  "host":        "$host",
  "user":        "$user",
  "port":        $port,
  "rc":          $rc,
  "started":     "$(date -u -Iseconds -d @"$t0")",
  "elapsed_s":   $elapsed,
  "size_bytes":  $(stat -c %s "$hdir/linenum.txt" 2>/dev/null || echo 0),
  "err_bytes":   $(stat -c %s "$hdir/linenum.err" 2>/dev/null || echo 0),
  "ssh_port":    $port,
  "key_used":    "${SSH_KEY:-}",
  "pass_used":   $([ -n "$SSH_PASS" ] && echo true || echo false)
}
META

    [ "$rc" -eq 0 ] && touch "$hdir/.done"

    # Optional inter-host delay under --throttle
    [ "${ENUM_THROTTLE:-0}" = 1 ] && sleep "$ENUM_THROTTLE_DELAY"
    return 0  # never fail the parallel batch on a single-host miss
}

# Subshell exports — xargs spawns one bash per host, so functions + state must
# travel through env. The EXTRA_SSH_OPTS array is persisted to $SSH_EXTRA_FILE
# above and read on demand inside ssh_base_args.
export -f run_one_host parse_spec ssh_base_args run_log
export -f have log hit miss err
export RUN_LOG OUTDIR LINENUM RESUME DRY_RUN SSH_USER SSH_KEY SSH_PASS SSH_PORT
export CONNECT_TIMEOUT KNOWN_HOSTS SSH_EXTRA_FILE ENUM_THROTTLE ENUM_THROTTLE_DELAY

# ---------- dispatch loop ----------
total_hosts=$(grep -cvE '^\s*(#|$)' "$TARGETS" || true)
echo "[*] $total_hosts host(s) to enumerate -> $OUTDIR (parallel=$PARALLEL)"
run_log "dispatch: $total_hosts hosts, parallel=$PARALLEL"

if [ "$total_hosts" -eq 0 ]; then
    err "targets file has no host entries (after stripping comments/blanks)"
    exit 1
fi

# Stream non-comment / non-blank target lines into xargs -P. `-I{}` implies
# one-arg-per-invocation so no -n1 needed.
grep -vE '^\s*(#|$)' "$TARGETS" | xargs -I{} -P"$PARALLEL" \
    bash -c 'run_one_host "$@"' _ {}

# ---------- post-run summary ----------
ok=0; fail=0; skip=0
declare -a failed_hosts=()
{
    printf '#host\trc\telapsed_s\tsize_kb\n'
    for hdir in "$OUTDIR"/*/; do
        [ -d "$hdir" ] || continue
        host=$(basename "$hdir")
        [ -f "$hdir/_meta.json" ] || { skip=$((skip+1)); continue; }
        rc=$(grep -oE '"rc":[[:space:]]*-?[0-9]+' "$hdir/_meta.json" | head -1 | grep -oE '\-?[0-9]+$' || echo "?")
        el=$(grep -oE '"elapsed_s":[[:space:]]*[0-9]+' "$hdir/_meta.json" | head -1 | grep -oE '[0-9]+$' || echo 0)
        sz=$(grep -oE '"size_bytes":[[:space:]]*[0-9]+' "$hdir/_meta.json" | head -1 | grep -oE '[0-9]+$' || echo 0)
        sz_kb=$(( (sz + 1023) / 1024 ))
        printf '%s\t%s\t%s\t%s\n' "$host" "$rc" "$el" "$sz_kb"
        if [ "$rc" = "0" ]; then ok=$((ok+1)); else fail=$((fail+1)); failed_hosts+=("$host(rc=$rc)"); fi
    done
} > "$OUTDIR/_summary.tsv"

echo
echo "=== bulk-enum complete ==="
echo "OK=$ok  FAIL=$fail  SKIP=$skip"
if [ "$fail" -gt 0 ]; then
    echo "Failed hosts:"
    printf '  - %s\n' "${failed_hosts[@]}"
fi
echo "Summary: $OUTDIR/_summary.tsv"
echo "Per-host: $OUTDIR/<host>/linenum.txt"
echo "Next: network/report.py $OUTDIR    # findings.json + report.md + report.html"
run_log "complete: OK=$ok FAIL=$fail SKIP=$skip"

# Exit 0 even on per-host failures — the per-host rcs are in _meta.json.
# The orchestrator only fails on systemic problems (no targets, bad args).
exit 0
