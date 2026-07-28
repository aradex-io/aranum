#!/usr/bin/env bash
# bulk-enum-linux.sh — run standalones/linux/linenum-fast.sh against many hosts in parallel
# via stdin-pipe over SSH. Per ADR-002 + ADR-006 (workstream 1a).
#
# Output layout (mirrors auto-enum.sh):
#     <outdir>/
#       run.log              — central timestamped journal
#       hosts.txt            — copy of the input target list (audit)
#       known_hosts          — engagement-scoped SSH known_hosts silo
#       _summary.tsv         — one row per host
#                              (host  status  rc  elapsed_s  size_kb  fail_reason)
#       <host>/
#         linenum.txt        — raw stdout from linenum-fast.sh
#         linenum.err        — stderr (ssh errors + script warnings)
#         _meta.json         — {rc, status, fail_reason, auth_mode, started, ...}
#         .done              — written iff rc=0 (for --resume)
#
# The remote script is NEVER written to disk on the target. stdin-pipe means it
# lives only in the SSH session's bash memory.
#
# ---------------------------------------------------------------------------
# Auth modes (ADR-006 workstream 1a — canonical SSH-option spec):
#
#   KEY            --key and/or ssh-agent, no --pass. Non-interactive pubkey.
#                  BatchMode=yes, PreferredAuthentications=publickey,
#                  -i + IdentitiesOnly=yes when --key is given.
#   PASS           --pass, no --key. Password via sshpass -e.
#                  BatchMode=no (sshpass needs the interactive prompt),
#                  PubkeyAuthentication=no, NumberOfPasswordPrompts=1,
#                  PreferredAuthentications=keyboard-interactive,password.
#   KEY_THEN_PASS  both --key and --pass. Try the key first, fall back to the
#                  password. BatchMode=no, -i + IdentitiesOnly=yes,
#                  PreferredAuthentications=publickey,keyboard-interactive,password,
#                  NumberOfPasswordPrompts=1. PubkeyAuthentication is NOT disabled.
#
# The historical bug (ADR-006): BatchMode=yes was set unconditionally, including
# on the --pass path. BatchMode disables the interactive password prompt that
# sshpass exists to answer, so every host returned 255 "Permission denied".
# The option builder now keys every BatchMode / PubkeyAuthentication / -i choice
# off the explicit auth mode, never off the mere presence of a password.
#
# NOTE on passphrase-encrypted keys: in KEY_THEN_PASS mode with a passphrase-
# protected --key, ssh prompts "Enter passphrase for key ...". sshpass -e would
# feed the *login password* into that passphrase prompt (it matches "assword"),
# which is wrong. For encrypted keys, load them into ssh-agent instead
# (`ssh-add key`) and use KEY mode — the agent answers the passphrase once.
# ---------------------------------------------------------------------------

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINENUM="$PROJECT_ROOT/standalones/linux/linenum-fast.sh"

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
PREFLIGHT=1
RETRIES=1
RETRY_BACKOFF=2
# Per-host wall-clock cap for the whole enum (auth + remote script). A slow /
# tarpit / NFS-heavy target can otherwise pin its parallel slot forever —
# ssh ServerAlive only catches DEAD connections, not slow-but-alive ones.
# 0 = unlimited (legacy behaviour). Requires coreutils `timeout`.
HOST_TIMEOUT=600

usage() {
    cat <<EOF
Usage: $0 --targets <file> [-o <outdir>] [options]

Required:
  --targets FILE         one host per line. Format: 'host', 'user@host', or
                         'user@host:port'. Lines starting with '#' are skipped.
                         A bare host uses --user (or current \$USER).

Output:
  -o, --output DIR       results dir (default: $OUTDIR)

Auth (KEY / PASS / KEY_THEN_PASS — see header), or rely on ssh-agent:
  -u, --user USER        default username for bare-host lines
  -k, --key FILE         SSH private key (-i FILE). For passphrase-encrypted
                         keys prefer ssh-agent (ssh-add) — see header note.
  --pass PASSWORD        password via sshpass (sshpass MUST be installed)
                         WARNING: visible in 'ps'; prefer --key or ssh-agent
                         --key + --pass = try key first, fall back to password.

Connection:
  --port N               default SSH port (default: $SSH_PORT)
  --connect-timeout SEC  ssh ConnectTimeout (default: $CONNECT_TIMEOUT)
  --ssh-opt 'K=V'        repeatable extra '-o K=V' (e.g. ProxyJump=bastion)
  --jump HOST            shorthand for --ssh-opt 'ProxyJump=HOST'

Reliability:
  --preflight            auth-probe the first host before the fan-out (default on)
  --no-preflight         skip the preflight probe
  --retries N            attempts per host (default: $RETRIES). Retries only
                         TIMEOUT/UNREACHABLE — never AUTH_FAIL (lockout risk).
  --host-timeout SEC     wall-clock cap per host for auth+enum (default:
                         $HOST_TIMEOUT, 0=unlimited). A slow/tarpit/NFS host that
                         exceeds it is killed and marked HOST_TIMEOUT (partial
                         output kept). Needs coreutils 'timeout'.

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
  $0 --targets dev.txt -P 8 --jump bastion.corp -o ./dev
  $0 --targets prev.txt --resume -o ./prev    # continue an interrupted run

Per-host status (in _summary.tsv / _meta.json):
  OK  AUTH_FAIL  UNREACHABLE  TIMEOUT  REMOTE_ERR

Per ADR-002:
  - linenum-fast.sh is piped over stdin (never lands on target disk)
  - known_hosts is per-engagement (\$OUTDIR/known_hosts) — not ~/.ssh/known_hosts
  - StrictHostKeyChecking=accept-new on first contact; verified thereafter

After the run:
  aranumtoolkit/network/report.py \$OUTDIR        # findings.json + report.md + report.html
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
        --jump)            EXTRA_SSH_OPTS_ARR+=(-o "ProxyJump=$2"); shift 2 ;;
        --preflight)       PREFLIGHT=1; shift ;;
        --no-preflight)    PREFLIGHT=0; shift ;;
        --retries)         RETRIES="$2"; shift 2 ;;
        --host-timeout)    HOST_TIMEOUT="$2"; shift 2 ;;
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

if ! [[ "$RETRIES" =~ ^[0-9]+$ ]] || [ "$RETRIES" -lt 1 ]; then
    err "--retries must be a positive integer (got: $RETRIES)"
    exit 2
fi

if ! [[ "$HOST_TIMEOUT" =~ ^[0-9]+$ ]]; then
    err "--host-timeout must be a non-negative integer of seconds (got: $HOST_TIMEOUT)"
    exit 2
fi
# Enforce a host-timeout only if coreutils `timeout` exists; degrade loudly.
# The per-host wrapper array is rebuilt inside run_one_host from this scalar
# (arrays can't cross the xargs subshell boundary; the scalar is exported).
if [ "$HOST_TIMEOUT" -gt 0 ] && ! have timeout; then
    err "--host-timeout $HOST_TIMEOUT requested but coreutils 'timeout' not found — running without a per-host cap"
    HOST_TIMEOUT=0
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
run_log "targets=$TARGETS outdir=$OUTDIR parallel=$PARALLEL resume=$RESUME throttle=$THROTTLE retries=$RETRIES preflight=$PREFLIGHT"
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

# ---------- auth mode selection (ADR-006 1a) ----------
# Determine the auth mode from which of --key/--pass are set. This is the single
# switch that all BatchMode / PubkeyAuthentication / -i decisions key off — never
# the mere presence of a password.
auth_mode() {
    if [[ -n "$SSH_KEY" && -n "$SSH_PASS" ]]; then
        printf 'KEY_THEN_PASS'
    elif [[ -n "$SSH_PASS" ]]; then
        printf 'PASS'
    else
        printf 'KEY'
    fi
}

# ---------- common ssh args (mode-aware, ADR-006 canonical spec table) ----------
ssh_base_args() {
    local mode="$1"
    local args=(
        -o "ConnectTimeout=$CONNECT_TIMEOUT"
        -o "ServerAliveInterval=15"
        -o "ServerAliveCountMax=4"
        -o "StrictHostKeyChecking=accept-new"
        -o "UserKnownHostsFile=$KNOWN_HOSTS"
        -o "LogLevel=ERROR"
    )
    case "$mode" in
        KEY)
            args+=(-o "BatchMode=yes" -o "PreferredAuthentications=publickey")
            if [[ -n "$SSH_KEY" ]]; then
                args+=(-i "$SSH_KEY" -o "IdentitiesOnly=yes")
            fi
            ;;
        PASS)
            # No BatchMode=yes: sshpass drives the interactive password prompt.
            args+=(
                -o "BatchMode=no"
                -o "PubkeyAuthentication=no"
                -o "PreferredAuthentications=keyboard-interactive,password"
                -o "NumberOfPasswordPrompts=1"
            )
            ;;
        KEY_THEN_PASS)
            # Pubkey stays ENABLED so the key is offered first; password is the
            # fallback. Only the one given key is offered (IdentitiesOnly).
            args+=(
                -o "BatchMode=no"
                -o "PreferredAuthentications=publickey,keyboard-interactive,password"
                -o "NumberOfPasswordPrompts=1"
                -i "$SSH_KEY"
                -o "IdentitiesOnly=yes"
            )
            ;;
        *)
            err "internal: unknown auth mode '$mode'"; return 1 ;;
    esac
    if [ -s "$SSH_EXTRA_FILE" ]; then
        while IFS= read -r line; do args+=("$line"); done < "$SSH_EXTRA_FILE"
    fi
    printf '%s\n' "${args[@]}"
}

# ---------- status classification (ADR-006 D1a-2) ----------
# Map (ssh rc + stderr) -> "STATUS<TAB>fail_reason".
#   OK           rc == 0
#   AUTH_FAIL    rc 255 + "Permission denied" (or sshpass incorrect-password rc 5)
#   UNREACHABLE  rc 255 + connection refused / no route / DNS failure / unknown
#   TIMEOUT      rc 255 + timed out
#   REMOTE_ERR   any other non-zero rc — auth succeeded, remote bash -s exited !=0
classify_status() {
    local rc="$1" errfile="$2"
    local status="OK" fail=""
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
            # coreutils `timeout` fired (TERM=124, KILL-after-grace=137): auth may
            # have succeeded but the enum exceeded --host-timeout. Partial output
            # in linenum.txt is kept. Distinct from connect-level TIMEOUT so the
            # retry loop does NOT re-run it (a slow host stays slow).
            status="HOST_TIMEOUT"; fail="enum exceeded --host-timeout"
        elif [ "$rc" -eq 255 ]; then
            if grep -qiE 'permission denied|authentication failed|too many authentication failures' "$errfile" 2>/dev/null; then
                status="AUTH_FAIL"; fail="permission denied"
            elif grep -qiE 'connection refused|no route to host|network is unreachable|name or service not known|could not resolve|connection closed' "$errfile" 2>/dev/null; then
                status="UNREACHABLE"; fail="host unreachable"
            elif grep -qiE 'timed out|timeout' "$errfile" 2>/dev/null; then
                status="TIMEOUT"; fail="connection timed out"
            else
                status="UNREACHABLE"; fail="ssh transport error (rc=255)"
            fi
        elif [ "$rc" -eq 5 ] && [ -n "$SSH_PASS" ]; then
            # sshpass exit 5 = it detected an incorrect-password re-prompt.
            status="AUTH_FAIL"; fail="sshpass: incorrect password"
        else
            status="REMOTE_ERR"; fail="remote command exited rc=$rc"
        fi
    fi
    # Keep fail_reason JSON-safe (we only emit controlled strings, but be strict).
    fail="${fail//\"/}"
    fail="${fail//$'\n'/ }"
    printf '%s\t%s\n' "$status" "$fail"
}

# Parse a target spec line into "user host port"
parse_spec() {
    local spec="$1"
    local user host port rest
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

    # Sanitise host into a single safe path component for the OUTPUT dir only —
    # a hostile/malformed targets line (e.g. ../../x) must never make mkdir
    # escape $OUTDIR (OPSEC §9). The ssh connection below still uses $host.
    local safe_host="${host//[^A-Za-z0-9._:-]/_}"
    case "$safe_host" in ""|"."|"..") safe_host="host" ;; esac
    local hdir="$OUTDIR/$safe_host"
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

    local mode; mode=$(auth_mode)

    if [ "$DRY_RUN" = 1 ]; then
        printf '[DRY] %s@%s:%s  (mode=%s)  ->  %s/linenum.txt\n' "$user" "$dest_host" "$port" "$mode" "$hdir"
        run_log "dry-run: $user@$dest_host:$port mode=$mode"
        return 0
    fi

    local ssh_args=()
    while IFS= read -r a; do ssh_args+=("$a"); done < <(ssh_base_args "$mode")
    ssh_args+=(-p "$port" "$user@$dest_host")

    # Per-host wall-clock cap, rebuilt here from the exported scalar (arrays
    # can't be exported to this xargs subshell). Empty when HOST_TIMEOUT=0.
    local -a to_cmd=()
    if [ "${HOST_TIMEOUT:-0}" -gt 0 ]; then
        to_cmd=(timeout --signal=TERM --kill-after=10 "$HOST_TIMEOUT")
    fi

    local t0 t1 elapsed rc attempt status fail
    t0=$(date +%s)
    attempt=1
    status="UNREACHABLE"; fail=""
    while : ; do
        run_log "begin: $user@$host:$port (mode=$mode attempt=$attempt/$RETRIES)"
        if [ -n "$SSH_PASS" ]; then
            SSHPASS="$SSH_PASS" "${to_cmd[@]}" sshpass -e ssh "${ssh_args[@]}" 'bash -s -- -v' \
                < "$LINENUM" > "$hdir/linenum.txt" 2> "$hdir/linenum.err"
        else
            "${to_cmd[@]}" ssh "${ssh_args[@]}" 'bash -s -- -v' \
                < "$LINENUM" > "$hdir/linenum.txt" 2> "$hdir/linenum.err"
        fi
        rc=$?
        IFS=$'\t' read -r status fail < <(classify_status "$rc" "$hdir/linenum.err")

        # Retry ONLY transient transport failures — never AUTH_FAIL (lockout risk),
        # never REMOTE_ERR (auth already succeeded; re-running won't help).
        if { [ "$status" = "TIMEOUT" ] || [ "$status" = "UNREACHABLE" ]; } && [ "$attempt" -lt "$RETRIES" ]; then
            run_log "retry: $user@$host:$port status=$status attempt=$attempt (backoff $((RETRY_BACKOFF * attempt))s)"
            sleep "$((RETRY_BACKOFF * attempt))"
            attempt=$((attempt + 1))
            continue
        fi
        break
    done

    t1=$(date +%s); elapsed=$((t1 - t0))
    run_log "end: $user@$host:$port rc=$rc status=$status elapsed=${elapsed}s attempts=$attempt"

    # Write _meta.json (small enough to hand-build; no python dep on the operator's box)
    cat > "$hdir/_meta.json" <<META
{
  "host":        "$host",
  "user":        "$user",
  "port":        $port,
  "rc":          $rc,
  "status":      "$status",
  "fail_reason": "$fail",
  "auth_mode":   "$mode",
  "attempts":    $attempt,
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
export -f run_one_host parse_spec ssh_base_args auth_mode classify_status run_log
export -f have log hit miss err
export RUN_LOG OUTDIR LINENUM RESUME DRY_RUN SSH_USER SSH_KEY SSH_PASS SSH_PORT
export CONNECT_TIMEOUT KNOWN_HOSTS SSH_EXTRA_FILE ENUM_THROTTLE ENUM_THROTTLE_DELAY
export RETRIES RETRY_BACKOFF HOST_TIMEOUT

# ---------- preflight (ADR-006 D1a-3) ----------
# Auth-probe the first non-comment host before burning the whole list. On
# AUTH_FAIL we print a loud warning but CONTINUE (operator may hold per-host creds).
preflight_probe() {
    local first_spec pf_parsed pf_user pf_host pf_port pf_dest pf_mode pf_rc pf_err
    local pf_status pf_reason
    first_spec=$(grep -vE '^\s*(#|$)' "$TARGETS" | head -1)
    [ -z "$first_spec" ] && return 0
    pf_parsed=$(parse_spec "$first_spec") || return 0
    [ -z "$pf_parsed" ] && return 0
    IFS=$'\t' read -r pf_user pf_host pf_port <<< "$pf_parsed"
    pf_dest="$pf_host"; [[ "$pf_host" == *:* ]] && pf_dest="[$pf_host]"
    pf_mode=$(auth_mode)

    local pf_args=()
    while IFS= read -r a; do pf_args+=("$a"); done < <(ssh_base_args "$pf_mode")
    pf_args+=(-p "$pf_port" "$pf_user@$pf_dest")

    pf_err=$(mktemp "$OUTDIR/.preflight.XXXXXX")
    echo "[*] preflight: auth-probing $pf_user@$pf_host:$pf_port (mode=$pf_mode)"
    if [ -n "$SSH_PASS" ]; then
        SSHPASS="$SSH_PASS" sshpass -e ssh "${pf_args[@]}" 'true' </dev/null >/dev/null 2> "$pf_err"
    else
        ssh "${pf_args[@]}" 'true' </dev/null >/dev/null 2> "$pf_err"
    fi
    pf_rc=$?
    IFS=$'\t' read -r pf_status pf_reason < <(classify_status "$pf_rc" "$pf_err")
    rm -f "$pf_err"
    run_log "preflight: $pf_user@$pf_host:$pf_port rc=$pf_rc status=$pf_status"
    if [ "$pf_status" = "AUTH_FAIL" ]; then
        err "auth failed against first host — check creds/transport before burning the list (continuing anyway)"
    else
        echo "[*] preflight status: $pf_status"
    fi
    return 0
}

# ---------- dispatch loop ----------
total_hosts=$(grep -cvE '^\s*(#|$)' "$TARGETS" || true)
echo "[*] $total_hosts host(s) to enumerate -> $OUTDIR (parallel=$PARALLEL)"
run_log "dispatch: $total_hosts hosts, parallel=$PARALLEL"

if [ "$total_hosts" -eq 0 ]; then
    err "targets file has no host entries (after stripping comments/blanks)"
    exit 1
fi

if [ "$PREFLIGHT" = 1 ] && [ "$DRY_RUN" = 0 ]; then
    preflight_probe
fi

# Stream non-comment / non-blank target lines into xargs -P. `-I{}` implies
# one-arg-per-invocation so no -n1 needed.
grep -vE '^\s*(#|$)' "$TARGETS" | xargs -I{} -P"$PARALLEL" \
    bash -c 'run_one_host "$@"' _ {}

# ---------- post-run summary ----------
ok=0; fail=0; skip=0
auth_fail=0; unreach=0; timeout=0; remote_err=0; host_timeout=0
declare -a failed_hosts=()
{
    printf '#host\tstatus\trc\telapsed_s\tsize_kb\tfail_reason\n'
    for hdir in "$OUTDIR"/*/; do
        [ -d "$hdir" ] || continue
        host=$(basename "$hdir")
        [ -f "$hdir/_meta.json" ] || { skip=$((skip+1)); continue; }
        rc=$(grep -oE '"rc":[[:space:]]*-?[0-9]+' "$hdir/_meta.json" | head -1 | grep -oE '\-?[0-9]+$' || echo "?")
        st=$(grep -oE '"status":[[:space:]]*"[A-Z_]+"' "$hdir/_meta.json" | head -1 | grep -oE '[A-Z_]+' | tail -1 || echo "?")
        fr=$(grep -oE '"fail_reason":[[:space:]]*"[^"]*"' "$hdir/_meta.json" | head -1 | sed -E 's/.*"fail_reason":[[:space:]]*"([^"]*)".*/\1/' || echo "")
        el=$(grep -oE '"elapsed_s":[[:space:]]*[0-9]+' "$hdir/_meta.json" | head -1 | grep -oE '[0-9]+$' || echo 0)
        sz=$(grep -oE '"size_bytes":[[:space:]]*[0-9]+' "$hdir/_meta.json" | head -1 | grep -oE '[0-9]+$' || echo 0)
        sz_kb=$(( (sz + 1023) / 1024 ))
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$host" "$st" "$rc" "$el" "$sz_kb" "$fr"
        case "$st" in
            OK)          ok=$((ok+1)) ;;
            AUTH_FAIL)   auth_fail=$((auth_fail+1)); fail=$((fail+1)); failed_hosts+=("$host($st)") ;;
            UNREACHABLE) unreach=$((unreach+1));     fail=$((fail+1)); failed_hosts+=("$host($st)") ;;
            TIMEOUT)     timeout=$((timeout+1));     fail=$((fail+1)); failed_hosts+=("$host($st)") ;;
            REMOTE_ERR)  remote_err=$((remote_err+1)); fail=$((fail+1)); failed_hosts+=("$host($st)") ;;
            HOST_TIMEOUT) host_timeout=$((host_timeout+1)); fail=$((fail+1)); failed_hosts+=("$host($st)") ;;
            *)           fail=$((fail+1)); failed_hosts+=("$host(rc=$rc)") ;;
        esac
    done
} > "$OUTDIR/_summary.tsv"

echo
echo "=== bulk-enum complete ==="
echo "OK=$ok  FAIL=$fail  SKIP=$skip"
echo "status: OK=$ok  AUTH_FAIL=$auth_fail  UNREACHABLE=$unreach  TIMEOUT=$timeout  HOST_TIMEOUT=$host_timeout  REMOTE_ERR=$remote_err"
if [ "$fail" -gt 0 ]; then
    echo "Failed hosts:"
    printf '  - %s\n' "${failed_hosts[@]}"
fi
echo "Summary: $OUTDIR/_summary.tsv"
echo "Per-host: $OUTDIR/<host>/linenum.txt"
echo "Next: aranumtoolkit/network/report.py $OUTDIR    # findings.json + report.md + report.html"
run_log "complete: OK=$ok FAIL=$fail SKIP=$skip (AUTH_FAIL=$auth_fail UNREACHABLE=$unreach TIMEOUT=$timeout HOST_TIMEOUT=$host_timeout REMOTE_ERR=$remote_err)"

# Exit 0 even on per-host failures — the per-host rcs/statuses are in _meta.json.
# The orchestrator only fails on systemic problems (no targets, bad args).
exit 0
