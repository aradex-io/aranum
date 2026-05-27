#!/usr/bin/env bash
# redis-quickwin.sh — Redis detection + exploitability classification.
#
# For each target:
#   1. Reachability + auth state (tries empty + common default creds)
#   2. Version, OS, role, process user (from INFO)
#   3. CONFIG GET protected-mode, dir, dbfilename, requirepass
#   4. MODULE LIST + capability to load modules (version gate)
#   5. ACL WHOAMI / ACL LIST (Redis 6+)
#   6. Classify CRITICAL/HIGH/MEDIUM/LOW with one-line reason
#
# Output: per-host text file + summary report.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_redis_lib.sh"

# ---------------- args ----------------
TARGETS=""
TARGET=""
OUT="./redis-quickwin"
PASS_LIST=""
PASS_OVERRIDE=""
PARALLEL=4

# shellcheck disable=SC2034  # PASS_LIST: parsed but pending wire-through into the per-target cred sweep (TODO)
while [ $# -gt 0 ]; do
    case "$1" in
        --targets)   TARGETS="$2"; shift 2 ;;
        --target)    TARGET="$2";  shift 2 ;;
        --output|-o) OUT="$2"; shift 2 ;;
        --pass|-p)   PASS_OVERRIDE="$2"; shift 2 ;;
        --passlist)  PASS_LIST="$2"; shift 2 ;;
        --parallel)  PARALLEL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --target host:port | --targets file [-o outdir] [--pass X | --passlist file] [--parallel N]"
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

if ! have_redis_cli; then err "redis-cli not installed"; exit 1; fi
mkdir -p "$OUT"

scan_one() {
    local t="$1"
    parse_target "$t"
    local outfile="$OUT/${HOST}_${PORT}.txt"
    local tier="-" reason=""
    PASS="${PASS_OVERRIDE:-}"
    {
        echo "Target: $HOST:$PORT"
        echo "Time:   $(date -Is)"
        echo

        if ! probe_redis 2>/dev/null; then
            echo "STATE: unreachable"; tier="DOWN"
        else
            if [ "$AUTH_REQUIRED" = 1 ] && [ "$AUTHED" = 0 ]; then
                local hit
                hit=$(try_default_creds 2>/dev/null) && echo "WEAK PASSWORD: '$hit'"
            fi
            echo "STATE: reachable | auth_required=$AUTH_REQUIRED authed=$AUTHED | version=${REDIS_VERSION:-?}"
            echo

            if [ "$AUTHED" = 1 ]; then
                echo "--- INFO server ---"
                rcmd INFO server | tr -d '\r'
                echo
                echo "--- INFO clients ---"
                rcmd INFO clients | tr -d '\r'
                echo
                echo "--- CONFIG snapshot ---"
                for k in dir dbfilename requirepass protected-mode bind appendonly masterauth maxclients; do
                    v=$(rcmd CONFIG GET "$k" 2>/dev/null | tail -1)
                    printf "  %-15s = %s\n" "$k" "$v"
                done
                echo
                echo "--- MODULE LIST ---"
                rcmd MODULE LIST 2>/dev/null
                echo
                echo "--- ACL ---"
                rcmd ACL WHOAMI 2>/dev/null
                rcmd ACL LIST   2>/dev/null
                echo
                echo "--- CLIENT LIST (first 10) ---"
                rcmd CLIENT LIST 2>/dev/null | head -10

                # --- classify ---
                ver_major=${REDIS_VERSION%%.*}
                ver_major=${ver_major:-0}
                dir=$(rcmd CONFIG GET dir | tail -1)
                # shellcheck disable=SC2034  # collected for the per-host report log line below
                proc_user=$(rcmd INFO server 2>/dev/null | awk -F: '/process_id|executable/{print $0}')
                module_capable=0
                [ "$ver_major" -ge 4 ] && module_capable=1

                # Module RCE check — try MODULE LIST and see if denied
                ml_out=$(rcmd MODULE LIST 2>&1)
                if echo "$ml_out" | grep -qiE 'ERR unknown command|disabled|forbidden|not allowed'; then
                    module_capable=0
                fi

                if [ "$AUTH_REQUIRED" = 0 ] && [ "$module_capable" = 1 ]; then
                    tier="CRITICAL"; reason="unauth + MODULE LOAD capable (v$REDIS_VERSION) → redis-rce-module.sh"
                elif [ "$AUTHED" = 1 ] && [ -n "$PASS" ] && [ "$module_capable" = 1 ] && [ "$AUTH_REQUIRED" = 1 ]; then
                    tier="CRITICAL"; reason="weak/default password + MODULE LOAD capable → redis-rce-module.sh"
                elif [ "$AUTH_REQUIRED" = 0 ] && echo "$dir" | grep -qE '^/(root|home/redis|var/lib/redis)'; then
                    tier="HIGH"; reason="unauth + dir=$dir → redis-rce-ssh.sh likely succeeds"
                elif [ "$AUTH_REQUIRED" = 0 ]; then
                    tier="HIGH"; reason="unauth — review CONFIG/dir + MODULE LIST manually"
                elif [ "$AUTHED" = 1 ]; then
                    tier="MEDIUM"; reason="authenticated; review CLIENT LIST + KEYS * for cred leaks"
                else
                    tier="LOW"; reason="auth required, no default creds; cred spray or move on"
                fi
            else
                tier="LOW"; reason="auth required, no default creds matched"
            fi
        fi
        echo
        echo "TIER:   $tier"
        echo "REASON: $reason"
    } > "$outfile" 2>&1

    # Stream tier line for the summary
    case "$tier" in
        CRITICAL) printf "%s[!!] %-21s CRITICAL%s  %s\n" "$_R" "$HOST:$PORT" "$_RST" "$reason" ;;
        HIGH)     printf "%s[+]  %-21s HIGH%s      %s\n" "$_G" "$HOST:$PORT" "$_RST" "$reason" ;;
        MEDIUM)   printf "%s[*]  %-21s MEDIUM%s    %s\n" "$_C" "$HOST:$PORT" "$_RST" "$reason" ;;
        LOW)      printf "%s[-]  %-21s LOW%s       %s\n" "$_Y" "$HOST:$PORT" "$_RST" "$reason" ;;
        DOWN)     printf "[?]  %-21s DOWN\n" "$HOST:$PORT" ;;
        *)        printf "[?]  %-21s UNKNOWN\n" "$HOST:$PORT" ;;
    esac

    echo "$tier|$HOST:$PORT|$reason" >> "$OUT/_tiers.tsv"
}

export -f scan_one parse_target probe_redis try_default_creds rcmd save_config restore_config have_redis_cli log hit miss err crit
export OUT PASS_OVERRIDE _G _Y _R _C _RST

# ---------------- main ----------------
: > "$OUT/_tiers.tsv"

if [ -n "$TARGET" ]; then
    scan_one "$TARGET"
elif [ -n "$TARGETS" ] && [ -f "$TARGETS" ]; then
    if command -v parallel >/dev/null 2>&1; then
        parallel -j "$PARALLEL" scan_one :::: "$TARGETS"
    else
        # bash xargs fallback
        xargs -a "$TARGETS" -n1 -P"$PARALLEL" -I{} bash -c 'scan_one "$@"' _ {}
    fi
else
    err "specify --target or --targets"; exit 1
fi

# ---------------- summary ----------------
echo
echo "================== SUMMARY =================="
sort "$OUT/_tiers.tsv" | awk -F'|' '
    {count[$1]++}
    END {
        for (t in count) printf "  %-9s %d\n", t, count[t]
    }
' | sort
echo
echo "Critical hosts (next step: redis-rce-module.sh):"
awk -F'|' '$1=="CRITICAL"{print "  "$2"  ["$3"]"}' "$OUT/_tiers.tsv"
echo
echo "Detailed per-host reports in: $OUT/"
