#!/usr/bin/env bash
# redis-rce-lua.sh — Redis Lua (EVAL) RCE detection + scripting-reachability check.
#
# WHY THIS EXISTS: on Redis 7.0+ `MODULE LOAD` is blocked by policy
# (enable-module-command no) and the rogue-master `.so` is deleted after RDB
# signature validation — so redis-rce-module.sh dead-ends there. The Lua
# interpreter reached via `EVAL` is the live RCE surface on exactly those hosts:
#   * CVE-2024-31449 — stack overflow in the Lua `bit` library, authenticated
#     EVAL, affects Redis < 7.4.1 (and the 7.2.x / 6.2.x maintenance lines).
#   * Historical Lua sandbox escapes (cjson/cmsgpack/struct) on older builds.
#
# SCOPE (CLAUDE.md §1 — validated PoCs / enumeration only): this helper
# DETECTS the precondition and, with --verify, confirms EVAL scripting is
# actually reachable by running a BENIGN marker script. It does NOT ship a
# memory-corruption payload for CVE-2024-31449 — that requires a crafted
# overflow; the version window + public-PoC pointer are emitted in _hints.txt
# so the operator can proceed under their own authorization.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_redis_lib.sh"

TARGET=""
PASS=""
OUT="./redis-lua"
VERIFY=0

usage() {
    cat <<EOF
Usage: $0 --target host[:port] [--pass P] [-o OUTDIR] [--verify]

  --target host[:port]   Redis target (port defaults to 6379)
  --pass P               AUTH password if the instance requires it
  -o, --output OUTDIR    output dir (default ./redis-lua)
  --verify               run a BENIGN EVAL marker to confirm scripting is reachable
                         (no exploitation — just proves the interpreter answers)
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target)     TARGET="$2"; shift 2 ;;
        --pass|-p)    PASS="$2"; shift 2 ;;
        --output|-o)  OUT="$2"; shift 2 ;;
        --verify)     VERIFY=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; usage; exit 1; }
if ! have_redis_cli; then err "redis-cli not installed"; exit 1; fi
mkdir -p "$OUT"

parse_target "$TARGET"
probe_redis || { err "redis unreachable at $HOST:$PORT"; exit 2; }
if [ "$AUTH_REQUIRED" = 1 ] && [ "$AUTHED" = 0 ]; then
    err "AUTH required and no working password supplied (Lua EVAL is authenticated)"; exit 3
fi
hit "Connected to $HOST:$PORT (v${REDIS_VERSION:-?})"

report="$OUT/${HOST}_${PORT}.txt"
{
    echo "Target:  $HOST:$PORT"
    echo "Version: ${REDIS_VERSION:-unknown}"
    echo "Auth:    required=$AUTH_REQUIRED authed=$AUTHED"
    echo
} > "$report"

# --- version gate for the Lua bit-lib overflow (CVE-2024-31449, fixed 7.4.1) ---
ver="${REDIS_VERSION:-}"
lua_cve="unknown"
if [ -n "$ver" ]; then
    # vulnerable if version < 7.4.1 (coarse: covers 6.x/7.0-7.4.0 maintenance lines)
    lowest=$(printf '%s\n%s\n' "$ver" "7.4.1" | sort -V | head -1)
    if [ "$ver" != "7.4.1" ] && [ "$lowest" = "$ver" ]; then
        lua_cve="candidate"
        crit "CVE-2024-31449 (Lua bit-lib EVAL stack overflow) candidate — Redis $ver < 7.4.1"
        echo "LUA_RCE: CVE-2024-31449 candidate (Redis $ver < 7.4.1) — authenticated EVAL" >> "$report"
    else
        echo "LUA_RCE: version $ver >= 7.4.1 — CVE-2024-31449 patched (Lua sandbox still worth manual review)" >> "$report"
    fi
fi

# --- confirm EVAL scripting is actually reachable (ACL may deny it) ---
if [ "$VERIFY" = 1 ]; then
    marker="aranum-lua-$$-ok"
    out=$(rcmd EVAL "return '$marker'" 0 2>&1)
    if printf '%s' "$out" | grep -q "$marker"; then
        crit "EVAL scripting REACHABLE on $HOST:$PORT — Lua interpreter answers (marker echoed)"
        echo "EVAL_REACHABLE: yes — interpreter returned the benign marker" >> "$report"
    elif printf '%s' "$out" | grep -qiE 'NOPERM|unknown command|ACL'; then
        miss "EVAL denied by ACL/policy on $HOST:$PORT — Lua RCE not reachable with these creds"
        echo "EVAL_REACHABLE: no — denied ($out)" >> "$report"
    else
        miss "EVAL returned an unexpected reply: $out"
        echo "EVAL_REACHABLE: unclear ($out)" >> "$report"
    fi
fi

cat > "$OUT/_hints.txt" <<EOF
Redis Lua (EVAL) RCE follow-ups:
  * CVE-2024-31449: authenticated EVAL stack overflow in the Lua 'bit' library,
    fixed in Redis 7.4.1 (backported to 7.2.6 / 6.2.16). Exploitation requires a
    crafted Lua payload that overflows the bit-lib stack — this helper does NOT
    ship that payload (§1). Public analysis/PoC: search "CVE-2024-31449 redis lua".
  * Precondition confirmed above: EVAL must be permitted by the ACL of the
    authenticated user (default user typically has +@scripting).
  * Older builds: review the Lua sandbox (cjson/cmsgpack/struct) escape lineage.
  * If MODULE LOAD is available instead, use redis-rce-module.sh (7.0+ blocks it).
EOF

log "redis-rce-lua done — see $report"
