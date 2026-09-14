# shellcheck shell=bash
# _lib.sh — shared helpers for enum dispatchers. Source me, don't exec.
# Expects: ENUM_USER ENUM_PASS ENUM_HASH ENUM_DOMAIN ENUM_DC_IP ENUM_PARALLEL

# --------------- arg parsing ---------------
parse_common_args() {
    TARGETS=""
    OUT=""
    ENUM_TASK_ID=""
    ENUM_TASK_SERVICE=""
    ENUM_TASK_PHASE=""
    ENUM_TASK_PROTOCOL=""
    ENUM_TASK_RISK=""
    ENUM_TASK_PRIORITY=""
    ENUM_TASK_TARGET=""
    while [ $# -gt 0 ]; do
        case "$1" in
            # Arity guard BEFORE touching $2: under the callers' `set -u`,
            # `--targets` with no value would abort on the unbound $2, and a
            # naive ${2:-} would infinite-loop (shift 2 with one arg is a no-op).
            --targets)
                [ $# -ge 2 ] || { echo "missing value for $1"; return 1; }
                TARGETS="$2"; shift 2 ;;
            --output)
                [ $# -ge 2 ] || { echo "missing value for $1"; return 1; }
                OUT="$2"; shift 2 ;;
            --task-id|--task-service|--task-phase|--task-protocol|--task-risk|--task-priority|--task-target)
                [ $# -ge 2 ] || { echo "missing value for $1"; return 1; }
                case "$1" in
                    --task-id)       ENUM_TASK_ID="$2" ;;
                    --task-service)  ENUM_TASK_SERVICE="$2" ;;
                    --task-phase)    ENUM_TASK_PHASE="$2" ;;
                    --task-protocol) ENUM_TASK_PROTOCOL="$2" ;;
                    --task-risk)     ENUM_TASK_RISK="$2" ;;
                    --task-priority) ENUM_TASK_PRIORITY="$2" ;;
                    --task-target)   ENUM_TASK_TARGET="$2" ;;
                esac
                shift 2 ;;
            *) echo "unknown arg: $1"; return 1 ;;
        esac
    done
    if [ -z "$TARGETS" ] || [ -z "$OUT" ]; then
        echo "usage: $0 --targets <file> --output <dir>"
        return 1
    fi
    if [ ! -f "$TARGETS" ]; then
        echo "targets file missing: $TARGETS"
        return 1
    fi
    if ! mkdir -p "$OUT" || [ ! -d "$OUT" ]; then
        echo "cannot create evidence output directory: $OUT"
        return 1
    fi

    # Queue mode is a real dispatcher contract, not an out-of-band task-file
    # hint.  When any task constraint is supplied, require and validate the
    # complete set before a dispatcher can touch an endpoint.  The targets file
    # must contain exactly the selected task endpoint, so a service-wide target
    # list cannot accidentally execute or complete unselected work.
    local task_fields=0 value
    for value in "$ENUM_TASK_ID" "$ENUM_TASK_SERVICE" "$ENUM_TASK_PHASE" \
                 "$ENUM_TASK_PROTOCOL" "$ENUM_TASK_RISK" "$ENUM_TASK_PRIORITY" \
                 "$ENUM_TASK_TARGET"; do
        [ -n "$value" ] && task_fields=$((task_fields + 1))
    done
    if [ "$task_fields" -ne 0 ]; then
        if [ "$task_fields" -ne 7 ]; then
            echo "incomplete task constraints: task id/service/phase/protocol/risk/priority/target are all required"
            return 1
        fi
        case "$ENUM_TASK_PROTOCOL" in tcp|udp) ;; *) echo "invalid task protocol: $ENUM_TASK_PROTOCOL"; return 1 ;; esac
        case "$ENUM_TASK_PRIORITY" in
            ''|*[!0-9]*) echo "invalid task priority: $ENUM_TASK_PRIORITY"; return 1 ;;
        esac
        if [ "$ENUM_TASK_PRIORITY" -gt 999 ]; then
            echo "invalid task priority: $ENUM_TASK_PRIORITY"
            return 1
        fi
        local -a constrained_targets=()
        mapfile -t constrained_targets < <(sed '/^[[:space:]]*$/d' "$TARGETS")
        if [ "${#constrained_targets[@]}" -ne 1 ] || [ "${constrained_targets[0]}" != "$ENUM_TASK_TARGET" ]; then
            echo "task target constraint mismatch: expected exactly $ENUM_TASK_TARGET"
            return 1
        fi
        local task_contract
        if ! task_contract=$(python3 - "${SCRIPT_DIR:?}" "$ENUM_TASK_SERVICE" "$ENUM_TASK_PHASE" <<'PY'
import json, pathlib, sys
script_dir, service, phase = sys.argv[1:]
metadata = json.loads((pathlib.Path(script_dir) / "service-metadata.json").read_text())
contract = metadata.get("services", {}).get(service)
if not isinstance(contract, dict):
    raise SystemExit(f"unknown task service: {service}")
execution = str(contract.get(
    "task_execution", metadata.get("defaults", {}).get("task_execution", "monolithic")
)).lower()
if execution not in {"monolithic", "phased"}:
    raise SystemExit(f"invalid task_execution for {service}: {execution}")
declared = [str(item.get("id")) for item in contract.get("phases", [])
            if isinstance(item, dict) and item.get("id") is not None]
allowed = declared if execution == "phased" else ["all"]
if phase not in allowed:
    raise SystemExit(
        f"unsupported task phase for {service}: {phase} "
        f"(task_execution={execution}; allowed={','.join(allowed)})")
print(f"{execution}\t{' '.join(allowed)}")
PY
        ); then
            return 1
        fi
        IFS=$'\t' read -r ENUM_TASK_EXECUTION ENUM_TASK_ALLOWED_PHASES <<< "$task_contract"
        export ENUM_TASK_ID ENUM_TASK_SERVICE ENUM_TASK_PHASE ENUM_TASK_PROTOCOL
        export ENUM_TASK_RISK ENUM_TASK_PRIORITY ENUM_TASK_TARGET
        export ENUM_TASK_EXECUTION ENUM_TASK_ALLOWED_PHASES
        export ENUM_TASK_CONSTRAINED=1

        # Durable, dispatcher-authored provenance.  Completion is recorded by
        # auto-enum only after this constrained dispatcher process exits.
        if ! python3 - "$OUT/_task-context.json" "$ENUM_TASK_ID" "$ENUM_TASK_SERVICE" \
            "$ENUM_TASK_PHASE" "$ENUM_TASK_PROTOCOL" "$ENUM_TASK_RISK" \
            "$ENUM_TASK_PRIORITY" "$ENUM_TASK_TARGET" <<'PY'
import json, os, sys, tempfile
path, task_id, service, phase, protocol, risk, priority, target = sys.argv[1:]
if target.startswith("[") and "]:" in target:
    ip, port = target[1:].rsplit("]:", 1)
else:
    ip, port = target.rsplit(":", 1)
payload = {"schema_version": 1, "task_id": task_id, "service": service,
           "phase": phase, "protocol": protocol, "risk": risk,
           "priority": int(priority), "target_label": target,
           "target": {"ip": ip, "port": int(port), "proto": protocol}}
directory = os.path.dirname(path) or "."
fd, tmp = tempfile.mkstemp(prefix=".task-context.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
        then
            echo "cannot write task execution context: $OUT"
            return 1
        fi
    else
        unset ENUM_TASK_CONSTRAINED
    fi
    return 0
}

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

# Dispatcher phase gate.  Normal direct/service-batch runs retain their full
# historical behavior; a constrained queue task executes only blocks declared
# for its selected planner phase.
task_phase_is() {
    [ "${ENUM_TASK_CONSTRAINED:-0}" != "1" ] || [ "${ENUM_TASK_PHASE:-}" = "$1" ]
}

# Declare the phases a dispatcher implements as independently executable
# production paths.  Constrained queue runs fail before probing when a planner
# task names a phase the dispatcher cannot honor; ordinary direct/service-batch
# runs remain cumulative and execute every declared phase.
task_phase_require() {
    [ "${ENUM_TASK_CONSTRAINED:-0}" = "1" ] || return 0
    local supported
    for supported in ${ENUM_TASK_ALLOWED_PHASES:-}; do
        [ "$ENUM_TASK_PHASE" = "$supported" ] && return 0
    done
    echo "unsupported task phase for $ENUM_TASK_SERVICE: $ENUM_TASK_PHASE (supported: ${ENUM_TASK_ALLOWED_PHASES:-none})"
    return 1
}

# Run one independently-scoped phase function.  This is the common dispatcher
# mechanism for phase-aware queue execution: direct runs execute every block,
# while a constrained task can enter only its selected block.
task_phase_run() {
    local phase="$1"
    shift
    task_phase_is "$phase" || return 0
    "$@"
}

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    _ARANUM_GREEN=$'\033[1;32m'
    _ARANUM_YELLOW=$'\033[1;33m'
    _ARANUM_RED=$'\033[1;31m'
    _ARANUM_RESET=$'\033[0m'
else
    _ARANUM_GREEN=""
    _ARANUM_YELLOW=""
    _ARANUM_RED=""
    _ARANUM_RESET=""
fi
hit()  { printf "%s[+]%s %s\n" "$_ARANUM_GREEN" "$_ARANUM_RESET" "$*"; }
miss() { printf "%s[-]%s %s\n" "$_ARANUM_YELLOW" "$_ARANUM_RESET" "$*"; }
err()  { printf "%s[!]%s %s\n" "$_ARANUM_RED" "$_ARANUM_RESET" "$*"; }
crit() { printf "%s[!!]%s %s\n" "$_ARANUM_RED" "$_ARANUM_RESET" "$*"; }

# split  ip:port  or  [v6]:port  -> echoes "<ip> <port>"
split_ipport() {
    local t="$1"
    if [[ "$t" == \[*\]:* ]]; then
        # [2001:db8::1]:22 -> 2001:db8::1 22
        local ip="${t#[}"
        ip="${ip%%]:*}"
        echo "$ip" "${t##*]:}"
    else
        # 10.0.0.1:22 -> 10.0.0.1 22
        echo "${t%:*}" "${t##*:}"
    fi
}

# Print unique IPs from a targets file (handles ipv4 + bracketed ipv6).
ips_only() {
    awk '{
        n = $1
        if (n ~ /^\[.*\]:[0-9]+$/) {
            sub(/^\[/, "", n); sub(/\]:.*$/, "", n)
        } else {
            sub(/:[0-9]+$/, "", n)
        }
        print n
    }' "$1" | sort -u
}

# Print "ip port" pairs from a targets file (one per line).
ip_port_pairs() {
    while read -r t _; do
        [ -z "$t" ] && continue
        split_ipport "$t"
    done < "$1"
}

# Populate the named bash array with nxc/netexec credential flags built from
# ENUM_USER/ENUM_PASS/ENUM_HASH/ENUM_DOMAIN. Use this instead of string
# concatenation — a credential containing quotes/spaces will not break the
# command line, and there is no eval/word-split surface for an attacker
# (or for a fat-fingered operator) to exploit.
#
# Usage:
#     local args=()
#     nxc_creds_array args
#     "$NXC" smb - "${args[@]}" --shares
#
# Requires bash >= 4.3 for namerefs (declare -n).
nxc_creds_array() {
    local -n _arr="$1"
    _arr=()
    if [ -n "${ENUM_USER:-}" ]; then
        _arr+=(-u "$ENUM_USER")
        if   [ -n "${ENUM_HASH:-}" ]; then _arr+=(-H "$ENUM_HASH")
        elif [ -n "${ENUM_PASS:-}" ]; then _arr+=(-p "$ENUM_PASS")
        fi
        [ -n "${ENUM_DOMAIN:-}" ] && _arr+=(-d "$ENUM_DOMAIN")
    fi
}

# Build the LDAP URL for a given IP. IPv6 addresses must be bracketed —
# 'ldap://2001:db8::1' is ambiguous to URL parsers; 'ldap://[2001:db8::1]' is not.
# Usage:
#     url=$(ldap_url "$ip")           # ldap://10.0.0.1
#     url=$(ldap_url "$ip" 636 ldaps) # ldaps://[2001:db8::1]:636
ldap_url() {
    local ip="$1"
    local port="${2:-}"
    local scheme="${3:-ldap}"
    local host
    if [[ "$ip" == *:* ]]; then host="[$ip]"; else host="$ip"; fi
    if [ -n "$port" ]; then echo "${scheme}://${host}:${port}"
    else                    echo "${scheme}://${host}"
    fi
}

# Make xargs use the requested parallelism
xargs_p() { xargs -n1 -P"${ENUM_PARALLEL:-4}" "$@"; }

# ----------------------------------------------------------
# E.5 + E.6 — proxy + User-Agent helpers for curl callsites
# ----------------------------------------------------------
# curl honors HTTPS_PROXY / HTTP_PROXY / ALL_PROXY natively, so no extra
# argument is required there. We also honor ENUM_PROXY for parity with
# standalones/graphql/gql.py's GQL_PROXY, and ENUM_USER_AGENT for the UA override.
#
# Usage from a dispatcher:
#     CURL_ARGS=()
#     curl_common_args CURL_ARGS
#     curl -ks "${CURL_ARGS[@]}" "$url"
curl_ua() {
    # Operator override wins; otherwise fall back to a Chrome-stable string
    # matching what standalones/graphql/gql.py uses by default (consistent fingerprint).
    if [ -n "${ENUM_USER_AGENT:-}" ]; then
        printf '%s' "$ENUM_USER_AGENT"
    else
        printf '%s' "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    fi
}

curl_proxy_arg() {
    # Returns "-x <url>" iff ENUM_PROXY is set (env-fallback to HTTPS_PROXY).
    # curl's native env honor means we usually don't need to pass anything,
    # but explicit -x is useful when the operator wants the dispatcher to
    # ignore conflicting *_PROXY env (e.g. inside a wrapper that sets them).
    if [ -n "${ENUM_PROXY:-}" ]; then
        printf -- "-x %s" "$ENUM_PROXY"
    fi
}

# Populate a bash array with common curl args. This preserves spaces and
# shell metacharacters in user-agent/proxy values without eval or word-splitting.
curl_common_args() {
    # shellcheck disable=SC2178  # _arr is a nameref to the caller's array.
    local -n _arr="$1"
    _arr=(-A "$(curl_ua)")
    if [ -n "${ENUM_PROXY:-}" ]; then
        _arr+=(-x "$ENUM_PROXY")
    fi
}

# ----------------------------------------------------------
# G.7 — throttle helpers for "gentle mode" in sensitive environments.
# auto-enum.sh's --throttle exports ENUM_THROTTLE=1 (and lowers NUCLEI_RATE,
# disables FFUF/NIKTO). Dispatchers that hammer the target (banner sweeps,
# multi-port nmap fans) can opt in via these helpers without rewriting flow.
# ----------------------------------------------------------

# Returns the seconds-per-target inter-host pause for gentle mode. Default 1s;
# override with ENUM_THROTTLE_DELAY=<n>. Returns 0 when throttle is off.
throttle_delay() {
    if [ "${ENUM_THROTTLE:-0}" = 1 ]; then
        printf '%s' "${ENUM_THROTTLE_DELAY:-1}"
    else
        printf '0'
    fi
}

# Sleep the throttle delay. Safe to call unconditionally — no-op when throttle is off.
throttle_sleep() {
    local d; d=$(throttle_delay)
    [ "$d" = 0 ] && return 0
    sleep "$d"
}

# Echo the nmap timing flag appropriate for the current throttle state.
# Prefer "${THROTTLE_NMAP_ARGS[@]}" in dispatchers so the empty case adds no arg.
throttle_nmap_args() {
    if [ "${ENUM_THROTTLE:-0}" = 1 ]; then
        printf '%s' "-T2"
    fi
}

# Bounding args so NSE/UDP scans can't hang forever on a tarpit/filtered host.
# Override via env. Echoed (word-split intentionally at call site, like throttle_nmap_args).
nmap_bound_args() {
    printf '%s ' --host-timeout "${ENUM_NMAP_HOST_TIMEOUT:-5m}" \
                 --script-timeout "${ENUM_NMAP_SCRIPT_TIMEOUT:-60s}" \
                 --max-retries "${ENUM_NMAP_MAX_RETRIES:-2}"
}

# shellcheck disable=SC2034  # sourced dispatchers consume this shared array.
THROTTLE_NMAP_ARGS=()
if [ "${ENUM_THROTTLE:-0}" = 1 ]; then
    # shellcheck disable=SC2034  # sourced dispatchers consume this shared array.
    THROTTLE_NMAP_ARGS=(-T2)
fi
