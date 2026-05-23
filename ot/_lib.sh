# shellcheck shell=bash
# ot/_lib.sh — shared helpers for OT / ICS read-side dispatchers.
#
# DO NOT source from network/ dispatchers — the safety controls here are
# specific to the OT threat model and are NOT a superset of network/_lib.sh.
#
# Anchor: docs/ADR-005-22MAY2026-ot-ics-safety-scope.md
#
# Hard rules enforced by this lib:
#   1. Every dispatcher checks $OT_CONFIRMED=1 before any probe leaves the
#      test box. The orchestrator (ot/ot-enum.sh) sets this after the
#      typed-confirmation prompt.
#   2. Throttle floor = 500ms per-host probe spacing — non-overridable.
#   3. Concurrency ceiling = 4 hosts in flight, default 2.
#   4. Write-side function codes are NOT exposed by any helper here.
#
# Reusing network/_lib.sh formatters (hit/log/miss/err) by sourcing them
# from a relative path so we don't reimplement.

# Resolve the network/_lib.sh path relative to this file
_OT_LIB_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../network/_lib.sh
. "$_OT_LIB_SCRIPT_DIR/../network/_lib.sh"

# --------------- OT safety primitives -------------------------------------

# Hard floor — non-overridable.
# Exported because ot/ot-enum.sh and the per-proto dispatchers consume them
# after sourcing this file (shellcheck SC2034 doesn't follow `source` so the
# bare assignment would falsely flag them as unused).
export OT_THROTTLE_FLOOR_MS=500
export OT_MAX_PARALLEL_DEFAULT=2
export OT_MAX_PARALLEL_HARD=4

# Each dispatcher must call this immediately after sourcing.
# Refuses to proceed unless $OT_CONFIRMED=1 is in the env.
ot_require_confirmed() {
    if [ "${OT_CONFIRMED:-0}" != "1" ]; then
        err "OT dispatcher refused: \$OT_CONFIRMED not set."
        err "Run via ot/ot-enum.sh --ics-confirm — this is intentional (ADR-005 D3)."
        err "To run a single OT dispatcher directly, set OT_CONFIRMED=1 only after"
        err "you have read ADR-005 and confirmed written engagement authorization"
        err "includes OT scope. Pass --ics-confirm on the orchestrator instead."
        exit 2
    fi
}

# Per-probe spacing: sleep at least OT_THROTTLE_FLOOR_MS ms between calls.
# Operator-supplied $ENUM_THROTTLE (aggressive/normal/conservative) is
# ignored — the floor is non-negotiable.
ot_throttle_sleep() {
    local ms="$OT_THROTTLE_FLOOR_MS"
    # Convert ms to floating seconds for `sleep`.
    sleep "$(awk -v m="$ms" 'BEGIN { printf "%.3f", m/1000 }')"
}

# Prompt the operator for the literal string "ICS-CONFIRMED". Anything
# else exits rc=2. Called by the orchestrator before dispatching.
#
# Stdin must be a TTY — piped/redirected confirmation (e.g.
# `echo ICS-CONFIRMED | ot-enum.sh --ics-confirm ...`) defeats the
# point of "a human deliberately typed this" and is refused. The escape
# hatch for legitimately-scripted operators is documented in ADR-005 D3:
# set OT_CONFIRMED=1 yourself only after written engagement authorization
# explicitly covers OT scope, then invoke a single ot/enum-*.sh dispatcher
# directly (bypassing this orchestrator entirely).
ot_confirm_prompt() {
    if ! [ -t 0 ]; then
        err "OT confirmation prompt requires a TTY on stdin — piped/redirected"
        err "input is refused. See ADR-005 D3 for the scripted-invocation escape"
        err "hatch (set OT_CONFIRMED=1 yourself + invoke a dispatcher directly,"
        err "only after written engagement authorization covers OT scope)."
        exit 2
    fi
    cat >&2 <<'EOF'

================================================================================
                       WARNING — OT/ICS ENUMERATION GATE
================================================================================
OT probes (Modbus/S7/EtherNet-IP/BACnet/OPC-UA/DNP3/IEC-104) can cause
physical events on legacy or fragile devices even when restricted to
read-side function codes. Anchor: docs/ADR-005-22MAY2026-ot-ics-safety-scope.md

You must have written engagement authorization that explicitly covers
OT scope and an agreed maintenance window for this run.

If you are unsure, ABORT NOW (Ctrl-C).

Type the literal string  ICS-CONFIRMED  (case-sensitive, no quotes) to
proceed. Anything else aborts.
================================================================================

EOF
    local confirm=""
    read -r confirm
    if [ "$confirm" != "ICS-CONFIRMED" ]; then
        err "confirmation string did not match — aborting (rc=2)."
        exit 2
    fi
    log "OT confirmation accepted."
    export OT_CONFIRMED=1
}

# Bound the operator's --max-parallel value to OT_MAX_PARALLEL_HARD.
ot_clamp_parallel() {
    local req="$1"
    if [ "$req" -gt "$OT_MAX_PARALLEL_HARD" ]; then
        err "requested --max-parallel=$req exceeds OT ceiling ($OT_MAX_PARALLEL_HARD) — clamping."
        echo "$OT_MAX_PARALLEL_HARD"
    elif [ "$req" -lt 1 ]; then
        echo 1
    else
        echo "$req"
    fi
}

# Parse a targets line in the canonical OT triple form `ip:port/proto`.
# Echoes "<ip> <port> <proto>". Falls back to "ip port unknown" when the
# /proto is missing (so the orchestrator can still route via the operator's
# explicit per-target mapping in the config block).
ot_split_target() {
    local t="$1"
    if [[ "$t" == */* ]]; then
        local front="${t%/*}"
        local proto="${t##*/}"
        local ip port
        read -r ip port <<< "$(split_ipport "$front")"
        echo "$ip" "$port" "$proto"
    else
        local ip port
        read -r ip port <<< "$(split_ipport "$t")"
        echo "$ip" "$port" "unknown"
    fi
}
