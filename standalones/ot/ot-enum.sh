#!/usr/bin/env bash
# standalones/ot/ot-enum.sh — Tier 4 OT/ICS orchestrator.
#
# Routes hand-picked OT targets to the right read-side dispatcher. NOT
# auto-routed from nmap output. Operator must:
#   1. Pass --ics-confirm AND type the confirmation string
#   2. Supply a --targets file of "ip:port/proto" triples
#
# Supported proto values: modbus, s7, enip, bacnet, opcua, dnp3, iec104
#
# Anchor: aranumtoolkit/docs/ADR-005-22MAY2026-ot-ics-safety-scope.md
# Plan:   aranumtoolkit/docs/ROADMAP-003-22MAY2026-tier4-ics-enumeration.md

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=standalones/ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"

usage() {
    cat >&2 <<EOF
usage: $0 --ics-confirm --targets <file> --output <dir> [--max-parallel N]

Targets file format (one per line):
    <ip>:<port>/<proto>
or  [<v6>]:<port>/<proto>

Supported proto: modbus, s7, enip, bacnet, opcua, dnp3, iec104

Examples:
    10.0.0.5:502/modbus
    10.0.0.6:102/s7
    [2001:db8::5]:4840/opcua

Safety:
    --ics-confirm is REQUIRED and triggers a typed-confirmation prompt
    (ICS-CONFIRMED). Anything else aborts.

    Throttle floor is 500ms per host (non-overridable). Concurrency
    ceiling is 4 (default 2). Operator --max-parallel is clamped.

    Write-side function codes are NEVER emitted. There is no override.

See: aranumtoolkit/docs/ADR-005-22MAY2026-ot-ics-safety-scope.md
EOF
    exit 2
}

# ---- arg parse ---------------------------------------------------------------
ICS_CONFIRM=0
TARGETS=""
OUT=""
MAX_PARALLEL="$OT_MAX_PARALLEL_DEFAULT"

while [ $# -gt 0 ]; do
    case "$1" in
        --ics-confirm)   ICS_CONFIRM=1;       shift ;;
        --targets)       TARGETS="$2";        shift 2 ;;
        --output)        OUT="$2";            shift 2 ;;
        --max-parallel)  MAX_PARALLEL="$2";   shift 2 ;;
        -h|--help)       usage ;;
        *) err "unknown arg: $1"; usage ;;
    esac
done

[ "$ICS_CONFIRM" = 1 ] || { err "--ics-confirm is required (ADR-005 D3)"; usage; }
[ -n "$TARGETS" ] || usage
[ -n "$OUT" ] || usage
[ -f "$TARGETS" ] || { err "targets file missing: $TARGETS"; exit 2; }

MAX_PARALLEL="$(ot_clamp_parallel "$MAX_PARALLEL")"
mkdir -p "$OUT"

# ---- safety prompt -----------------------------------------------------------
ot_confirm_prompt
# After this point OT_CONFIRMED=1 is exported.

log "ot-enum: $(wc -l < "$TARGETS") targets -> $OUT (max-parallel=$MAX_PARALLEL)"

# ---- dispatch table ----------------------------------------------------------
declare -A DISPATCHER_FOR_PROTO=(
    [modbus]="enum-modbus.sh"
    [s7]="enum-s7.sh"
    [enip]="enum-enip.sh"
    [bacnet]="enum-bacnet.sh"
    [opcua]="enum-opcua.sh"
    [dnp3]="enum-dnp3.sh"
    [iec104]="enum-iec104.sh"
)

# ---- group targets by proto -------------------------------------------------
declare -A PROTO_TARGET_FILES=()
TMP_DIR="$(mktemp -d /tmp/ot-enum.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

while IFS= read -r line; do
    [ -z "$line" ] && continue
    [[ "$line" =~ ^# ]] && continue
    read -r ip port proto <<< "$(ot_split_target "$line")"
    if [ -z "${DISPATCHER_FOR_PROTO[$proto]:-}" ]; then
        err "unsupported proto '$proto' for target '$line' — skipping"
        continue
    fi
    pfile="$TMP_DIR/${proto}.targets"
    PROTO_TARGET_FILES[$proto]="$pfile"
    # The downstream dispatchers expect plain "ip:port" lines.
    if [[ "$ip" == *:* ]]; then
        echo "[${ip}]:${port}" >> "$pfile"
    else
        echo "${ip}:${port}" >> "$pfile"
    fi
done < "$TARGETS"

# ---- run dispatchers in serial groups, each with internal host parallelism --
# We do NOT parallelize protos against each other — operator picks bigger
# subnets, they get max-parallel per group, not per dispatcher.
overall_rc=0
for proto in "${!PROTO_TARGET_FILES[@]}"; do
    dispatcher="${DISPATCHER_FOR_PROTO[$proto]}"
    pfile="${PROTO_TARGET_FILES[$proto]}"
    log "dispatching $proto ($(wc -l < "$pfile") target(s)) -> $dispatcher"
    if [ ! -x "$SCRIPT_DIR/$dispatcher" ]; then
        err "$dispatcher missing or not executable — skipping $proto"
        overall_rc=1
        continue
    fi
    OT_CONFIRMED=1 OT_MAX_PARALLEL="$MAX_PARALLEL" \
        bash "$SCRIPT_DIR/$dispatcher" \
        --targets "$pfile" --output "$OUT" || {
            rc=$?
            err "$dispatcher exited rc=$rc"
            [ "$overall_rc" -eq 0 ] && overall_rc="$rc"
        }
done

log "ot-enum done. overall_rc=$overall_rc"
exit "$overall_rc"
