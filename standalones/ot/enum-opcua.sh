#!/usr/bin/env bash
# standalones/ot/enum-opcua.sh — OPC-UA 4840 read-side identification (GetEndpoints).
#
# Probe: nmap opcua-info NSE — GetEndpoints (no session). Emits server URI,
# security policies, server certificate metadata, MessageSecurityMode list.
# Flag `None` security policy as MEDIUM (per ADR-005 D6).
# NO Write, NO Call, NO AddNodes/AddReferences/DeleteNodes.
#
# Anchor: ADR-005 §D2 §D5 §D6
# Plan:   ROADMAP-003 §T4.5

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=standalones/ot/_lib.sh
. "$SCRIPT_DIR/_lib.sh"
ot_require_confirmed
parse_common_args "$@" || exit 1
log "opcua: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nmap; then
    miss "nmap not installed — opcua dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out_file="$OUT/$ip/opcua_${port}.txt"

    nmap -Pn -sT -p "$port" \
        --script opcua-info \
        --max-retries 1 --host-timeout 30s \
        "$ip" -oN "$out_file" 2>/dev/null || true

    # Two-evidence:
    #   (a) port open + opcua-info NSE produced output
    #   (b) at least one endpoint URL / security policy / application URI present
    is_opcua=0
    if grep -qE '^[0-9]+/tcp[[:space:]]+open' "$out_file" 2>/dev/null \
       && grep -q '| opcua-info:' "$out_file" 2>/dev/null; then
        is_opcua=1
    fi
    has_endpoint=0
    if grep -qE '^\|[[:space:]]+(EndpointUrl|SecurityPolicyUri|ApplicationUri|ProductUri|SecurityMode|UserIdentityToken)' "$out_file" 2>/dev/null; then
        has_endpoint=1
    fi

    if [ "$is_opcua" = 1 ] && [ "$has_endpoint" = 1 ]; then
        endpoint=$(grep -oE '^\| +EndpointUrl:.*'      "$out_file" | head -1 | sed 's/^| *EndpointUrl: *//' | tr -d '\r' || true)
        product=$(grep -oE '^\| +ProductUri:.*'         "$out_file" | head -1 | sed 's/^| *ProductUri: *//' | tr -d '\r' || true)
        hit "OT-ID OPC-UA $ip:$port — endpoint=${endpoint:-?} product=${product:-?}"

        # Flag `None` security policy as MEDIUM (ADR-005 D6) — but always
        # cite the full policy list in the finding so report.py severity
        # rule can correlate evidence vs context.
        if grep -qE 'SecurityPolicyUri:.*#None' "$out_file" 2>/dev/null \
           || grep -qE 'SecurityPolicy.*\bNone\b' "$out_file" 2>/dev/null; then
            policies=$(grep -oE 'SecurityPolicyUri:.*' "$out_file" | sed 's/SecurityPolicyUri: *//' | sort -u | head -5 | tr '\n' ';' | tr -d '\r')
            hit "OPC-UA endpoint advertises 'None' security policy: $ip:$port — policies=${policies}"
        fi
    fi

    ot_throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
OPC-UA OT follow-ups (READ-SIDE ONLY):

  * GetEndpoints is unauthenticated by design (it has to be — clients use it
    to discover security policies before session establishment).

  * `None` security policy advertised does NOT mean the device accepts
    unauthenticated sessions — many servers advertise None on the discovery
    endpoint only, while production endpoints require Basic256Sha256 or
    Aes256Sha256RsaPss. Check Anonymous user-token policy separately before
    concluding.

  * NEVER call Write, Call (RPC), AddNodes, AddReferences, DeleteNodes,
    or HistoryUpdate. ADR-005 D2.

  * For deeper safe ENUM: open62541 / FreeOpcUa Python clients in read-only
    mode with explicit endpoint selection. Out of scope for this dispatcher.
EOF

log "opcua dispatcher done."
