#!/usr/bin/env bash
# enum-kubernetes.sh — Kubernetes apiserver + kubelet enumeration.
#
# Three high-value surfaces:
#   6443 (TLS apiserver)      — anonymous RBAC + version banner
#   8080 (insecure apiserver) — deprecated; if present, FULL access without TLS
#   10250 (kubelet API)       — /pods, /run/<pod>/<container>/<cmd> (exec)
#   10255 (read-only kubelet) — deprecated; /stats, /metrics
#   10256 (kube-proxy health) — fingerprint only
#
# READ-ONLY. Never exercises kubelet /run, /exec, or apiserver mutating verbs.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "kubernetes: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — kubernetes dispatcher cannot probe"
    exit 0
fi

# Optional bearer token (e.g. captured service-account token)
K8S_TOKEN="${K8S_TOKEN:-}"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"

    AUTH=()
    [ -n "$K8S_TOKEN" ] && AUTH=(-H "Authorization: Bearer $K8S_TOKEN")

    # Pick scheme + endpoints based on port
    case "$port" in
        8080)
            scheme="http"
            endpoints=("version" "api/v1/nodes" "api/v1/pods" "api/v1/namespaces"
                       "api/v1/secrets" "api/v1/services" "api/v1/configmaps") ;;
        6443)
            scheme="https"
            endpoints=("version" "api/v1/nodes" "api/v1/pods" "api/v1/namespaces"
                       "api/v1/secrets" "api/v1/services") ;;
        10250)
            scheme="https"
            endpoints=("pods" "stats/summary" "metrics" "healthz") ;;
        10255)
            scheme="http"
            endpoints=("pods" "stats/summary" "metrics" "healthz") ;;
        10256)
            scheme="http"
            endpoints=("healthz") ;;
        *)
            scheme="https"; endpoints=("version") ;;
    esac

    base="${scheme}://${h}:${port}"
    for ep in "${endpoints[@]}"; do
        safe=$(echo "$ep" | sed 's|[/?&=]|_|g')
        code=$(curl -ksI "${AUTH[@]}" --connect-timeout 5 --max-time 10 \
                    -o /dev/null -w '%{http_code}' "$base/$ep" 2>/dev/null)
        [ "$code" = "000" ] && continue
        curl -ks "${AUTH[@]}" --connect-timeout 5 --max-time 15 "$base/$ep" \
            > "$out_dir/${safe}.json" 2>/dev/null || true

        case "$port:$code" in
            "8080:200")
                err "CRITICAL: insecure apiserver $base/$ep returned 200 (deprecated insecure port — no TLS, no auth required)" ;;
            "6443:200")
                if [ -z "$K8S_TOKEN" ]; then
                    hit "UNAUTH on TLS apiserver $base/$ep — anonymous RBAC grants access"
                fi ;;
            "10250:200")
                hit "kubelet $base/$ep returned 200 — pod listing / exec endpoint exposed" ;;
            "10255:200")
                hit "deprecated read-only kubelet $base/$ep returned 200" ;;
        esac
    done

    # Quick version banner
    if [ -s "$out_dir/version.json" ] && grep -q '"gitVersion"' "$out_dir/version.json" 2>/dev/null; then
        v=$(grep -oE '"gitVersion":"[^"]+' "$out_dir/version.json" | head -1 | cut -d'"' -f4)
        echo "$v" > "$out_dir/_version.txt"
        log "  $base apiserver version: $v"
    fi
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Kubernetes API findings:
  * 8080 reachable -> deprecated insecure apiserver. ANY 200 means full cluster
    control. Immediate escalation.
  * 6443 anonymous returning data -> anonymous role-binding granted more than
    just /version. Check api/v1/pods, api/v1/secrets — if those return 200
    without a Bearer token, you have cluster reconnaissance.
  * kubelet 10250 /pods returning 200 -> can enumerate pods AND on older
    kubelet (1.10ish) the /exec/<ns>/<pod>/<container> verb works without
    apiserver auth (CVE-2018-1002105 family).
  * If you have a Bearer token (captured SA token, kubeconfig, etc.), set
    K8S_TOKEN env and re-run.
EOF

log "kubernetes dispatcher done."
