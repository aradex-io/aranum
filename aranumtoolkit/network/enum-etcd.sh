#!/usr/bin/env bash
# enum-etcd.sh — etcd (k8s control-plane KV store) enumeration.
#
# etcd holds every Kubernetes Secret in plaintext (or AES-CBC keyed with a
# locally-stored encryption key — often not enabled). Unauth read access to
# etcd = full cluster secret exfil + the ability to read API server certs.
#
# READ-ONLY: only GET on /v2/keys (v2 legacy) and /v3 endpoint discovery.
# Never POST/PUT/DELETE.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "etcd: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — etcd dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"

    # 2379 = client port (HTTPS in modern k8s), 2380 = peer port (cluster-internal)
    for scheme in http https; do
        base="${scheme}://${h}:${port}"
        # ---------- version ----------
        code=$(curl -ksI --connect-timeout 5 --max-time 10 \
                    -o /dev/null -w '%{http_code}' "$base/version" 2>/dev/null)
        [ "$code" = "000" ] && continue
        if [ "$code" = "200" ]; then
            curl -ks --connect-timeout 5 --max-time 10 "$base/version" \
                > "$out_dir/version_${scheme}.json" 2>/dev/null || true

            # ---------- v2 keys (legacy etcd v2 API) ----------
            curl -ks --connect-timeout 5 --max-time 15 \
                "$base/v2/keys/?recursive=true" \
                > "$out_dir/v2_keys_${scheme}.json" 2>/dev/null || true
            if [ -s "$out_dir/v2_keys_${scheme}.json" ] \
               && ! grep -qi 'unauthorized\|requires authentication' "$out_dir/v2_keys_${scheme}.json"; then
                err "CRITICAL: $base/v2/keys/?recursive=true returned data — etcd v2 unauth read"
            fi

            # ---------- v3 endpoint discovery (post-3.0 grpc-gateway) ----------
            # /version + /metrics work over HTTP/1.1; full v3 needs gRPC.
            curl -ks --connect-timeout 5 --max-time 10 "$base/metrics" \
                > "$out_dir/metrics_${scheme}.txt" 2>/dev/null || true
            if grep -q 'etcd_' "$out_dir/metrics_${scheme}.txt" 2>/dev/null; then
                err "CRITICAL: $base/metrics exposes etcd internals without auth"
            fi
        fi
    done
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
etcd follow-ups:
  * Unauth /v2/keys/?recursive=true on a k8s control-plane host returns the
    ENTIRE cluster state including secrets, kubelet TLS certs, and the
    apiserver's signing keys. This is full-cluster compromise.
  * v3 API (post-3.0 default) is gRPC; use etcdctl with --insecure-skip-tls-verify:
      etcdctl --endpoints=https://<ip>:2379 --insecure-transport \
        --insecure-skip-tls-verify get / --prefix --keys-only
  * Peer port 2380 is cluster-internal; if reachable externally with
    --peer-cert-allowed-cn unset, an attacker can join the cluster.
EOF

log "etcd dispatcher done."
