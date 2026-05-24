#!/usr/bin/env bash
# enum-storage.sh — storage fabric and object-store discovery.
#
# Read-side only. Covers iSCSI, Ceph/RADOSGW/Dashboard, Gluster, and MinIO.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "storage: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

url_host() {
    local ip="$1"
    if [[ "$ip" == *:* ]]; then printf '[%s]' "$ip"; else printf '%s' "$ip"; fi
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    host=$(url_host "$ip")
    mkdir -p "$OUT/$ip"

    case "$port" in
        3260)
            if have nmap; then
                nmap -Pn -sT -p 3260 --script iscsi-info \
                    --max-retries 1 --host-timeout 20s \
                    "$ip" -oN "$OUT/$ip/iscsi_${port}.txt" 2>/dev/null || true
                if grep -qE 'iscsi-info:|Target Name:' "$OUT/$ip/iscsi_${port}.txt" 2>/dev/null; then
                    hit "Storage iSCSI target exposed: $ip:$port"
                fi
            else
                miss "nmap not installed — skipping iSCSI NSE probe"
            fi
            ;;
        24007)
            if have nc; then
                timeout 5 nc -nv -w 4 "$ip" "$port" > "$OUT/$ip/gluster_${port}.txt" 2>&1 || true
                if grep -qiE '(gluster|connected|open)' "$OUT/$ip/gluster_${port}.txt" 2>/dev/null; then
                    hit "Storage Gluster management reachable: $ip:$port"
                fi
            else
                miss "nc not installed — skipping Gluster reachability probe"
            fi
            ;;
        3300|6789)
            if have nc; then
                timeout 5 nc -nv -w 4 "$ip" "$port" > "$OUT/$ip/ceph_mon_${port}.txt" 2>&1 || true
                if grep -qiE '(connected|open)' "$OUT/$ip/ceph_mon_${port}.txt" 2>/dev/null; then
                    hit "Storage Ceph monitor reachable: $ip:$port"
                fi
            else
                miss "nc not installed — skipping Ceph monitor reachability probe"
            fi
            ;;
        7480|9000|9001)
            have curl || { miss "curl not installed — skipping HTTP storage probe"; continue; }
            for scheme in http https; do
                base="${scheme}://${host}:${port}"
                safe="${scheme}_${port}"

                minio="$OUT/$ip/minio_${safe}.txt"
                curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
                    -D "$minio.headers" "$base/minio/health/live" > "$minio.body" 2>&1 || true
                status=$(grep -m1 -oE '^HTTP/[0-9.]+ [0-9]+' "$minio.headers" 2>/dev/null | awk '{print $2}')
                if [ "$status" = "200" ] || grep -qiE '(MinIO|x-minio)' "$minio.headers" "$minio.body" 2>/dev/null; then
                    hit "Storage MinIO detected: $base"
                fi

                ceph="$OUT/$ip/ceph_rgw_${safe}.txt"
                curl -ks "${CURL_ARGS[@]}" --connect-timeout 4 --max-time 8 \
                    -D "$ceph.headers" "$base/" > "$ceph.body" 2>&1 || true
                if grep -qiE '(x-amz-request-id|x-rgw-object-type|ceph|radosgw)' "$ceph.headers" "$ceph.body" 2>/dev/null; then
                    hit "Storage Ceph/RADOSGW object gateway detected: $base"
                fi
            done
            ;;
        *)
            log "storage: unsupported port $ip:$port"
            ;;
    esac

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Storage follow-ups:
  * iSCSI: target names often encode cluster, application, or backup roles.
    Do not attach or mount targets from this dispatcher.
  * MinIO / S3-compatible gateways: check anonymous bucket listing only under
    scope; object reads can be sensitive and high-volume.
  * Ceph / Gluster: management reachability from user VLANs is usually a
    segmentation finding even without authentication bypass.
EOF

log "storage dispatcher done."
