#!/usr/bin/env bash
# enum-hpc.sh — HPC scheduler / cluster-manager enumeration.
#
# Ports:
#   6817        Slurm slurmctld (controller)
#   6818        Slurm slurmd    (compute node — banner only)
#   9618        HTCondor collector (CCB / shared port)
#   8088        YARN ResourceManager web UI / /ws/v1/cluster/* REST
#
# Probes are READ-SIDE ONLY:
#   - Slurm: HTTP-OK probe (slurmctld speaks RPC, not HTTP — alive on connect)
#   - HTCondor: TCP connect + tiny CCB hello (just confirm protocol)
#   - YARN: curl /ws/v1/cluster/info — unauth on legacy clusters
#
# NO job submission. NO queue mutation. NO scancel/sacctmgr-write paths.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "hpc: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

if ! have curl && ! have nc; then
    miss "neither curl nor nc available — hpc dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    case "$port" in
        6817|6818)
            # ---------- Slurm slurmctld / slurmd ----------
            # slurmctld responds to TCP connect but does not speak HTTP.
            # If we just want a reachability + role hint:
            #   - 6817: master (controller)
            #   - 6818: compute node (slurmd)
            slurm_file="$OUT/$ip/slurm_${port}.txt"
            # nmap NSE check for slurm banner if available
            if have nmap; then
                nmap -Pn -sT -p "$port" --script banner \
                    --max-retries 1 --host-timeout 15s \
                    "$ip" -oN "$slurm_file" 2>/dev/null || true
            fi

            # Two-evidence: port open AND port number matches known Slurm port
            # (the protocol is opaque; without sniffing RPC payloads we can't
            # confirm it's actually slurm).
            if [ -f "$slurm_file" ] && grep -qE "^${port}/tcp[[:space:]]+open" "$slurm_file" 2>/dev/null; then
                role="?"
                [ "$port" = "6817" ] && role="slurmctld (master)"
                [ "$port" = "6818" ] && role="slurmd (compute)"
                hit "Slurm scheduler reachable: $ip:$port — role=${role}"
            fi
            ;;

        9618)
            # ---------- HTCondor ----------
            # condor_collector listens on 9618 (shared port across all daemons).
            # Send a minimal CCB-equivalent hello — actually just connect and
            # let condor's shared port emit its banner. condor sends a few
            # bytes including "DC_RAW" on protocol mismatch.
            condor_file="$OUT/$ip/condor_${port}.txt"
            printf '' | timeout 5 nc -nv -w 4 "$ip" "$port" > "$condor_file" 2>&1 || true

            # Two-evidence: any non-empty response that contains condor protocol
            # markers ("DC_", "CONDOR", "shared port") OR confirmed-open via nmap.
            is_condor=0
            if [ -s "$condor_file" ] && LC_ALL=C grep -qE '(DC_|CONDOR|shared_port|condor_)' "$condor_file" 2>/dev/null; then
                is_condor=1
            fi
            if [ "$is_condor" = 0 ] && have nmap; then
                nmap_out="$OUT/$ip/condor_${port}_nmap.txt"
                nmap -Pn -sT -p "$port" --max-retries 1 --host-timeout 15s \
                    "$ip" -oN "$nmap_out" 2>/dev/null || true
                if grep -qE "^${port}/tcp[[:space:]]+open" "$nmap_out" 2>/dev/null; then
                    # Open but no banner — informational only
                    log "HTCondor port open (no banner): $ip:$port"
                fi
            fi
            if [ "$is_condor" = 1 ]; then
                first=$(LC_ALL=C tr -dc '[:print:]' < "$condor_file" | head -c 80)
                hit "HTCondor collector reachable: $ip:$port — banner=\"${first}\""
            fi
            ;;

        8088)
            # ---------- YARN ResourceManager ----------
            # /ws/v1/cluster/info is unauth on legacy/unsecured clusters.
            # On secured Hadoop (Kerberos / SPNEGO), this returns 401.
            yarn_file="$OUT/$ip/yarn_${port}_info.json"
            curl -ks "${CURL_ARGS[@]}" --max-time 8 \
                "http://${ip}:${port}/ws/v1/cluster/info" \
                > "$yarn_file" 2>&1 || true

            # Two-evidence:
            #   (a) response contains "clusterInfo" JSON key
            #   (b) AND at least one of: hadoopVersion, resourceManagerVersion,
            #       state, startedOn (YARN-specific keys)
            if grep -q '"clusterInfo"' "$yarn_file" 2>/dev/null \
               && grep -qE '"(hadoopVersion|resourceManagerVersion|state|startedOn)":' "$yarn_file" 2>/dev/null; then
                version=$(grep -oE '"hadoopVersion":"[^"]+"' "$yarn_file" \
                    | head -1 | sed 's/.*:"//;s/"$//')
                state=$(grep -oE '"state":"[^"]+"' "$yarn_file" \
                    | head -1 | sed 's/.*:"//;s/"$//')
                hit "YARN ResourceManager UNAUTH: $ip:$port — hadoop=${version:-?} state=${state:-?}"

                # /ws/v1/cluster/apps lists every job + submitter — also unauth.
                apps_file="$OUT/$ip/yarn_${port}_apps.json"
                curl -ks "${CURL_ARGS[@]}" --max-time 10 \
                    "http://${ip}:${port}/ws/v1/cluster/apps?limit=20" \
                    > "$apps_file" 2>&1 || true
                if grep -q '"app":' "$apps_file" 2>/dev/null; then
                    app_count=$(grep -oE '"id":"application_' "$apps_file" | wc -l | tr -d '[:space:]')
                    hit "YARN UNAUTH app inventory: $ip:$port — $app_count app(s) disclosed"
                fi
            fi
            ;;

        *)
            log "hpc: unsupported port $ip:$port (expected 6817/6818/9618/8088)"
            ;;
    esac

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
HPC scheduler follow-ups:

  Slurm:
    * Auth typically munge-token based. If you have a foothold on any
      compute node, /var/run/munge/munge.socket.2 is the auth key — DO
      NOT exfiltrate without explicit authorization.
    * `sacctmgr show user format=user,defaultaccount,maxsubmitjobs` is
      read-side; `sacctmgr show qos`, `sacctmgr show account` similarly.

  HTCondor:
    * `condor_status -any` lists every machine in the pool + role.
    * `condor_q -allusers` lists all queued jobs across users.
    * Auth: classic UNIX FS+UID by default — strongly recommend bumping
      to GSI/Kerberos. CLAIMTOBE auth historically vulnerable.

  YARN:
    * If /ws/v1/cluster/apps is unauth, /ws/v1/cluster/scheduler also
      is — reveals queue capacity and priority configuration.
    * Pre-auth RCE chains exist in old Hadoop versions (Cloudera CDH
      pre-2.7, MapR pre-6.0) — fingerprint the hadoopVersion field and
      cross-reference vendor advisories.

  Defensive note: HPC schedulers are network-segmented from generic
  enterprise networks. If you reached one from a normal user VLAN, the
  segmentation control failed — surface to customer in the report.
EOF

log "hpc dispatcher done."
