#!/usr/bin/env bash
# enum-backup.sh — backup-infrastructure detection (Veeam, CommVault, NetBackup).
#
# Backup servers are exceptionally high-value lateral targets: they hold
# credentials for every system they back up, and their pre-auth attack
# surface has been responsible for major incidents.
#
# DETECT-ONLY at this tier — no exploit. Pre-auth RCE CVEs live in _hints.txt
# for operator follow-up under engagement scope.
#
# Ports:
#   9392    Veeam Backup & Replication REST API (HTTPS)
#   8400    CommVault REST                       (HTTP/S)
#   81      CommVault Web Service (legacy)       (HTTP)
#   1556    Veritas NetBackup CORBA              (TCP)

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "backup: $(wc -l < "$TARGETS") targets -> $OUT"
CURL_ARGS=()
curl_common_args CURL_ARGS

if ! have curl && ! have nc; then
    miss "neither curl nor nc available — backup dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    case "$port" in
        9392)
            # ---------- Veeam B&R REST ----------
            have curl || { miss "curl missing — skipping veeam probe"; continue; }
            veeam_file="$OUT/$ip/veeam_${port}.txt"
            # Veeam exposes /api/v1/serverInfo (v11+) and /api/sessionMngr (v9-v10).
            # 401 + WWW-Authenticate header carrying realm is the fingerprint.
            curl -ks "${CURL_ARGS[@]}" --max-time 8 \
                -D "$veeam_file.headers" \
                "https://${ip}:${port}/api/v1/serverInfo" \
                > "$veeam_file.body" 2>&1 || true

            # Two-evidence:
            #   (a) header set includes 'X-RestSvcSessionId' OR Server: Veeam
            #   (b) body contains JSON keys ('serverName','patchLevel','vbrVersion')
            #       OR 401 with WWW-Authenticate referencing Veeam
            is_veeam=0
            if grep -qiE '^(server: veeam|x-restsvcsessionid|www-authenticate:.*veeam)' "$veeam_file.headers" 2>/dev/null; then
                is_veeam=1
            fi
            if [ "$is_veeam" = 0 ] && grep -qE '"(serverName|patchLevel|vbrVersion|name)":' "$veeam_file.body" 2>/dev/null; then
                is_veeam=1
            fi

            if [ "$is_veeam" = 1 ]; then
                version=$(grep -oE '"vbrVersion":"[^"]+"' "$veeam_file.body" \
                    | head -1 | sed 's/.*:"//;s/"$//' || true)
                if [ -z "$version" ]; then
                    version=$(grep -oE '"patchLevel":"[^"]+"' "$veeam_file.body" \
                        | head -1 | sed 's/.*:"//;s/"$//' || true)
                fi
                hit "Veeam B&R REST detected: $ip:$port — version=${version:-?}"
            fi
            ;;

        8400|81)
            # ---------- CommVault ----------
            have curl || { miss "curl missing — skipping commvault probe"; continue; }
            cv_file="$OUT/$ip/commvault_${port}.txt"
            # Try /SearchSvc/CVWebService.svc/  — CommVault canonical endpoint
            # CommServe answers with a WSDL or HTML index that contains
            # "CVWebService" / "CommVault" strings.
            scheme="http"
            [ "$port" = "8400" ] && scheme="https"
            curl -ks "${CURL_ARGS[@]}" --max-time 8 \
                "${scheme}://${ip}:${port}/SearchSvc/CVWebService.svc/" \
                > "$cv_file" 2>&1 || true

            is_cv=0
            if grep -qiE '(CVWebService|CommVault|CVSearchSvc|Commvault Systems)' "$cv_file" 2>/dev/null; then
                is_cv=1
            fi

            if [ "$is_cv" = 1 ]; then
                hit "CommVault detected: $ip:$port (CVWebService reachable)"
            fi
            ;;

        1556)
            # ---------- Veritas NetBackup ----------
            # bpcd / vnetd listen on 1556 (legacy) and 13724 (current). Send
            # nothing — capture banner. Most NetBackup daemons accept-then-
            # silent without a valid request; nmap-NSE banner script is more
            # informative.
            nb_file="$OUT/$ip/netbackup_${port}.txt"
            if have nmap; then
                nmap -Pn -sT -p "$port" --script banner \
                    --max-retries 1 --host-timeout 15s \
                    "$ip" -oN "$nb_file" 2>/dev/null || true
            fi

            is_nb=0
            if [ -f "$nb_file" ]; then
                # nmap fingerprint match: 'vnetd' / 'pbx_exchange' / 'bpcd'
                if grep -qE '^[0-9]+/tcp[[:space:]]+open[[:space:]]+(vnetd|pbx_exchange|bpcd)' "$nb_file" 2>/dev/null; then
                    is_nb=1
                fi
            fi

            if [ "$is_nb" = 1 ]; then
                svc=$(grep -oE '^[0-9]+/tcp[[:space:]]+open[[:space:]]+[a-z_]+' "$nb_file" | head -1 | awk '{print $3}')
                hit "Veritas NetBackup detected: $ip:$port — service=${svc:-?}"
            fi
            ;;

        *)
            log "backup: unsupported port $ip:$port (expected 9392/8400/81/1556)"
            ;;
    esac

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Backup infrastructure follow-ups (DETECT-ONLY here):

  Veeam B&R (9392):
    * CVE-2024-29849 — auth bypass + RCE chain (April 2024)
    * CVE-2023-27532 — pre-auth credential leak via Veeam.Backup.Service
    * CVE-2024-40711 — pre-auth RCE in Veeam Backup Enterprise Manager
    * Fingerprint vbrVersion against vendor advisory feed — DO NOT exploit
      without explicit engagement scope including the backup tier.
    * Veeam backs up domain controllers — compromise here yields ntds.dit
      equivalent access. Surface to customer as highest-tier finding.

  CommVault (8400 / 81):
    * CVE-2024-29156 — auth bypass on Web Server prior to 11.32.x
    * CVE-2023-7028 — privilege escalation on certain builds
    * `/webconsole/applicationManager/applicationConfig.do` endpoint
      historically leaks config — pre-auth on legacy builds.

  Veritas NetBackup (1556):
    * Pre-auth bpcd / vnetd chains in pre-9.x master servers; mostly
      patched but legacy environments still vulnerable.
    * Operator credentials are stored under
      /usr/openv/var/global/serverlist on master servers.

  Defensive note: backup infrastructure should be on a dedicated
  management VLAN with no inbound from user networks. Reaching any of
  the above from a normal user VLAN is a segmentation finding regardless
  of patch status.

  IMPORTANT: backup-tier exploitation is an engagement-scope question.
  Many engagement statements EXCLUDE backup infrastructure even when
  the rest of the network is in scope, because of recovery-time
  implications. Confirm scope before any follow-up.
EOF

log "backup dispatcher done."
