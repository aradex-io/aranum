#!/usr/bin/env bash
# imds-check.sh — cloud metadata service (IMDS) reachability audit.
# READ-ONLY: checks whether the link-local metadata endpoint is reachable from
# this (unprivileged) context and, for AWS, whether IMDSv1 (no token) still
# answers. Reports reachability ONLY — it does NOT fetch, print, or store any
# credential material (OPSEC §9). No dependencies beyond curl OR bash /dev/tcp.
set -u

C_RST=$'\033[0m'; C_HIT=$'\033[1;33m'; C_HDR=$'\033[1;36m'
[ -t 1 ] || { C_RST=""; C_HIT=""; C_HDR=""; }
printf "%s== cloud metadata (IMDS) reachability ==%s\n" "$C_HDR" "$C_RST"

AWS_IP="169.254.169.254"; GCP_HOST="metadata.google.internal"

# TCP reachability without curl: bash /dev/tcp (guarded — dash/busybox lack it).
tcp_open() {
    local host="$1" port="$2"
    if [ -n "${BASH_VERSION:-}" ]; then
        (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null && { exec 3>&- 2>/dev/null; return 0; }
    fi
    return 1
}

have_curl=0; command -v curl >/dev/null 2>&1 && have_curl=1

# --- 169.254.169.254 reachability (AWS/Azure/OpenStack/DO all use this IP) ---
reachable=0
if [ "$have_curl" = 1 ]; then
    code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://$AWS_IP/" 2>/dev/null)
    [ -n "$code" ] && [ "$code" != "000" ] && reachable=1
else
    tcp_open "$AWS_IP" 80 && reachable=1
fi
if [ "$reachable" = 1 ]; then
    printf "%s[!] 169.254.169.254 reachable — cloud metadata endpoint present%s\n" "$C_HIT" "$C_RST"
    # AWS IMDSv1 = credential exposure without a token (SSRF-equivalent from here).
    if [ "$have_curl" = 1 ]; then
        v1=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://$AWS_IP/latest/meta-data/" 2>/dev/null)
        v2=$(curl -s -o /dev/null -m 2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
             -w '%{http_code}' "http://$AWS_IP/latest/api/token" 2>/dev/null)
        if [ "$v1" = "200" ]; then
            printf "%s[!] AWS IMDSv1 ENABLED — /latest/meta-data/ answers WITHOUT a token (role-cred exposure)%s\n" "$C_HIT" "$C_RST"
            printf "    (not fetching credentials — flag only; enforce IMDSv2 / hop-limit 1)\n"
        elif [ "$v2" = "200" ]; then
            printf "  AWS IMDSv2 token endpoint answers — v1 appears disabled (good).\n"
        fi
    fi
else
    printf "  169.254.169.254 not reachable — likely not a cloud host (or IMDS firewalled).\n"
fi

# --- GCP metadata server ---
if [ "$have_curl" = 1 ]; then
    g=$(curl -s -o /dev/null -m 2 -H 'Metadata-Flavor: Google' -w '%{http_code}' \
        "http://$GCP_HOST/computeMetadata/v1/" 2>/dev/null)
    if [ "$g" = "200" ]; then
        printf "%s[!] GCP metadata server reachable (Metadata-Flavor: Google honored) — SA token exposure surface%s\n" "$C_HIT" "$C_RST"
        printf "    (not fetching the token — flag only)\n"
    fi
fi

# --- Azure IMDS (same IP, requires Metadata:true header + api-version) ---
if [ "$reachable" = 1 ] && [ "$have_curl" = 1 ]; then
    a=$(curl -s -o /dev/null -m 2 -H 'Metadata:true' -w '%{http_code}' \
        "http://$AWS_IP/metadata/instance?api-version=2021-02-01" 2>/dev/null)
    [ "$a" = "200" ] && printf "%s[!] Azure IMDS reachable — managed-identity token surface%s\n" "$C_HIT" "$C_RST"
fi
