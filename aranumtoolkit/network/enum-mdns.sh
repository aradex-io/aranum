#!/usr/bin/env bash
# enum-mdns.sh — mDNS / DNS-SD (5353/udp) service discovery.
#
# READ-ONLY: a unicast DNS-SD PTR query for `_services._dns-sd._udp.local`
# enumerates the service catalog the host advertises (internal hostnames,
# printers, AirPlay, SMB, SSH, _http, etc.) — high-value internal recon that
# often leaks the host's real name and adjacent services. Stdlib socket; nmap
# NSE fallback. Not amplification-risky (single unicast query), so not gated.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "mdns: $(wc -l < "$TARGETS") targets -> $OUT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"
    out="$OUT/$ip/mdns_${port}.txt"

    if have python3; then
        python3 - "$ip" "$port" > "$out" 2>/dev/null <<'PY' || true
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
# DNS query: _services._dns-sd._udp.local  PTR
def enc(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
pkt = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + enc("_services._dns-sd._udp.local") + b"\x00\x0c\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(pkt, (ip, port))
    d, _ = s.recvfrom(8192)
    # crude readable extraction of labels in the answer section
    import re
    labels = re.findall(rb"[ -~]{3,}", d)
    services = sorted({l.decode("latin-1") for l in labels if b"_" in l or b"local" in l})
    for sv in services:
        print("SERVICE:", sv)
except Exception:
    pass
finally:
    s.close()
PY
    fi
    if have nmap && [ ! -s "$out" ]; then
        timeout 30 nmap -sU -p "$port" --script dns-service-discovery --script-timeout 15s \
            -oN "$OUT/$ip/mdns_nmap_${port}.txt" "$ip" >/dev/null 2>&1 || true
    fi

    if grep -q 'SERVICE:' "$out" 2>/dev/null; then
        n=$(grep -c 'SERVICE:' "$out")
        hit "mDNS/DNS-SD catalog: $ip:$port — $n advertised service type(s)"
    fi
    throttle_sleep
done < "$TARGETS"

cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

mDNS / DNS-SD follow-ups:
  * Each advertised _service._proto.local can be resolved further (PTR->SRV->A)
    for host:port + the device's real hostname. Common leaks: _ssh, _sftp-ssh,
    _smb, _afpovertcp, _airplay, _ipp/_printer, _http, _workstation.
  * mDNS reachable off-subnet often means a misconfigured reflector/relay.
EOF
log "mdns dispatcher done."
