#!/usr/bin/env bash
# enum-monitoring.sh — monitoring / lab-data service enumeration.
#
# Ports:
#   10050  Zabbix agent          (TCP — agent.ping / system.uname queries)
#   10051  Zabbix server         (TCP — trapper protocol)
#   5666   Nagios NRPE           (TCP — _NRPE_CHECK probe)
#   8089   Splunk management API (HTTPS — services/info endpoint)
#
# Probes are READ-SIDE ONLY:
#   - Zabbix agent: agent.ping + system.uname — read-side metric queries
#   - NRPE: _NRPE_CHECK builtin — version probe; no remote command exec
#   - Splunk: /services/info — version/cluster fingerprint
#
# NO command execution. NO config write. NO Splunk REST write endpoints.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "monitoring: $(wc -l < "$TARGETS") targets -> $OUT"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    case "$port" in
        10050)
            # ---------- Zabbix agent ----------
            have nc || { miss "nc not installed — skipping zabbix-agent probe"; continue; }
            agent_file="$OUT/$ip/zabbix_agent_${port}.txt"

            # Zabbix agent protocol: 13-byte header "ZBXD\x01" + 8-byte little-endian
            # length + 8-byte reserved + payload. Easier: send the raw text key
            # followed by \n — old agents accept it; new agents prefer the framed
            # form but still respond to old form on read keys.
            # Use python3 for portable framing:
            if have python3; then
                python3 - "$ip" "$port" >> "$agent_file" 2>&1 <<'PY' || true
import socket, sys, struct
ip, port = sys.argv[1], int(sys.argv[2])
def send_key(key):
    payload = key.encode()
    hdr = b"ZBXD\x01" + struct.pack("<QQ", len(payload), 0)
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((ip, port))
        s.sendall(hdr + payload)
        resp = s.recv(4096)
        print(f"KEY={key} RAW={resp!r}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"KEY={key} ERR={type(e).__name__}")
    finally:
        s.close()
for k in ["agent.ping", "agent.version", "system.uname", "agent.hostname"]:
    send_key(k)
PY
            fi

            # Two-evidence:
            #   (a) at least one ZBXD response framing byte sequence found
            #   (b) at least one non-error value extracted
            is_zabbix=0
            if grep -q "ZBXD" "$agent_file" 2>/dev/null \
               && grep -qE "KEY=(agent\.version|agent\.hostname|system\.uname) RAW=" "$agent_file" 2>/dev/null \
               && ! grep -q "ZBX_NOTSUPPORTED" "$agent_file" 2>/dev/null; then
                is_zabbix=1
            fi

            if [ "$is_zabbix" = 1 ]; then
                version=$(grep -oE 'KEY=agent.version[^;]*RAW=[^"]*"[0-9.]+' "$agent_file" \
                    | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
                uname=$(grep -oE 'KEY=system.uname[^;]*RAW=.*' "$agent_file" \
                    | head -1 | grep -oE '[A-Za-z]+ [a-zA-Z0-9_.-]+' | head -c 80 || true)
                hit "Zabbix agent UNAUTH metric query: $ip:$port — version=${version:-?} uname=${uname:-?}"
            fi
            ;;

        10051)
            # ---------- Zabbix server (trapper) ----------
            # Trapper protocol accepts active-check requests and historical
            # data submissions. We only confirm reachability + ZBXD framing.
            have nc || { miss "nc not installed — skipping zabbix-server probe"; continue; }
            trapper_file="$OUT/$ip/zabbix_server_${port}.txt"
            printf '' | timeout 5 nc -nv -w 4 "$ip" "$port" > "$trapper_file" 2>&1 || true

            # nmap zabbix-info NSE if available
            if have nmap; then
                zfile="$OUT/$ip/zabbix_server_${port}_nse.txt"
                nmap -Pn -sT -p "$port" --script zabbix-info \
                    --max-retries 1 --host-timeout 20s \
                    "$ip" -oN "$zfile" 2>/dev/null || true
                if grep -q "| zabbix-info:" "$zfile" 2>/dev/null \
                   && grep -qE '^\|[[:space:]]+(version|host_uuid|encryption)' "$zfile" 2>/dev/null; then
                    version=$(grep -oE '^\| +version:.*' "$zfile" | head -1 | sed 's/^| *version: *//' || true)
                    hit "Zabbix server reachable: $ip:$port — version=${version:-?}"
                fi
            fi
            ;;

        5666)
            # ---------- Nagios NRPE ----------
            # NRPE v2/v3/v4 — _NRPE_CHECK is the canonical version probe.
            # Plaintext NRPE (no SSL): rare on modern; modern uses --ssl.
            have python3 || { miss "python3 not installed — skipping NRPE probe"; continue; }
            nrpe_file="$OUT/$ip/nrpe_${port}.txt"

            python3 - "$ip" "$port" > "$nrpe_file" 2>&1 <<'PY' || true
import socket, struct, sys
ip, port = sys.argv[1], int(sys.argv[2])
# NRPE v3 packet: version(2) | type(2) | crc32(4) | result(2) | alignment(2) | buffer_len(4) | buffer | padding
# v2: version(2)=2 | type(2)=1 (query) | crc32(4)=0 | result(2)=2324 | buffer(1024) | padding(2)
# We send v2 query for "_NRPE_CHECK" — no auth, returns version banner.
buf = b"_NRPE_CHECK" + b"\x00" * (1024 - 11)
pkt = struct.pack(">HHIH", 2, 1, 0, 2324) + buf + b"\x53\x52"
# compute CRC32 over pkt with crc field zeroed (already is) — many servers
# accept CRC=0 in "easy mode" if compiled with --enable-easy-args
import zlib
crc = zlib.crc32(pkt) & 0xffffffff
pkt = struct.pack(">HHIH", 2, 1, crc, 2324) + buf + b"\x53\x52"
s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(4)
try:
    s.connect((ip, port))
    s.sendall(pkt)
    resp = s.recv(4096)
    print(f"NRPE rc=0 len={len(resp)} hex={resp[:64].hex()}")
    # The response buffer starts at byte 10 in the v2 frame.
    if len(resp) >= 12:
        # Find printable ASCII run in response payload
        payload = resp[10:]
        printable = bytes(b for b in payload if 32 <= b < 127)
        print(f"NRPE PRINTABLE={printable[:120]!r}")
except (socket.timeout, ConnectionRefusedError, OSError) as e:
    print(f"NRPE rc=1 err={type(e).__name__}")
finally:
    s.close()
PY

            # Two-evidence:
            #   (a) NRPE probe returned non-empty response (rc=0)
            #   (b) printable response includes version-style string OR
            #       canonical NRPE error ("CHECK_NRPE", "Command not allowed",
            #       "Could not read request")
            is_nrpe=0
            if grep -q "NRPE rc=0" "$nrpe_file" 2>/dev/null \
               && grep -qE "(CHECK_NRPE|NRPE v[0-9]|Command not allowed|Could not read|nrpe v[0-9])" "$nrpe_file" 2>/dev/null; then
                is_nrpe=1
            fi

            if [ "$is_nrpe" = 1 ]; then
                printable=$(grep -oE 'PRINTABLE=.*' "$nrpe_file" | head -1 | cut -c1-100)
                hit "Nagios NRPE reachable: $ip:$port — evidence=${printable:-?}"
            fi
            ;;

        8089)
            # ---------- Splunk management API ----------
            # /services/info returns version + license + cluster ID. Requires
            # auth on hardened deployments, returns 401 — but legacy / lab
            # Splunk installs serve it unauth.
            have curl || { miss "curl not installed — skipping splunk probe"; continue; }
            splunk_file="$OUT/$ip/splunk_${port}_info.xml"
            curl -ks -A "$(curl_ua)" $(curl_proxy_arg) --max-time 8 \
                "https://${ip}:${port}/services/info" \
                > "$splunk_file" 2>&1 || true

            # Two-evidence:
            #   (a) response includes a Splunk-style Atom feed XML AND
            #   (b) includes one of: <s:key name="version">, <s:key name="build">,
            #       <s:key name="licenseSignature">, <s:key name="serverName">
            is_splunk=0
            if grep -q '<feed xmlns="http://www.w3.org/2005/Atom"' "$splunk_file" 2>/dev/null \
               && grep -qE '<s:key name="(version|build|licenseSignature|serverName)"' "$splunk_file" 2>/dev/null; then
                is_splunk=1
            fi

            if [ "$is_splunk" = 1 ]; then
                version=$(grep -oE '<s:key name="version">[^<]+' "$splunk_file" | head -1 | sed 's/.*>//' || true)
                build=$(grep -oE '<s:key name="build">[^<]+'   "$splunk_file" | head -1 | sed 's/.*>//' || true)
                hit "Splunk mgmt API UNAUTH: $ip:$port — version=${version:-?} build=${build:-?}"
            elif grep -qE 'HTTP/[12]\.[01] 401' "$splunk_file" 2>/dev/null; then
                # 401 still reveals the product — useful intel without UNAUTH severity
                log "Splunk mgmt API auth-gated (401): $ip:$port"
            fi
            ;;

        *)
            log "monitoring: unsupported port $ip:$port (expected 10050/10051/5666/8089)"
            ;;
    esac

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Monitoring / lab-data follow-ups:

  Zabbix agent (10050):
    * Default config exposes EVERY system.* / vfs.* metric. Try
      `vfs.file.contents[/etc/passwd]` — if accepted, the agent is in
      "active checks" mode without a key list and exposes file reads.
    * `system.run[CMD]` is disabled by default but enabled by some
      operator templates. NEVER attempt without explicit authorization.

  Zabbix server (10051):
    * If you can reach 10051 from an attacker box, you can submit
      historical data for any host the trapper recognizes — useful for
      blue-team detection bypass research, NOT for engagement work.

  Nagios NRPE (5666):
    * CVE-2017-7714 era: arg substitution via $ARG1$ in nrpe.cfg
      check_command definitions. Plaintext NRPE is the prerequisite.
    * If NRPE responds to _NRPE_CHECK but not to any other command,
      it has command_prefix enabled — modern hardening.
    * NEVER attempt arbitrary check name execution without explicit
      authorization — that path is RCE-equivalent on misconfigured
      hosts.

  Splunk mgmt API (8089):
    * /services/info reveals version — cross-reference Splunk CVE feed
      (multiple pre-auth and post-auth RCEs in 2023–2024).
    * /services/auth/login is the auth endpoint — DO NOT spray. Lockout
      can lock out legitimate admins.

  Defensive note: monitoring services are routinely placed on an
  un-segmented management VLAN. Reaching them from a normal user VLAN
  indicates segmentation failure — surface to customer.
EOF

log "monitoring dispatcher done."
