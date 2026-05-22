#!/usr/bin/env bash
# enum-radius.sh — RADIUS UDP 1812/1813 reachability + BlastRADIUS precondition.
#
# AGGRESSIVE PROBE — requires explicit opt-in:
#   ENUM_RUN_RADIUS=1   enable this dispatcher (or use auto-enum.sh --radius)
#
# WARNING: Some RADIUS configurations count failed Access-Request attempts
# toward NAS-side account lockout. The User-Name "aratool-probe" should NOT
# match any real account; verify engagement-specific lockout policy first.
#
# Required dep: python3 (stdlib only — no scapy)
#
# §9 invariants: enumeration-only; no writes to target.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

# ---- env-gate (exit 0 = documented default, not a failure) -------------------
if [ "${ENUM_RUN_RADIUS:-0}" != "1" ]; then
    err "enum-radius.sh refuses to run — set ENUM_RUN_RADIUS=1 (or use auto-enum.sh --radius) to enable aggressive UDP probes"
    exit 0
fi

parse_common_args "$@" || exit 1

log "radius: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have python3; then
    err "python3 not found"
    exit 1
fi

# ---- inline Python RADIUS probe (stdlib only) --------------------------------
# Written to a temp file so the bash script stays readable.
RADIUS_PROBE=$(mktemp /tmp/aratool-radius-probe.XXXXXX.py)
trap 'rm -f "$RADIUS_PROBE"' EXIT

cat > "$RADIUS_PROBE" << 'PYEOF'
#!/usr/bin/env python3
"""Minimal RADIUS Access-Request probe using stdlib socket + struct only.

Usage:
    python3 <script> <ip> <port> <output_bin> [--blast]

Exit codes:
    0  = response received (code written to stdout as decimal int)
    1  = timeout / no response
    2  = error

--blast: send a second packet WITH a deliberately-wrong Message-Authenticator
         attribute (type 80, 16 zero bytes). If the server responds instead of
         silently dropping, it does not enforce Message-Authenticator on
         Access-Request — BlastRADIUS (CVE-2024-3596) precondition detected.
"""
from __future__ import annotations
import os
import socket
import struct
import sys


def _md5(data: bytes) -> bytes:
    import hashlib
    return hashlib.md5(data).digest()


def _encrypt_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    """PAP password encryption per RFC 2865 §5.2.
    With unknown shared-secret, result is garbage — that is intentional for
    the probe: we want to see if the server responds to ANY request."""
    padded = password + b"\x00" * ((-len(password)) % 16)
    result = b""
    prev = authenticator
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xor_key = _md5(secret + prev)
        chunk = bytes(a ^ b for a, b in zip(block, xor_key))
        result += chunk
        prev = chunk
    return result


def build_access_request(identifier: int, authenticator: bytes,
                          include_bad_ma: bool = False) -> bytes:
    """Build a minimal RADIUS Access-Request (Code=1).

    Attributes included:
      1 (User-Name)     "aratool-probe"
      2 (User-Password) encrypted with empty shared-secret (result is garbage)
     61 (NAS-Port-Type) 0 (Virtual)
      5 (NAS-Port)      0
    Optionally:
     80 (Message-Authenticator)  16 zero bytes  — deliberately invalid MA
                                                   for BlastRADIUS precondition
    """
    secret = b""  # unknown shared-secret; garbage-encrypt password
    username = b"aratool-probe"
    password = b"aratool-probe-pw"
    encrypted_pw = _encrypt_password(password, secret, authenticator)

    def attr(t: int, v: bytes) -> bytes:
        return bytes([t, len(v) + 2]) + v

    attrs = b""
    attrs += attr(1, username)
    attrs += attr(2, encrypted_pw)
    attrs += attr(61, struct.pack(">I", 5))   # NAS-Port-Type: Virtual
    attrs += attr(5, struct.pack(">I", 0))    # NAS-Port: 0

    if include_bad_ma:
        # Message-Authenticator = type 80, 16 zero bytes (deliberately wrong)
        attrs += attr(80, b"\x00" * 16)

    length = 20 + len(attrs)
    packet = bytes([1, identifier]) + struct.pack(">H", length) + authenticator + attrs
    return packet


def probe(ip: str, port: int, out_path: str, blast: bool) -> int:
    """Returns the RADIUS response code (2=Accept, 3=Reject, 11=Challenge)
       or raises socket.timeout on no response."""
    identifier = int.from_bytes(os.urandom(1), "big")
    authenticator = os.urandom(16)
    packet = build_access_request(identifier, authenticator, include_bad_ma=blast)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(packet, (ip, port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    with open(out_path, "wb") as f:
        f.write(data)

    if len(data) < 1:
        raise ValueError("empty response")
    return data[0]  # first byte = Code


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} <ip> <port> <output_bin> [--blast]", file=sys.stderr)
        sys.exit(2)

    ip_arg = sys.argv[1]
    port_arg = int(sys.argv[2])
    out_arg = sys.argv[3]
    blast_arg = "--blast" in sys.argv

    try:
        code = probe(ip_arg, port_arg, out_arg, blast_arg)
        print(code)
        sys.exit(0)
    except socket.timeout:
        sys.exit(1)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
PYEOF

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    log "radius: probing $ip:$port"

    bin_out="$OUT/$ip/radius_response_${port}.bin"
    blast_bin="$OUT/$ip/radius_blast_${port}.bin"

    # ---- Probe 1: standard Access-Request ------------------------------------
    code=$(python3 "$RADIUS_PROBE" "$ip" "$port" "$bin_out" 2>/dev/null)
    probe_rc=$?

    case "$probe_rc" in
        0)
            hit "RADIUS server reachable: $ip:$port — code=$code"
            if [ "$code" = "2" ]; then
                hit "CRITICAL: RADIUS Access-Accept to bogus credential: $ip:$port"
            fi

            # ---- Probe 2: BlastRADIUS precondition check -------------------------
            # Send a packet WITH a deliberately-wrong Message-Authenticator.
            # If the server responds (instead of silently dropping), it does NOT
            # enforce Message-Authenticator on Access-Request — precondition met.
            log "radius: BlastRADIUS (CVE-2024-3596) precondition check for $ip:$port"
            blast_code=$(python3 "$RADIUS_PROBE" "$ip" "$port" "$blast_bin" --blast 2>/dev/null)
            blast_rc=$?
            if [ "$blast_rc" = "0" ]; then
                hit "RADIUS BlastRADIUS (CVE-2024-3596) precondition: $ip:$port lacks Message-Authenticator enforcement"
            fi
            ;;
        1)
            miss "RADIUS server did not respond at $ip:$port (likely silent-drop or not RADIUS)"
            ;;
        *)
            miss "RADIUS probe error for $ip:$port (see dispatcher log)"
            ;;
    esac

    throttle_sleep
done < "$TARGETS"

# ---- hints -------------------------------------------------------------------
cat >> "$OUT/_hints.txt" 2>/dev/null <<'EOF'

RADIUS / BlastRADIUS follow-ups:
  * CVE-2024-3596 (BlastRADIUS) — exploitable when (a) M-A not enforced AND
    (b) attacker can MITM a legitimate Access-Request. This dispatcher checks
    only condition (a) — the precondition. Full exploit requires a separate
    nonce-grinding tool and on-path position.
  * Account-lockout risk: some RADIUS configurations count failed Access-Request
    attempts toward lockout. The User-Name "aratool-probe" should NOT match any
    real account; verify the engagement-specific NAS-Identifier policy first.
  * Access-Accept on bogus credential (code=2) is critical — either anonymous
    auth is enabled or the NAS has no shared-secret configured.
  * Raw response bytes saved to radius_response_<port>.bin for manual analysis.
EOF

log "radius dispatcher done."
