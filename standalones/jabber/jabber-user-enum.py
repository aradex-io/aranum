#!/usr/bin/env python3
"""jabber-user-enum.py — XMPP user enumeration via SASL response differential.

Per ADR-001 D2 + D4: stdlib-only, enumeration-only (no spray, no account
creation). The IBR-based enum technique in XEP-0077 §3.1.1 is rejected
because it *creates* accounts when the conflict-error path doesn't fire —
that's a target-state change we won't take. We use the SASL-failure-XML
+ timing differential instead, which is purely read-only.

Methodology:
    1. Open an XMPP stream to <domain> via <ip>:<port>, negotiate STARTTLS
       if advertised (we never auth over plaintext).
    2. For each candidate username, attempt SASL PLAIN with the candidate
       and a deliberately wrong password.
    3. Classify the failure XML:
         <not-authorized/>        -> USER_EXISTS  (server reached cred check)
         <invalid-authzid/>       -> INVALID_FORMAT
         <account-disabled/>      -> EXISTS_DISABLED
         <credentials-expired/>   -> EXISTS_EXPIRED
         <temporary-auth-failure/>-> SERVER_ERROR (rate-limited or backend down)
         (no <failure/>)          -> UNCLASSIFIED — timing fallback
    4. Record per-user response time. A consistent timing differential
       between known-good and bogus users is itself a signal even when the
       failure XML is identical.

Many hardened servers (modern Ejabberd with the right auth_method config)
return <not-authorized/> for every username. In that case this tool will
report USER_EXISTS for every candidate and the timing column is the only
useful signal. That's the intended degradation behavior.

The Openfire CVE-2023-32315 helper lives elsewhere — this tool is purely
about who can authenticate, not about path-traversal admin bypass.
"""

from __future__ import annotations
import argparse
import base64
import re
import socket
import ssl
import sys
import time
from pathlib import Path

# --------------------------------------------------- colors
def _c(s: str, code: str) -> str:
    if not sys.stdout.isatty():
        return s
    return {"R": "\033[1;31m", "G": "\033[1;32m", "Y": "\033[1;33m",
            "C": "\033[1;36m", "M": "\033[1;35m"}.get(code, "") + s + "\033[0m"


# --------------------------------------------------- XMPP framing
STREAM_OPEN = (
    "<?xml version='1.0'?>"
    "<stream:stream xmlns='jabber:client' "
    "xmlns:stream='http://etherx.jabber.org/streams' "
    "to='{domain}' version='1.0'>"
)
STARTTLS_REQ = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
STREAM_CLOSE = "</stream:stream>"


def _send(sock, data: str) -> None:
    sock.sendall(data.encode("utf-8"))


def _recv_until(sock, marker_re: re.Pattern, timeout: float = 3.0) -> bytes:
    """Read until we see the marker regex or the timeout fires."""
    sock.settimeout(timeout)
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if marker_re.search(bytes(buf)):
            break
    return bytes(buf)


_FEATURES_END = re.compile(rb"</stream:features>|<failure ")
_PROCEED_RE   = re.compile(rb"<proceed ")
_FAILURE_RE   = re.compile(rb"<failure[\s\S]*?</failure>")
_SUCCESS_RE   = re.compile(rb"<success ")


def _open_stream(ip: str, port: int, domain: str, want_starttls: bool, timeout: float):
    """Connect, open stream, negotiate STARTTLS if advertised + requested.
    Returns (socket, raw_features_bytes)."""
    s = socket.create_connection((ip, port), timeout=timeout)
    _send(s, STREAM_OPEN.format(domain=domain))
    feats = _recv_until(s, _FEATURES_END, timeout)
    if want_starttls and b"<starttls" in feats:
        _send(s, STARTTLS_REQ)
        proceed = _recv_until(s, _PROCEED_RE, timeout)
        if b"<proceed" not in proceed:
            raise RuntimeError(f"STARTTLS request rejected: {proceed!r}")
        # Wrap in TLS; we deliberately do not verify — labs and engagement
        # targets routinely present self-signed certs. Operator can pin later.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=domain)
        _send(s, STREAM_OPEN.format(domain=domain))
        feats = _recv_until(s, _FEATURES_END, timeout)
    return s, feats


def _sasl_plain_payload(user: str, password: str) -> str:
    """SASL PLAIN payload per RFC 4616: authzid\\0authcid\\0passwd. authzid empty."""
    raw = f"\0{user}\0{password}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _probe_user(ip: str, port: int, domain: str, user: str,
                timeout: float, use_starttls: bool) -> dict:
    """Send one SASL PLAIN attempt with a bogus password; return a classified
    result dict for the caller to print."""
    started = time.monotonic()
    try:
        s, feats = _open_stream(ip, port, domain, use_starttls, timeout)
    except Exception as e:
        return {"user": user, "verdict": "STREAM_FAIL", "detail": str(e),
                "elapsed_ms": int((time.monotonic() - started) * 1000)}

    if b"<mechanism>PLAIN</mechanism>" not in feats:
        try: s.close()
        except: pass
        return {"user": user, "verdict": "NO_PLAIN",
                "detail": "server doesn't offer SASL PLAIN — try SCRAM-based probe (not implemented yet)",
                "elapsed_ms": int((time.monotonic() - started) * 1000)}

    bogus_pw = "wrong-password-for-enumeration-probe-only"
    auth = f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{_sasl_plain_payload(user, bogus_pw)}</auth>"
    _send(s, auth)
    resp = _recv_until(s, _FAILURE_RE, timeout)
    try: s.close()
    except: pass

    elapsed_ms = int((time.monotonic() - started) * 1000)
    text = resp.decode("utf-8", errors="replace")

    if _SUCCESS_RE.search(resp):
        # This shouldn't ever happen (we sent a bogus pw) but if it does:
        return {"user": user, "verdict": "AUTH_OK_BUG?", "detail": "server accepted bogus password — investigate",
                "elapsed_ms": elapsed_ms, "raw": text}

    # Map SASL failure conditions per RFC 6120 §6.5
    failure_map = [
        (re.compile(r"<not-authorized\s*/>"),          "USER_EXISTS"),
        (re.compile(r"<account-disabled\s*/>"),        "EXISTS_DISABLED"),
        (re.compile(r"<credentials-expired\s*/>"),     "EXISTS_EXPIRED"),
        (re.compile(r"<temporary-auth-failure\s*/>"),  "SERVER_ERROR"),
        (re.compile(r"<invalid-authzid\s*/>"),         "INVALID_FORMAT"),
        (re.compile(r"<invalid-mechanism\s*/>"),       "NO_PLAIN"),
        (re.compile(r"<malformed-request\s*/>"),       "MALFORMED"),
        (re.compile(r"<encryption-required\s*/>"),     "ENCRYPTION_REQUIRED"),
        (re.compile(r"<aborted\s*/>"),                 "ABORTED"),
    ]
    for pat, verdict in failure_map:
        if pat.search(text):
            return {"user": user, "verdict": verdict, "detail": "",
                    "elapsed_ms": elapsed_ms, "raw": text[:200]}
    if "<failure" in text:
        return {"user": user, "verdict": "UNCLASSIFIED_FAILURE",
                "detail": "<failure> with unknown child", "elapsed_ms": elapsed_ms,
                "raw": text[:200]}
    return {"user": user, "verdict": "NO_RESPONSE", "detail": "no <failure/> seen before timeout",
            "elapsed_ms": elapsed_ms, "raw": text[:200]}


# --------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="XMPP server IP or hostname")
    ap.add_argument("--port", type=int, default=5222, help="c2s port (default 5222)")
    ap.add_argument("--domain", required=True,
                    help="XMPP domain (the to= attribute on stream open) — derive from cert SAN if unsure")
    ap.add_argument("--user-list", required=True,
                    help="path to newline-separated candidate usernames (one per line, # for comments)")
    ap.add_argument("--no-starttls", action="store_true",
                    help="skip STARTTLS negotiation (plaintext SASL — DANGER on real targets)")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-probe socket timeout (default 4s)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between probes (per ADR-001 D2 we never spray, but use this for rate-shaping)")
    ap.add_argument("--out", help="write per-user JSONL results to this file")
    args = ap.parse_args()

    users = [l.strip() for l in Path(args.user_list).read_text().splitlines()
             if l.strip() and not l.strip().startswith("#")]
    if not users:
        print(_c("[!] user list is empty", "R"), file=sys.stderr); return 2

    print(_c(f"[*] probing {len(users)} users against {args.host}:{args.port} (domain={args.domain})", "C"))
    print(_c(f"    method: SASL PLAIN response differential — read-only, no account creation", "C"))
    if args.no_starttls:
        print(_c("[!] --no-starttls — plaintext SASL. Use only on authorized lab targets.", "Y"))
    print()

    out_fh = open(args.out, "w") if args.out else None
    use_starttls = not args.no_starttls

    counts: dict[str, int] = {}
    timings: dict[str, list[int]] = {}
    for user in users:
        r = _probe_user(args.host, args.port, args.domain, user, args.timeout, use_starttls)
        v = r["verdict"]
        counts[v] = counts.get(v, 0) + 1
        timings.setdefault(v, []).append(r["elapsed_ms"])
        flag = {"USER_EXISTS": _c("+", "G"), "EXISTS_DISABLED": _c("!", "Y"),
                "EXISTS_EXPIRED": _c("!", "Y"), "STREAM_FAIL": _c("X", "R"),
                "NO_PLAIN": _c("?", "Y")}.get(v, " ")
        print(f"  [{flag}] {user:30s}  {v:24s}  {r['elapsed_ms']:5d}ms  {r['detail']}")
        if out_fh:
            import json as _json
            out_fh.write(_json.dumps(r) + "\n")
        if args.delay > 0:
            time.sleep(args.delay)

    if out_fh:
        out_fh.close()
        print(_c(f"[+] per-user JSONL written to {args.out}", "G"))

    print()
    print(_c("--- summary ---", "M"))
    for v, n in sorted(counts.items(), key=lambda x: -x[1]):
        ts = sorted(timings[v])
        med = ts[len(ts) // 2]
        print(f"  {v:24s}  ×{n:5d}  median {med}ms")
    print(_c("[*] interpretation: if every candidate returned USER_EXISTS the server "
             "doesn't differentiate via SASL XML — check the timing column for outliers", "C"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr); sys.exit(130)
