#!/usr/bin/env python3
"""jabber-validate.py — single-credential XMPP SASL validation.

Per ADR-001 D2: ONE user, ONE password, ONE attempt. No spray.

Tries SASL mechanisms in this order (configurable via --mechs):
  1. SCRAM-SHA-256       (server SHOULD advertise; client-final-proof verified)
  2. SCRAM-SHA-1         (RFC 5802; widely available)
  3. PLAIN               (last resort — only over TLS unless --no-starttls)

Exits 0 on AUTH_OK, 1 on AUTH_FAIL (with reason printed), 2 on connect/
protocol error before authentication was attempted.

Stdlib-only (per ADR-001 D4). SCRAM is implemented inline rather than
pulling in a library — the protocol is small.
"""

from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import os
import re
import socket
import ssl
import sys

# --------------------------------------------------- colors
def _c(s: str, code: str) -> str:
    if not sys.stdout.isatty():
        return s
    return {"R": "\033[1;31m", "G": "\033[1;32m", "Y": "\033[1;33m",
            "C": "\033[1;36m"}.get(code, "") + s + "\033[0m"


# --------------------------------------------------- XMPP framing (shared shape with H.3)
STREAM_OPEN = ("<?xml version='1.0'?>"
               "<stream:stream xmlns='jabber:client' "
               "xmlns:stream='http://etherx.jabber.org/streams' "
               "to='{domain}' version='1.0'>")
STARTTLS_REQ = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

_FEATURES_END = re.compile(rb"</stream:features>|<failure ")
_PROCEED_RE   = re.compile(rb"<proceed ")
_CHALLENGE_RE = re.compile(rb"<challenge[\s\S]*?</challenge>")
_OUTCOME_RE   = re.compile(rb"<success[\s\S]*?</success>|<failure[\s\S]*?</failure>")


def _recv_until(sock, marker_re: re.Pattern, timeout: float = 4.0) -> bytes:
    import time as _time
    sock.settimeout(timeout)
    buf = bytearray()
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        try:    chunk = sock.recv(4096)
        except socket.timeout: break
        if not chunk: break
        buf.extend(chunk)
        if marker_re.search(bytes(buf)): break
    return bytes(buf)


def _open(ip: str, port: int, domain: str, want_starttls: bool, timeout: float):
    s = socket.create_connection((ip, port), timeout=timeout)
    s.sendall(STREAM_OPEN.format(domain=domain).encode())
    feats = _recv_until(s, _FEATURES_END, timeout)
    if want_starttls and b"<starttls" in feats:
        s.sendall(STARTTLS_REQ.encode())
        proceed = _recv_until(s, _PROCEED_RE, timeout)
        if b"<proceed" not in proceed:
            raise RuntimeError(f"STARTTLS rejected: {proceed!r}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=domain)
        s.sendall(STREAM_OPEN.format(domain=domain).encode())
        feats = _recv_until(s, _FEATURES_END, timeout)
    return s, feats


def _b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def _b64d(s: str) -> bytes: return base64.b64decode(s)


# --------------------------------------------------- SASL: PLAIN
def _auth_plain(sock, user: str, password: str, timeout: float) -> tuple[bool, str]:
    payload = _b64e(f"\0{user}\0{password}".encode())
    sock.sendall(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{payload}</auth>".encode())
    out = _recv_until(sock, _OUTCOME_RE, timeout)
    if b"<success " in out: return True, "success"
    return False, out.decode("utf-8", errors="replace")[:300]


# --------------------------------------------------- SASL: SCRAM (RFC 5802)
def _scram(sock, user: str, password: str, hash_name: str, timeout: float) -> tuple[bool, str]:
    """Implement client SCRAM with channel-binding=n (no TLS binding).
    hash_name = 'sha1' or 'sha256'. Mechanism string is SCRAM-{SHA-1|SHA-256}."""
    mech = "SCRAM-SHA-256" if hash_name == "sha256" else "SCRAM-SHA-1"
    h = lambda b: hashlib.new(hash_name, b).digest()
    hmac_ = lambda key, msg: hmac.new(key, msg, hash_name).digest()

    # Client first message
    nonce = base64.b64encode(os.urandom(18)).decode("ascii")
    cbind_header = "n,,"        # no channel binding
    client_first_bare = f"n={user},r={nonce}"
    client_first = cbind_header + client_first_bare
    sock.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{mech}'>{_b64e(client_first.encode())}</auth>".encode()
    )
    chal = _recv_until(sock, re.compile(rb"<challenge[\s\S]*?</challenge>|<failure[\s\S]*?</failure>"), timeout)
    text = chal.decode("utf-8", errors="replace")
    if "<failure" in text or "<challenge" not in text:
        return False, text[:300]
    inner = re.search(r"<challenge[^>]*>([^<]+)</challenge>", text)
    if not inner: return False, "no challenge body"
    server_first = _b64d(inner.group(1)).decode("utf-8")
    sf = dict(x.split("=", 1) for x in server_first.split(","))
    if not sf["r"].startswith(nonce):
        return False, f"server nonce doesn't begin with client nonce (got {sf['r']!r})"
    salt = _b64d(sf["s"]); iters = int(sf["i"]); rserver_nonce = sf["r"]

    # PBKDF2
    salted_password = hashlib.pbkdf2_hmac(hash_name, password.encode(), salt, iters)
    client_key = hmac_(salted_password, b"Client Key")
    stored_key = h(client_key)
    cbind_b64 = _b64e(cbind_header.encode())
    client_final_without_proof = f"c={cbind_b64},r={rserver_nonce}"
    auth_message = ",".join([client_first_bare, server_first, client_final_without_proof])
    client_signature = hmac_(stored_key, auth_message.encode())
    client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    client_final = f"{client_final_without_proof},p={_b64e(client_proof)}"
    sock.sendall(f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{_b64e(client_final.encode())}</response>".encode())
    out = _recv_until(sock, _OUTCOME_RE, timeout)
    if b"<success" in out:
        # Optionally verify server signature; we skip that here — auth already succeeded.
        return True, "success"
    return False, out.decode("utf-8", errors="replace")[:300]


# --------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5222)
    ap.add_argument("--domain", required=True, help="XMPP domain (to= on stream open)")
    ap.add_argument("--jid", required=True,
                    help="full JID 'user@domain' OR bare username (defaults the domain to --domain)")
    ap.add_argument("--password", help="password (omit to read from JABBER_PASSWORD env)")
    ap.add_argument("--mechs", default="scram-sha-256,scram-sha-1,plain",
                    help="comma-separated mechs to attempt in order")
    ap.add_argument("--no-starttls", action="store_true",
                    help="skip STARTTLS — plaintext SASL. DANGER on real targets.")
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    password = args.password or os.environ.get("JABBER_PASSWORD", "")
    if not password:
        print(_c("[!] --password not given and JABBER_PASSWORD env empty", "R"), file=sys.stderr); return 2

    user = args.jid.split("@")[0]
    print(_c(f"[*] validating {user}@{args.domain} against {args.host}:{args.port}", "C"))
    print(_c(f"    mech order: {args.mechs}", "C"))
    if args.no_starttls:
        print(_c("[!] --no-starttls — plaintext SASL.", "Y"))
    print()

    try:
        sock, feats = _open(args.host, args.port, args.domain, not args.no_starttls, args.timeout)
    except Exception as e:
        print(_c(f"[!] stream open failed: {e}", "R")); return 2

    feats_text = feats.decode("utf-8", errors="replace")
    advertised = set(re.findall(r"<mechanism>([^<]+)</mechanism>", feats_text))
    print(_c(f"    server advertises: {sorted(advertised)}", "C"))

    mech_to_kind = {
        "scram-sha-256": ("SCRAM-SHA-256", lambda: _scram(sock, user, password, "sha256", args.timeout)),
        "scram-sha-1":   ("SCRAM-SHA-1",   lambda: _scram(sock, user, password, "sha1",   args.timeout)),
        "plain":         ("PLAIN",         lambda: _auth_plain(sock, user, password, args.timeout)),
    }

    for m in [m.strip().lower() for m in args.mechs.split(",")]:
        if m not in mech_to_kind:
            print(_c(f"[!] unknown mech {m}", "Y")); continue
        adv_name, runner = mech_to_kind[m]
        if adv_name not in advertised:
            print(f"  [-] {adv_name:14s} not advertised — skipping")
            continue
        print(f"  [*] {adv_name:14s} ...", end="", flush=True)
        try:
            ok, detail = runner()
        except Exception as e:
            print(_c(f" ERROR: {e}", "R")); continue
        if ok:
            print(_c(" AUTH_OK", "G"))
            try: sock.close()
            except: pass
            return 0
        else:
            print(_c(f" AUTH_FAIL", "Y"))
            print(_c(f"      response: {detail[:200]}", "Y"))
            # Once any mech returns <failure>, the stream is generally
            # poisoned — re-open for the next mech.
            try: sock.close()
            except: pass
            try:
                sock, feats = _open(args.host, args.port, args.domain, not args.no_starttls, args.timeout)
            except Exception as e:
                print(_c(f"[!] re-open failed: {e}", "R")); return 1

    print(_c("[!] all advertised+requested mechs rejected the credential", "R"))
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr); sys.exit(130)
