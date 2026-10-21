#!/usr/bin/env python3
"""connect-reply-sim.py — simulate an HTTP CONNECT reply "back from a remote host".

Authorized testing / lab use only. Crafts the TCP segment a proxy / remote host sends
in response to an HTTP `CONNECT host:port HTTP/1.1` request — i.e.

    HTTP/1.1 200 Connection Established\r\n\r\n

Why: to exercise a client, a proxy-handling code path, or network monitoring against a
controlled "remote host" reply without standing up a real proxy — e.g. validating
aranum's `--proxy` routing, a tunneling client, or a detection rule, on a network you own.

SAFETY (CLAUDE.md §1 / §9):
  * DEFAULT IS DRY-RUN. The script only *builds and prints* the packet. Nothing is put on
    the wire until you pass the explicit `--send` flag — the same "no target-write without
    an explicit flag" gate the rest of aranum uses.
  * Only aim `--send` at hosts/segments you are authorized to test. Emitting a
    crafted/spoofed-source reply at third-party traffic is out of scope for this repo.
  * No persistence, no exfiltration, no detection-evasion. Output (pcap) goes only to the
    path you pass with `--write-pcap`.

Modes:
  craft           (default) build one reply from the addresses/seq/ack you supply.
  --sniff-respond lab responder: sniff an inbound CONNECT on --iface and build the matching
                  reply with correct seq/ack derived from the observed request.

Style: CLAUDE.md §8 (stdlib + scapy; type hints on public functions; errors to stderr).
"""
from __future__ import annotations

import argparse
import sys
from typing import Optional

PROG = "connect-reply-sim.py"


def _err(msg: str) -> None:
    print(f"{PROG}: {msg}", file=sys.stderr)


try:
    from scapy.all import IP, TCP, Raw, send, sniff, conf  # type: ignore
    from scapy.packet import Packet  # type: ignore
except Exception as exc:  # pragma: no cover - import guard
    _err(f"scapy is required (pip install scapy): {exc}")
    sys.exit(3)


def build_payload(status: str, headers: Optional[list[str]]) -> bytes:
    """Build the HTTP CONNECT response body (status line + optional headers + CRLFCRLF)."""
    line = f"HTTP/1.1 {status}\r\n"
    hdr = ""
    if headers:
        hdr = "".join(h.rstrip("\r\n") + "\r\n" for h in headers)
    return (line + hdr + "\r\n").encode("latin-1", "replace")


def build_reply(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> Packet:
    """Craft the simulated CONNECT reply: PSH,ACK from the remote host to the client."""
    return (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)
        / Raw(load=payload)
    )


def emit(pkt: Packet, do_send: bool, count: int, interval: float, pcap: Optional[str]) -> None:
    """Dry-run print, optionally transmit (only when do_send), optionally save a pcap."""
    print(pkt.summary())
    pkt.show()
    if pcap:
        try:
            from scapy.all import wrpcap  # type: ignore
            wrpcap(pcap, [pkt])
            print(f"[+] wrote crafted packet to {pcap}")
        except Exception as exc:
            _err(f"could not write pcap {pcap}: {exc}")
    if not do_send:
        print("[dry-run] not sent — pass --send to transmit (authorized targets only).")
        return
    import os
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        _err("sending raw packets needs root (re-run with sudo).")
        sys.exit(4)
    send(pkt, count=count, inter=interval, verbose=True)
    print(f"[+] sent {count} packet(s).")


def _is_connect_request(pkt: Packet) -> bool:
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return False
    try:
        return bytes(pkt[Raw].load).lstrip().upper().startswith(b"CONNECT")
    except Exception:
        return False


def run_sniff_respond(args: argparse.Namespace, payload: bytes) -> int:
    """Lab responder: wait for a CONNECT to our sport, craft the matching reply."""
    bpf = f"tcp and dst port {args.sport}"
    if args.dst:
        bpf += f" and src host {args.dst}"
    print(f"[*] sniffing on {args.iface or conf.iface} for CONNECT ({bpf}) ... Ctrl-C to stop")

    def _handle(pkt: Packet) -> None:
        if not _is_connect_request(pkt):
            return
        ip, tcp, raw = pkt[IP], pkt[TCP], pkt[Raw]
        reply = build_reply(
            src=args.src or ip.dst,          # reply "from" the host the client dialed
            sport=args.sport,
            dst=ip.src,                       # back to the client
            dport=tcp.sport,
            seq=tcp.ack,                      # our seq = what the client already ACKed
            ack=tcp.seq + len(bytes(raw.load)),  # ack the request bytes
            payload=payload,
        )
        print(f"[>] CONNECT from {ip.src}:{tcp.sport} -> replying {args.status}")
        emit(reply, args.send, 1, 0.0, args.write_pcap)

    try:
        sniff(filter=bpf, iface=args.iface, prn=_handle, store=False, count=args.max_replies)
    except PermissionError:
        _err("sniffing needs root (re-run with sudo).")
        return 4
    except KeyboardInterrupt:
        print("\n[*] stopped.")
    return 0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Simulate an HTTP CONNECT reply from a remote host (dry-run by default).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  # dry-run: just show the packet that WOULD be sent\n"
            "  sudo ./connect-reply-sim.py --src 10.0.0.9 --sport 8080 --dst 10.0.0.5 --dport 51000\n\n"
            "  # actually transmit one reply on a lab segment\n"
            "  sudo ./connect-reply-sim.py --src 10.0.0.9 --dst 10.0.0.5 --dport 51000 --send\n\n"
            "  # lab responder: answer real CONNECTs seen on eth0 (authorized network only)\n"
            "  sudo ./connect-reply-sim.py --sniff-respond --iface eth0 --sport 8080 --send\n\n"
            "  # save the crafted packet to a pcap instead of sending\n"
            "  ./connect-reply-sim.py --src 10.0.0.9 --dst 10.0.0.5 --dport 51000 --write-pcap reply.pcap\n"
        ),
    )
    p.add_argument("--src", help="simulated remote-host/proxy source IP (reply appears to come from here)")
    p.add_argument("--sport", type=int, default=8080, help="remote-host/proxy TCP port (default 8080)")
    p.add_argument("--dst", help="client IP the reply is sent to")
    p.add_argument("--dport", type=int, help="client TCP (ephemeral) port")
    p.add_argument("--seq", type=int, default=1, help="TCP sequence number for the reply (craft mode)")
    p.add_argument("--ack", type=int, default=1, help="TCP ack number for the reply (craft mode)")
    p.add_argument("--status", default="200 Connection Established",
                   help='HTTP status line after "HTTP/1.1 " (default: "200 Connection Established")')
    p.add_argument("--header", action="append", dest="headers",
                   help="extra response header line (repeatable), e.g. --header 'Via: 1.1 lab'")
    p.add_argument("--count", type=int, default=1, help="craft mode: number of copies to send (default 1)")
    p.add_argument("--interval", type=float, default=0.0, help="craft mode: seconds between sends")
    p.add_argument("--iface", help="interface for --sniff-respond / --send")
    p.add_argument("--sniff-respond", action="store_true",
                   help="lab responder: sniff for a CONNECT and reply with the matching seq/ack")
    p.add_argument("--max-replies", type=int, default=0,
                   help="--sniff-respond: stop after N replies (0 = run until Ctrl-C)")
    p.add_argument("--write-pcap", metavar="FILE", help="save the crafted packet(s) to a pcap (operator path)")
    p.add_argument("--send", action="store_true",
                   help="ACTUALLY transmit (default is dry-run). Authorized targets only.")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    payload = build_payload(args.status, args.headers)

    if args.sniff_respond:
        return run_sniff_respond(args, payload)

    # craft mode
    if not args.src or not args.dst or args.dport is None:
        _err("craft mode needs --src, --dst and --dport (or use --sniff-respond). See --help.")
        return 2

    reply = build_reply(
        src=args.src, sport=args.sport, dst=args.dst, dport=args.dport,
        seq=args.seq, ack=args.ack, payload=payload,
    )
    emit(reply, args.send, args.count, args.interval, args.write_pcap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
