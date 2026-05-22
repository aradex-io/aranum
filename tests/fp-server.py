#!/usr/bin/env python3
"""Multi-flavor FP test server. Listens on N ports, each running a different
'wrong protocol' service so we can verify aratool dispatchers don't FP."""
import socket, threading, time, sys, signal, argparse

# ---- flavor handlers ---------------------------------------------------------
def http_handler(c):
    """Plain HTTP/1.1 200 OK — generic web server impersonation."""
    try:
        data = c.recv(4096)
        body = b"<html><body>nope, just a web server</body></html>"
        c.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: SimpleHTTP/0.6 Python/3.12\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
    except Exception: pass
    finally: c.close()

def ssh_handler(c):
    """SSH banner — wrong-protocol-on-port scenario."""
    try:
        c.sendall(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n")
        time.sleep(0.5)
    except Exception: pass
    finally: c.close()

def accept_silent_handler(c):
    """Accept then silent — TCP three-way handshake completes but no app data."""
    try:
        time.sleep(2)
    except Exception: pass
    finally: c.close()

def echo_handler(c):
    """Echo whatever the client sends. Many naive scanners FP on this."""
    try:
        c.settimeout(2)
        data = c.recv(4096)
        if data: c.sendall(data)
    except Exception: pass
    finally: c.close()

# ---- listener ----------------------------------------------------------------
def serve(port, handler, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    print(f"[harness] {name} listening on 127.0.0.1:{port}", flush=True)
    while True:
        try:
            c, _ = s.accept()
            threading.Thread(target=handler, args=(c,), daemon=True).start()
        except Exception: break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FP test server — wrong-protocol scenarios")
    parser.add_argument("--port-base", type=int, default=19000,
                        help="Base port (default 19000). Four consecutive ports are used.")
    args = parser.parse_args()
    base = args.port_base

    flavors = [
        (base + 0, http_handler,           "http-200"),
        (base + 1, ssh_handler,            "ssh-banner"),
        (base + 2, accept_silent_handler,  "accept-silent"),
        (base + 3, echo_handler,           "tcp-echo"),
    ]
    for port, h, name in flavors:
        threading.Thread(target=serve, args=(port, h, name), daemon=True).start()
    signal.pause()
