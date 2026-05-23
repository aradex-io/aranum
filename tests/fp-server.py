#!/usr/bin/env python3
"""Multi-flavor FP test server. Listens on N ports, each running a different
'wrong protocol' service so we can verify aratool dispatchers don't FP.

The "evil-*" flavors (added 2026-05-22 for v0.22.1) cover the v0.20.1
known-gap class: specifically-crafted servers that embed dispatcher keywords
in benign protocol layers. They protect the two-evidence discipline by
ensuring keyword-only matches don't promote to findings."""
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

# ---- evil-* flavors (cross-service FP scenarios) -----------------------------
# v0.20.1 Notes flagged that "specifically-crafted evil servers could still
# trigger FPs". These three flavors are the answer to that gap.

_EVIL_JSON_BODY = (
    b'{"status":"ok","note":"this is NOT a real product",'
    b'"keywords":["sealed","neo4j_version","consul","vault","elasticsearch",'
    b'"kibana","couchdb","etcd","ipp-cups","zookeeper","cassandra","kafka",'
    b'"influxdb","solr","jenkins","grafana","prometheus","vmware-vcenter",'
    b'"oracle-tns","mongodb","postgresql","mysql","redis","activemq",'
    b'"rabbitmq","memcached","jmx","docker","kubernetes","ipmi"],'
    b'"shape":"flat-object - no per-product nested structure",'
    b'"http_status":200,"vault_token":"NOT_A_REAL_TOKEN",'
    b'"sealed":false,"initialized":true}'
)

def evil_json_handler(c):
    """HTTP/200 with a JSON body that name-drops every dispatcher's keywords.

    This protects the "two-evidence" discipline (v0.21.0 ADR) — a real
    product fingerprint requires protocol-specific endpoint shape, not just
    the keyword appearing somewhere. Any dispatcher that FPs on this is
    matching content too loosely."""
    try:
        c.recv(4096)
        c.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(_EVIL_JSON_BODY)).encode() + b"\r\n\r\n"
            + _EVIL_JSON_BODY
        )
    except Exception: pass
    finally: c.close()

def evil_banner_handler(c):
    """Plain TCP banner containing the literal strings of many protocols but
    no protocol behavior. Tests that dispatchers require *protocol-level*
    markers (IAC bytes, fingerprint lines, handshake replies) not just the
    word in a banner.

    Specifically embeds: "ajp13" (must require nmap fingerprint AND script
    result), "Telnet" (must require IAC bytes 0xFF 0xFB-0xFE), "rsync" (must
    require RSYNCD handshake), "ssh" (must not confuse anything), and the
    free-text labels of half the dispatcher set."""
    try:
        banner = (
            b"Welcome to multi-protocol-test-banner\r\n"
            b"Tags: ajp13 / Telnet / rsync / cassandra / oracle-tns / mqtt / sip\r\n"
            b"NOTE: this is a banner string only - no protocol behavior follows\r\n"
            b"\r\n"
        )
        c.sendall(banner)
        time.sleep(1)
    except Exception: pass
    finally: c.close()

def evil_product_headers_handler(c):
    """HTTP/200 with Server / X-Powered-By / Set-Cookie headers claiming to
    be a product, but no product-specific endpoint behavior. Targets the
    enum-http.sh product-detect FP class — a real product fingerprint must
    require body / JSON-key evidence, not just headers.

    Headers claim Jenkins + Grafana + Solr + Vault. Body is plain HTML with
    NO API endpoints implemented (a real GET /api/json returns 404)."""
    try:
        data = c.recv(4096) or b""
        # Always 404 on any path — so a real product-detect probe finds
        # NO endpoints alive even though headers are vendor-stuffed.
        body = b"<html><body>404 not found</body></html>"
        c.sendall(
            b"HTTP/1.1 404 Not Found\r\n"
            b"Server: Jenkins/2.401.3\r\n"
            b"X-Powered-By: Apache Solr 9.3.0\r\n"
            b"X-Grafana-Version: 10.2.0\r\n"
            b"Set-Cookie: vault_token=FAKE-NOT-REAL; Path=/\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
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
                        help="Base port (default 19000). Seven consecutive ports are used.")
    args = parser.parse_args()
    base = args.port_base

    flavors = [
        (base + 0, http_handler,                 "http-200"),
        (base + 1, ssh_handler,                  "ssh-banner"),
        (base + 2, accept_silent_handler,        "accept-silent"),
        (base + 3, echo_handler,                 "tcp-echo"),
        # evil-* scenarios — v0.22.1 cross-service FP coverage
        (base + 4, evil_json_handler,            "evil-json"),
        (base + 5, evil_banner_handler,          "evil-banner"),
        (base + 6, evil_product_headers_handler, "evil-product-hdrs"),
    ]
    for port, h, name in flavors:
        threading.Thread(target=serve, args=(port, h, name), daemon=True).start()
    signal.pause()
