#!/usr/bin/env python3
"""True-positive simulator stubs for the fixed dispatchers.

Port layout (offsets from --port-base, default 19010):
  +0  rsync daemon stub   — sends module list after handshake (rc=0)
  +1  telnet IAC stub     — sends IAC option-negotiation bytes on connect

AJP TP is NOT stubbed here — it is verified via a static fixture file
aranumtoolkit/tests/fixtures/ajp-real-nmap.txt in fp-harness.sh.

Product-detect TP stubs (offsets from --port-base, default 19010):
  +10 (19020)  Jenkins stub  — X-Jenkins header + hudson.model.Hudson body
  +11 (19021)  Grafana stub  — /api/health with "database" + "version" keys
  +12 (19022)  Prometheus stub — /-/healthy exact body
  +14 (19024)  vCenter stub  — /sdk/vimServiceVersions.xml + /ui/ responses

I-K print stubs (offsets from --port-base, default 19010):
  +15 (19025)  JetDirect / PJL stub — UEL framing + @PJL INFO ID response
  +16 (19026)  LPD daemon stub — RFC 1179 short-form queue dump

These stubs serve on a fixed base+offset so fp-harness.sh can refer to
the absolute ports directly (base=19010, so 19020/19021/19022/19024/19025/19026).
"""
import socket, threading, time, sys, signal, argparse

# ---- rsync stub (port base+0) -----------------------------------------------
# Real rsync handshake:
#   S -> C: @RSYNCD: 31.0\n
#   C -> S: @RSYNCD: 31.0\n          (version echo)
#   C -> S: \n                        (empty module = list request)
#   S -> C: <module lines>\n
#   S -> C: @RSYNCD: EXIT\n
def rsync_handler(c):
    try:
        c.sendall(b"@RSYNCD: 31.0\n")
        # read client greeting line (version echo)
        _line = b""
        while True:
            ch = c.recv(1)
            if not ch or ch == b"\n":
                break
            _line += ch
        # read client module request (empty line = list)
        _mod = b""
        while True:
            ch = c.recv(1)
            if not ch or ch == b"\n":
                break
            _mod += ch
        # send module list then EXIT
        c.sendall(b"alpha\tFirst module\nbeta\tBackup module\n@RSYNCD: EXIT\n")
    except Exception:
        pass
    finally:
        c.close()

# ---- telnet IAC stub (port base+1) ------------------------------------------
# Send standard IAC WILL / DO option-negotiation bytes followed by a login prompt.
# 0xFF 0xFD 0x18 = IAC DO TERMINAL-TYPE
# 0xFF 0xFD 0x20 = IAC DO TERMINAL-SPEED
# 0xFF 0xFD 0x23 = IAC DO X-DISPLAY-LOCATION
def telnet_handler(c):
    try:
        c.sendall(
            b"\xff\xfd\x18"       # IAC DO TERMINAL-TYPE
            b"\xff\xfd\x20"       # IAC DO TERMINAL-SPEED
            b"\xff\xfd\x23"       # IAC DO X-DISPLAY-LOCATION
            b"\r\nUser Access Verification\r\nUsername: "
        )
        time.sleep(2)
    except Exception:
        pass
    finally:
        c.close()

# ---- Jenkins TP stub (port base+10 = 19020) ---------------------------------
# Serves any request with X-Jenkins header + hudson.model.Hudson JSON body.
# enum-http.sh C.13 requires X-Jenkins header to be present — that is the
# product-specific marker. Status 200 + "_class":"hudson.model.Hudson" triggers
# the UNAUTH: Jenkins API exposed hit too.
JENKINS_BODY = b'{"_class":"hudson.model.Hudson","mode":"NORMAL"}'
JENKINS_BODY_LEN = str(len(JENKINS_BODY)).encode()

def jenkins_handler(c):
    try:
        c.recv(4096)   # drain the HTTP request
        c.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"X-Jenkins: 2.452.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + JENKINS_BODY_LEN + b"\r\n"
            b"\r\n" +
            JENKINS_BODY
        )
    except Exception:
        pass
    finally:
        c.close()


# ---- Grafana TP stub (port base+11 = 19021) ---------------------------------
# /api/health response must contain both "database" and "version" JSON keys.
GRAFANA_BODY = b'{"commit":"abc123","database":"ok","version":"10.4.2"}'
GRAFANA_BODY_LEN = str(len(GRAFANA_BODY)).encode()

def grafana_handler(c):
    try:
        c.recv(4096)
        c.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + GRAFANA_BODY_LEN + b"\r\n"
            b"\r\n" +
            GRAFANA_BODY
        )
    except Exception:
        pass
    finally:
        c.close()


# ---- Prometheus TP stub (port base+12 = 19022) ------------------------------
# /-/healthy must return exactly "Prometheus Server is Healthy.\n".
PROMETHEUS_BODY = b"Prometheus Server is Healthy.\n"
PROMETHEUS_BODY_LEN = str(len(PROMETHEUS_BODY)).encode()

def prometheus_handler(c):
    try:
        c.recv(4096)
        c.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + PROMETHEUS_BODY_LEN + b"\r\n"
            b"\r\n" +
            PROMETHEUS_BODY
        )
    except Exception:
        pass
    finally:
        c.close()


# ---- VMware vCenter TP stub (port base+14 = 19024) --------------------------
# enum-http.sh C.13 probes two endpoints:
#   GET /sdk/vimServiceVersions.xml  — expects <namespace>urn:vim25</namespace>
#   GET /ui/                          — expects <title>vSphere Client</title>
VCENTER_SDK_BODY = b'<?xml version="1.0"?><namespaces><namespace>urn:vim25</namespace></namespaces>'
VCENTER_SDK_LEN  = str(len(VCENTER_SDK_BODY)).encode()
VCENTER_UI_BODY  = b'<html><head><title>vSphere Client</title></head></html>'
VCENTER_UI_LEN   = str(len(VCENTER_UI_BODY)).encode()

def vcenter_handler(c):
    try:
        req = c.recv(4096).decode("utf-8", errors="replace")
        if "/sdk/vimServiceVersions.xml" in req:
            c.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/xml\r\n"
                b"Content-Length: " + VCENTER_SDK_LEN + b"\r\n"
                b"\r\n" +
                VCENTER_SDK_BODY
            )
        elif req.startswith("GET /ui/") or req.startswith("GET /ui "):
            c.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: " + VCENTER_UI_LEN + b"\r\n"
                b"\r\n" +
                VCENTER_UI_BODY
            )
        else:
            c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    except Exception:
        pass
    finally:
        c.close()


# ---- JetDirect / PJL TP stub (port base+15 = 19025) -------------------------
# Reads the operator's PJL probe and responds with a UEL-framed @PJL INFO ID
# block carrying a recognizable device model in quoted form.
def jetdirect_handler(c):
    try:
        c.settimeout(3)
        try:
            c.recv(2048)
        except Exception:
            pass
        # Real JetDirect echoes the UEL framing bytes around its response.
        # \x1b%-12345X@PJL ... \x1b%-12345X is the canonical sequence.
        response = (
            b"\x1b%-12345X"
            b"@PJL INFO ID\r\n"
            b"\"hp LaserJet M607 (test-stub)\"\r\n"
            b"@PJL INFO PRODINFO\r\n"
            b"PRODUCT=\"M607\"\r\nFIRMWARE_REV=\"4.10.2.0\"\r\n"
            b"@PJL INFO STATUS\r\n"
            b"CODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n"
            b"PAGE COUNT = 8421\r\n"
            b"\x1b%-12345X"
        )
        c.sendall(response)
        time.sleep(0.2)
    except Exception:
        pass
    finally:
        c.close()


# ---- LPD TP stub (port base+16 = 19026) -------------------------------------
# Responds to RFC 1179 short-form queue probes (\x04<queue>\n) with a queue
# dump including the canonical "Rank Owner Job Files" column header.
def lpd_handler(c):
    try:
        c.settimeout(3)
        try:
            req = c.recv(64)
        except Exception:
            req = b""
        # Short-form queue dump (most common operator-visible LPD response).
        response = (
            b"Rank   Owner      Job  Files                    Total Size\r\n"
            b"active alice      42   confidential.pdf         15234 bytes\r\n"
            b"1st    bob        43   q3-report.ps             89221 bytes\r\n"
        )
        c.sendall(response)
        time.sleep(0.2)
    except Exception:
        pass
    finally:
        c.close()


# ---- generic listener --------------------------------------------------------
def serve(port, handler, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    print(f"[tp-harness] {name} listening on 127.0.0.1:{port}", flush=True)
    while True:
        try:
            c, _ = s.accept()
            threading.Thread(target=handler, args=(c,), daemon=True).start()
        except Exception:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TP stub server for aranum dispatcher regression tests")
    parser.add_argument("--port-base", type=int, default=19010,
                        help="Base port (default 19010). Two consecutive ports are used.")
    args = parser.parse_args()
    base = args.port_base

    stubs = [
        (base + 0,  rsync_handler,      "rsync-stub"),
        (base + 1,  telnet_handler,     "telnet-iac-stub"),
        (base + 10, jenkins_handler,    "jenkins-stub"),
        (base + 11, grafana_handler,    "grafana-stub"),
        (base + 12, prometheus_handler, "prometheus-stub"),
        (base + 14, vcenter_handler,    "vcenter-stub"),
        (base + 15, jetdirect_handler,  "jetdirect-stub"),
        (base + 16, lpd_handler,        "lpd-stub"),
    ]
    for port, h, name in stubs:
        threading.Thread(target=serve, args=(port, h, name), daemon=True).start()
    signal.pause()
