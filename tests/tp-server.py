#!/usr/bin/env python3
"""True-positive simulator stubs for the three fixed dispatchers.

Port layout (offsets from --port-base, default 19010):
  +0  rsync daemon stub  — sends module list after handshake (rc=0)
  +1  telnet IAC stub    — sends IAC option-negotiation bytes on connect

AJP TP is NOT stubbed here — it is verified via a static fixture file
tests/fixtures/ajp-real-nmap.txt in fp-harness.sh.
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
    parser = argparse.ArgumentParser(description="TP stub server for aratool dispatcher regression tests")
    parser.add_argument("--port-base", type=int, default=19010,
                        help="Base port (default 19010). Two consecutive ports are used.")
    args = parser.parse_args()
    base = args.port_base

    stubs = [
        (base + 0, rsync_handler,  "rsync-stub"),
        (base + 1, telnet_handler, "telnet-iac-stub"),
    ]
    for port, h, name in stubs:
        threading.Thread(target=serve, args=(port, h, name), daemon=True).start()
    signal.pause()
