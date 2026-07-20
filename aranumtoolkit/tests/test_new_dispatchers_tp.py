#!/usr/bin/env python3
"""test_new_dispatchers_tp.py — true-positive tests for the REVIEW-004 HTTP
dispatchers: each must DETECT its own service (emit the CRITICAL marker) when
pointed at a stub that mimics that service. Complements the FP harness (which
proves dispatchers don't fire on the wrong service). Self-contained http.server
stubs on an ephemeral port — no external deps, skips cleanly if curl is absent.
"""
from __future__ import annotations

import http.server
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"


class _Stub(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        for prefix, (code, body) in self.routes.items():
            if self.path.startswith(prefix):
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(404); self.end_headers()


def _serve(routes):
    handler = type("H", (_Stub,), {"routes": routes})
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


@unittest.skipUnless(shutil.which("curl"), "curl required for HTTP dispatcher TP tests")
class TestNewDispatcherTruePositives(unittest.TestCase):
    def _run_dispatcher(self, script, port):
        with tempfile.TemporaryDirectory() as td:
            tgt = Path(td) / "t.txt"; tgt.write_text(f"127.0.0.1:{port}\n")
            out = Path(td) / "out"
            r = subprocess.run(
                ["bash", str(NET / script), "--targets", str(tgt), "--output", str(out)],
                capture_output=True, text=True, timeout=60)
            return r.stdout + r.stderr

    def test_clickhouse_detected(self):
        routes = {
            "/ping": (200, b"Ok.\n"),
            "/?query": (200, b"default\nsystem\n"),
        }
        srv, port = _serve(routes)
        try:
            out = self._run_dispatcher("enum-clickhouse.sh", port)
        finally:
            srv.shutdown()
        self.assertIn("UNAUTH ClickHouse", out, out)

    def test_couchbase_detected(self):
        routes = {"/pools": (200, b'{"implementationVersion":"7.2.0-enterprise","pools":[]}')}
        srv, port = _serve(routes)
        try:
            out = self._run_dispatcher("enum-couchbase.sh", port)
        finally:
            srv.shutdown()
        self.assertIn("UNAUTH Couchbase", out, out)


if __name__ == "__main__":
    unittest.main()
