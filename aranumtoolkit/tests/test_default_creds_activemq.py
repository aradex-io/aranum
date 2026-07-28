#!/usr/bin/env python3
"""test_default_creds_activemq.py — regression for the ActiveMQ default-creds
false-negative (admin:admin reported "could not authenticate").

Root cause: try_creds required status == success_code (200) exactly, but a valid
Basic-auth login on the ActiveMQ/Jetty console 302-redirects to a dashboard, so
the 302 read as failure. Fixed with an unauth-baseline "auth-gate-cleared" check
(unauth 401/403 -> credentialed 2xx/3xx = creds accepted).

Uses a local mock server (401 unauth, 302 on valid admin:admin, 401 on wrong
creds) — no network, no real ActiveMQ.
"""
import base64
import importlib.util
import http.server
import socketserver
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SWEEP = REPO / "standalones" / "creds" / "default-creds-sweep.py"

_spec = importlib.util.spec_from_file_location("dcs", SWEEP)
dcs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dcs)

_VALID = "Basic " + base64.b64encode(b"admin:admin").decode()


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if not auth:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="ActiveMQRealm"')
            self.end_headers()
            self.wfile.write(b"<html>ActiveMQ console</html>")
            return
        if auth == _VALID:
            self.send_response(302)               # the case the old check missed
            self.send_header("Location", "/admin/index.jsp")
            self.end_headers()
            return
        self.send_response(401)                   # wrong creds
        self.send_header("WWW-Authenticate", 'Basic realm="ActiveMQRealm"')
        self.end_headers()


class ActiveMQDefaultCredsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        socketserver.TCPServer.allow_reuse_address = True
        cls.srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _product(self):
        return {
            "name": "ActiveMQ Web Console",
            "test_path": "/admin/",
            "creds": ["admin:admin"],
            "success_code": 200,
        }

    def test_valid_creds_on_302_redirect_detected(self):
        base = f"http://127.0.0.1:{self.port}"
        ok, status, why = dcs.try_creds(base, self._product(), "admin", "admin")
        self.assertTrue(ok, f"admin:admin must be detected (status={status}, why={why})")
        self.assertEqual(why, "auth-gate-cleared")
        self.assertEqual(status, 302)

    def test_wrong_creds_not_a_false_positive(self):
        base = f"http://127.0.0.1:{self.port}"
        ok, status, why = dcs.try_creds(base, self._product(), "admin", "wrongpass")
        self.assertFalse(ok, f"wrong creds must NOT be reported (status={status}, why={why})")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
