#!/usr/bin/env python3
"""test_proxy_norpc.py — auto-enum.sh --proxy (Burp routing) and --no-rpc.

--proxy exports ENUM_PROXY + HTTP(S)_PROXY to every dispatcher (so curl/httpx/
nuclei/ffuf/whatweb + the python HTTP tools route through an intercepting proxy).
--no-rpc excludes the msrpc dispatcher and sets NO_RPC=1 so rpcclient-using
dispatchers (enum-smb.sh) skip their RPC calls.

Exercised via `--dry-run` so no scanners actually run (no network).
"""
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
AUTO = REPO / "aranumtoolkit" / "network" / "auto-enum.sh"

GNMAP = (
    "Host: 10.0.0.5 ()\tPorts: 80/open/tcp//http///, "
    "135/open/tcp//msrpc///, 445/open/tcp//microsoft-ds///\tIgnored State: closed (0)\n"
)


def _dry_run(tmp, *extra):
    gnmap = tmp / "t.gnmap"
    gnmap.write_text(GNMAP)
    out = tmp / "out"
    cmd = ["bash", str(AUTO), "-i", str(gnmap), "-o", str(out), "--dry-run", *extra]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


class ProxyNoRpcTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_proxy_normalizes_and_announces(self):
        p = _dry_run(self.tmp, "--proxy", "127.0.0.1:8080")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("http://127.0.0.1:8080", p.stdout)
        self.assertIn("proxy", p.stdout.lower())

    def test_proxy_full_url_preserved(self):
        p = _dry_run(self.tmp, "--proxy", "socks5://127.0.0.1:1080")
        self.assertIn("socks5://127.0.0.1:1080", p.stdout)

    def test_no_rpc_excludes_msrpc(self):
        p = _dry_run(self.tmp, "--no-rpc")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("NO_RPC=1", p.stdout)
        # http + smb still dispatched; msrpc must not be a dispatched service line.
        self.assertRegex(p.stdout, r"Service:\s*http")
        self.assertNotRegex(p.stdout, r"Service:\s*msrpc")

    def test_rpc_present_without_flag(self):
        # Sanity: without --no-rpc, msrpc IS a dispatched service (proves the
        # exclusion above is real, not a fixture artifact).
        p = _dry_run(self.tmp)
        self.assertRegex(p.stdout, r"Service:\s*msrpc")


if __name__ == "__main__":
    unittest.main()
