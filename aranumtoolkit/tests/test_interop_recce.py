#!/usr/bin/env python3
"""test_interop_recce.py — unit tests for aranumtoolkit/interop/aranum_to_recce.py.

Run: python3 -m unittest tests.test_interop_recce
or:  python3 aranumtoolkit/tests/test_interop_recce.py

The translation helpers (IP/port resolution, SERVICE_MAP loading, inventory and
raw-tree port extraction, subnet sizing, source auto-discovery) are recce-
independent and always tested. The full end-to-end `ingest()` is exercised only
when the recce package is importable (set RECCE_PATH=/path/to/recce, or have it
on PYTHONPATH); otherwise that one test skips, so CI without recce stays green.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ADAPTER = REPO / "aranumtoolkit" / "interop" / "aranum_to_recce.py"


def _load():
    spec = importlib.util.spec_from_file_location("aranum_to_recce", ADAPTER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load()


def _wj(path: str, obj) -> str:
    with open(path, "w") as fh:
        json.dump(obj, fh)
    return path


def _try_recce():
    """Return the recce module if importable (honoring RECCE_PATH), else None."""
    rp = os.environ.get("RECCE_PATH")
    try:
        return M._load_recce(rp) if rp else __import__("recce")
    except SystemExit:
        return None
    except ImportError:
        return None


class TestHelpers(unittest.TestCase):
    def test_resolve_ip_direct_and_from_line(self):
        self.assertEqual(M._resolve_ip({"host": "10.0.0.5"}), "10.0.0.5")
        # synthetic (dispatcher) bucket -> first IPv4 in the line
        self.assertEqual(
            M._resolve_ip({"host": "(dispatcher)",
                           "line": "admin at http://10.0.0.11:8080/x"}),
            "10.0.0.11")
        self.assertIsNone(M._resolve_ip({"host": "", "line": "no ip here"}))

    def test_resolve_port_explicit_and_embedded(self):
        self.assertEqual(M._resolve_port({"port": "445"}), 445)
        self.assertEqual(M._resolve_port({"port": "", "line": "http://h:8080/x"}), 8080)
        self.assertEqual(M._resolve_port({"port": "", "line": "445/tcp open"}), 445)
        self.assertIsNone(M._resolve_port({"port": "", "line": "nothing"}))
        self.assertIsNone(M._resolve_port({"port": "99999"}))  # out of range

    def test_severity_passthrough_and_fallback(self):
        self.assertEqual(M._severity({"severity": "CRITICAL"}), "critical")
        self.assertEqual(M._severity({"severity": "bogus"}), "info")
        self.assertEqual(M._severity({}), "info")

    def test_subnet_size(self):
        self.assertEqual(M._subnet_size("10.0.0.0/24"), 254)
        self.assertEqual(M._subnet_size("10.0.0.0/30"), 2)
        self.assertEqual(M._subnet_size("10.0.0.5/32"), 1)
        self.assertEqual(M._subnet_size("garbage"), 0)

    def test_service_map_loads_and_has_core_services(self):
        sp = M._load_service_ports()
        # If nmap-parse.py is present (it is, in-repo), these must be populated.
        self.assertIn("smb", sp)
        self.assertIn(445, sp["smb"])
        self.assertIn(389, sp["ldap"])

    def test_primary_port_overrides(self):
        sp = M._load_service_ports()
        # smb lists 139 and 445; canonical must be 445, not min() == 139.
        self.assertEqual(M._primary_port("smb", sp), 445)
        self.assertEqual(M._primary_port("nfs", sp), 2049)
        self.assertEqual(M._primary_port("ldap", sp), 389)  # min is correct here
        self.assertIsNone(M._primary_port("nonexistent-svc", sp))

    def test_ports_from_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            p = _wj(os.path.join(d, "inv.json"), {"summary": {}, "entries": [
                {"ip": "10.0.0.5", "port": 445, "proto": "tcp", "service": "smb",
                 "product": "Samba", "version": "4.15"},
                {"ip": "10.0.0.5", "port": 80, "service": "http"},
                {"ip": "bad", "port": 80},          # dropped: bad ip
                {"ip": "10.0.0.6", "port": "x"},    # dropped: non-int port
            ]})
            got = M._ports_from_inventory(p)
        self.assertEqual(len(got), 2)
        smb = next(e for e in got if e["port"] == 445)
        self.assertEqual((smb["service"], smb["product"], smb["version"]),
                         ("smb", "Samba", "4.15"))

    def test_ports_from_raw_tree_both_layouts(self):
        sp = M._load_service_ports()
        with tempfile.TemporaryDirectory() as d:
            # <service>/<ip>_<port>/  and  <service>/<ip>/  and a _skipped dir
            os.makedirs(os.path.join(d, "http", "10.0.0.5_8080"))
            os.makedirs(os.path.join(d, "smb", "10.0.0.7"))       # bare IP leaf
            os.makedirs(os.path.join(d, "_logs", "x"))            # ignored
            got = {(e["service"], e["ip"], e["port"])
                   for e in M._ports_from_raw_tree(d, sp)}
        self.assertIn(("http", "10.0.0.5", 8080), got)
        # bare-IP smb leaf -> canonical smb port 445
        self.assertIn(("smb", "10.0.0.7", 445), got)
        self.assertFalse(any(e[0] == "_logs" for e in got))

    def test_resolve_source_dir_and_file(self):
        with tempfile.TemporaryDirectory() as d:
            fj = _wj(os.path.join(d, "findings.json"), {"findings": []})
            self.assertEqual(M._resolve_source(fj), fj)          # direct file
            self.assertEqual(M._resolve_source(d), fj)           # session dir
        with self.assertRaises(SystemExit):
            M._resolve_source("/nonexistent/path/xyz")


class TestIngestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.recce = _try_recce()
        if self.recce is None:
            self.skipTest("recce not importable (set RECCE_PATH to enable)")

    def test_full_coverage_ingest(self):
        with tempfile.TemporaryDirectory() as d:
            inv = _wj(os.path.join(d, "inv.json"), {"summary": {}, "entries": [
                {"ip": "10.9.0.10", "port": 445, "proto": "tcp", "service": "smb"},
                {"ip": "10.9.0.10", "port": 8080, "service": "http",
                 "product": "Tomcat", "version": "9"},
                {"ip": "10.9.0.11", "port": 22, "service": "ssh"},
            ]})
            fj = _wj(os.path.join(d, "findings.json"),
                     {"schema_version": "2", "label": "t", "findings": [
                         {"host": "10.9.0.10", "port": "", "service": "smb",
                          "severity": "critical", "line": "MS17-010 CVE-2017-0144",
                          "title": "eb"}]})
            out = os.path.join(d, "eng")
            M.ingest(fj, out, self.recce, inventory_path=inv,
                     no_autodiscover=True, quiet=True)

            import sys as _sys
            rp = os.environ.get("RECCE_PATH")
            if rp and rp not in _sys.path:
                _sys.path.insert(0, rp)
            from recce.store import Store
            s = Store(os.path.join(out, "results.sqlite"))
            try:
                hosts = {h.ip: h for h in s.all_hosts()}
                self.assertEqual(set(hosts), {"10.9.0.10", "10.9.0.11"})
                ports = {(h.ip, p.portid) for h in hosts.values() for p in h.ports}
                self.assertEqual(ports, {("10.9.0.10", 445), ("10.9.0.10", 8080),
                                         ("10.9.0.11", 22)})
                v = [v for h in hosts.values() for v in h.vulns]
                self.assertEqual(len(v), 1)
                self.assertEqual(v[0].severity, "critical")
                self.assertEqual(v[0].source, "aranum")
                self.assertIn("CVE-2017-0144", v[0].ids)
            finally:
                s.close()


if __name__ == "__main__":
    unittest.main()
