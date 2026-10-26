#!/usr/bin/env python3
"""test_endpoint_attribution.py — D1.3 endpoint attribution (G04, G05).

Proves the new attribution behaviour in report.py:
  * port-less inventory records fold into their port-specific siblings;
  * ``scheme://host`` URLs without a port match the scheme default (http 80,
    https 443, ldap 389, ldaps 636, ftp 21) FOR MATCHING ONLY;
  * an ambiguous-port, single-host line attributes host-level (port="");
  * the token matcher never confuses 10.0.0.1 with 10.0.0.10;
  * a line naming two distinct known hosts stays run-scoped as "(dispatcher)";
  * the shipped example fixture attributes with zero "(dispatcher)" noise
    (iLO -> 10.0.0.30:443, SMB -> 10.0.0.5:445).

These are ordinary unit tests (new-behaviour proof). No new acceptance *gate*
is introduced by D1.3, so Phase 7(c) is N/A for this item.

Run with: python3 -m unittest tests.test_endpoint_attribution
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"
EXAMPLE_FIXTURE = REPO / "aranumtoolkit" / "docs" / "examples" / "dashboard" / "fixture"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_d13", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def _seed_targets(out: Path, service: str, endpoints: list[str]) -> None:
    (out / f"_targets_{service}.txt").write_text("\n".join(endpoints) + "\n")


def _disp(line: str, service: str) -> dict:
    """A raw dispatcher finding, as walk_findings emits one for a top-level log."""
    return {"host": "(dispatcher)", "port": "", "service": service,
            "severity": "high", "line": line, "evidence_path": f"{service}/_dispatcher.log"}


class TestSchemeDefaultPorts(unittest.TestCase):
    def test_bare_https_url_attributes_to_443_not_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _seed_targets(out, "http", ["10.0.0.30:443", "10.0.0.30:8006"])
            fin = R.finalize_findings(
                out, [_disp("BMC HPE iLO detected: https://10.0.0.30 — iLO 5", "http")])
            self.assertEqual(len(fin), 1)
            self.assertEqual(fin[0]["host"], "10.0.0.30")
            self.assertEqual(fin[0]["port"], "443",
                             "https://host with no port must match the 443 endpoint, "
                             "not stay ambiguous against :8006")
            self.assertEqual(fin[0]["scope"], "endpoint")

    def test_explicit_port_url_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _seed_targets(out, "http", ["10.0.0.30:443", "10.0.0.30:8006"])
            fin = R.finalize_findings(
                out, [_disp("Proxmox API exposed: https://10.0.0.30:8006", "http")])
            self.assertEqual(fin[0]["port"], "8006")
            self.assertEqual(fin[0]["scope"], "endpoint")

    def test_normalizer_does_not_mutate_evidence_text(self):
        line = "iLO at https://10.0.0.30 here"
        self.assertEqual(
            R._normalize_scheme_default_ports(line),
            "iLO at https://10.0.0.30:443 here")
        # A URL that already has a port is untouched.
        self.assertEqual(
            R._normalize_scheme_default_ports("x https://10.0.0.30:8006 y"),
            "x https://10.0.0.30:8006 y")


class TestHostLevelFallback(unittest.TestCase):
    def test_ambiguous_ports_same_host_attributes_host_level(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _seed_targets(out, "http", ["10.0.0.30:443", "10.0.0.30:8006"])
            # No scheme/port in the line -> bare host matches BOTH endpoints.
            fin = R.finalize_findings(
                out, [_disp("weak TLS config observed on 10.0.0.30 web stack", "http")])
            self.assertEqual(fin[0]["host"], "10.0.0.30")
            self.assertEqual(fin[0]["port"], "",
                             "ambiguous port -> host-level attribution (port empty)")
            self.assertEqual(fin[0]["scope"], "host",
                             "a host we know is better than (dispatcher)")

    def test_protocol_only_ambiguity_keeps_the_port(self):
        # ROUND2 #5 (regression): the SAME host+port seen as both tcp and udp is
        # a PROTOCOL-only ambiguity, not a port ambiguity. The known port must be
        # kept (protocol blank), not discarded to host scope.
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "inventory.json").write_text(json.dumps({"entries": [
                {"ip": "192.0.2.9", "port": "5060", "proto": "tcp", "service": "sip"},
                {"ip": "192.0.2.9", "port": "5060", "proto": "udp", "service": "sip"},
            ]}))
            fin = R.finalize_findings(
                out, [_disp("SIP service: 192.0.2.9:5060 — Asterisk", "sip")])
            self.assertEqual(len(fin), 1)
            self.assertEqual(fin[0]["host"], "192.0.2.9")
            self.assertEqual(fin[0]["port"], "5060",
                             "a protocol-only ambiguity must not erase the known port")
            self.assertEqual(fin[0]["protocol"], "",
                             "the ambiguous protocol is left blank, never guessed")


class TestHostDisambiguation(unittest.TestCase):
    def test_one_is_not_a_substring_of_ten(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _seed_targets(out, "http", ["10.0.0.1:80", "10.0.0.10:80"])
            fin = R.finalize_findings(
                out, [_disp("UNAUTH endpoint at 10.0.0.10:80 reachable", "http")])
            self.assertEqual(fin[0]["host"], "10.0.0.10",
                             "10.0.0.1 must not steal the match for 10.0.0.10")
            self.assertEqual(fin[0]["port"], "80")

    def test_multi_host_line_stays_run_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _seed_targets(out, "http", ["10.0.0.30:443", "10.0.0.20:8080"])
            fin = R.finalize_findings(
                out, [_disp("lateral path 10.0.0.30 -> 10.0.0.20 observed", "http")])
            self.assertEqual(fin[0]["host"], "(dispatcher)",
                             "two distinct known hosts -> unattributable")
            self.assertEqual(fin[0]["scope"], "run")
            self.assertEqual(fin[0]["attribution"], "run")


class TestPortlessFold(unittest.TestCase):
    def test_portless_record_folded_when_ported_sibling_exists(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _seed_targets(out, "http", ["10.0.0.9:80"])
            # A host dir with no port suffix would otherwise add a port-less record.
            (out / "http" / "10.0.0.9").mkdir(parents=True)
            (out / "http" / "10.0.0.9" / "probe.txt").write_text("noop\n")
            recs = R._inventory_endpoints(out)
            http = [r for r in recs if r["service"] == "http" and r["host"] == "10.0.0.9"]
            self.assertEqual(len(http), 1, f"port-less record not folded: {http}")
            self.assertEqual(http[0]["port"], "80")

    def test_portless_record_kept_when_no_ported_sibling(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "http" / "db1").mkdir(parents=True)
            (out / "http" / "db1" / "probe.txt").write_text("noop\n")
            recs = R._inventory_endpoints(out)
            http = [r for r in recs if r["service"] == "http" and r["host"] == "db1"]
            self.assertEqual(len(http), 1)
            self.assertEqual(http[0]["port"], "", "lone host record must survive")


class TestExampleFixtureAttribution(unittest.TestCase):
    """Acceptance (PLAN-001 S1): the shipped fixture attributes with zero
    (dispatcher) noise, iLO -> 10.0.0.30:443, SMB -> 10.0.0.5:445."""

    def test_fixture_has_zero_dispatcher_findings(self):
        self.assertTrue(EXAMPLE_FIXTURE.is_dir(), "example fixture must exist")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "run"
            shutil.copytree(EXAMPLE_FIXTURE, out)
            rules = R._load_rules(None)
            fin = R.finalize_findings(out, list(R.walk_findings(out, rules)))
            self.assertGreater(len(fin), 0)
            run_scoped = [f for f in fin if f.get("scope") == "run"]
            self.assertEqual(run_scoped, [], "no finding should be run-scoped on this fixture")
            self.assertFalse([f for f in fin if f["host"] == "(dispatcher)"],
                             "zero (dispatcher) findings")
            ilo = [f for f in fin if "iLO" in f["line"]]
            self.assertTrue(ilo and all(f["host"] == "10.0.0.30" and f["port"] == "443" for f in ilo),
                            "iLO must attribute to 10.0.0.30:443")
            smb = [f for f in fin if f["service"] == "smb" and "10.0.0.5" in f["line"]]
            self.assertTrue(smb and all(f["host"] == "10.0.0.5" and f["port"] == "445" for f in smb),
                            "SMB 10.0.0.5 evidence must attribute to :445")


if __name__ == "__main__":
    unittest.main()
