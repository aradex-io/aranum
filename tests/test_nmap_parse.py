#!/usr/bin/env python3
"""test_nmap_parse.py — G.2 unit tests for network/nmap-parse.py.

Run with: python3 -m unittest tests.test_nmap_parse
or:       python3 tests/test_nmap_parse.py

Imports nmap-parse.py via importlib (the dash in the filename blocks
`import nmap-parse`). Tests exercise routing, IPv6, closed-port filtering,
XXE rejection, and CLI surface — anything a future refactor could regress.

Fixtures live in tests/fixtures/services/ and tests/fixtures/*.xml
(the malicious fixtures share the legacy location used by smoke.sh).
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PARSER_PATH = REPO / "network" / "nmap-parse.py"
FIXTURES = REPO / "tests" / "fixtures" / "services"
MALICIOUS_DIR = REPO / "tests" / "fixtures"


def _load_module():
    spec = importlib.util.spec_from_file_location("nmap_parse", PARSER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


def _run_cli(*args: str) -> tuple[int, str, str]:
    """Invoke nmap-parse.py as a subprocess and return (rc, stdout, stderr)."""
    p = subprocess.run(
        [sys.executable, str(PARSER_PATH), *args],
        capture_output=True, text=True, timeout=15,
    )
    return p.returncode, p.stdout, p.stderr


# --------------------------------------------------------------------- SERVICE_MAP
class TestServiceMap(unittest.TestCase):
    """SERVICE_MAP is the routing table — completeness regressions silently
    break a dispatcher's reachability."""

    REQUIRED_CATEGORIES = {
        # Windows / AD surface
        "smb", "ldap", "kerberos", "winrm", "rdp", "mssql",
        # web + DB
        "http", "https", "mysql", "postgres", "redis", "mongo", "elastic",
        # Infra
        "ssh", "ftp", "smtp", "snmp", "dns", "nfs", "ipmi",
        # Iteration B/C P0/P1
        "docker", "kubernetes", "rabbitmq", "memcached", "couchdb", "etcd",
        "vnc", "jmx", "activemq",
        # Iteration H jabber
        "xmpp", "openfire-admin",
        # Iteration E2 — Tier 2a high-yield services
        "cassandra", "consul", "influxdb", "ipp", "kafka",
        "msrpc", "netbios-ns", "neo4j", "solr", "vault", "zookeeper",
    }

    def test_every_required_category_present(self):
        missing = self.REQUIRED_CATEGORIES - set(M.SERVICE_MAP.keys())
        self.assertFalse(missing, f"SERVICE_MAP is missing required categories: {missing}")

    def test_port_set_disjoint_for_never_match_regex_categories(self):
        # Categories that route by port-set only (regex = `a^`) must have a
        # non-empty port set, else they can never fire.
        for cat, (ports, regex) in M.SERVICE_MAP.items():
            if regex == r"a^":
                self.assertTrue(ports, f"{cat} uses never-match regex but its port set is empty")


# --------------------------------------------------------------------- categorize()
class TestCategorize(unittest.TestCase):
    def test_smb_routes_by_port(self):
        self.assertIn("smb", M.categorize(445, "microsoft-ds"))
        self.assertIn("smb", M.categorize(139, "netbios-ssn"))

    def test_http_routes_by_port_or_name(self):
        self.assertIn("http",  M.categorize(80,   "http"))
        self.assertIn("https", M.categorize(443,  "https"))
        # non-standard port but http-named service still routes
        self.assertIn("http",  M.categorize(8888, "http"))

    def test_openfire_admin_port_only_never_steals_other_http(self):
        # 9090 routes to BOTH openfire-admin (port-set) AND http (port 9090
        # is also in http's port set). This dual-routing is intentional —
        # auto-enum runs both dispatchers, openfire-admin handles version +
        # CVE-2023-32315, http handles generic web probes.
        cats_9090 = M.categorize(9090, "http")
        self.assertIn("openfire-admin", cats_9090)
        self.assertIn("http",           cats_9090)
        # But a plain 8080 must NOT pick up openfire-admin
        self.assertNotIn("openfire-admin", M.categorize(8080, "http"))

    def test_unknown_port_returns_empty(self):
        self.assertEqual([], M.categorize(48312, "unknown"))
        self.assertEqual([], M.categorize(48312, ""))


# --------------------------------------------------------------------- XML routing end-to-end
class TestRoutingFromFixture(unittest.TestCase):
    """Exercise the full XML → category-list path. dispatch() returns raw
    entries without a `categories` field — main() decorates them post-dispatch
    by calling categorize(port, service). Tests mirror that pattern."""

    def setUp(self):
        raw = list(M.dispatch(FIXTURES / "all-services.xml"))
        for e in raw:
            e["categories"] = M.categorize(e["port"], e["service"])
        self.entries = raw

    def test_every_host_gets_at_least_one_category(self):
        # Unknown bucket lives in main()'s --unknown branch; here every entry
        # in this fixture is intentionally a known-service port.
        for e in self.entries:
            self.assertTrue(e["categories"],
                            f"{e['ip']}:{e['port']} ({e['service']}) got no categories: {e}")

    def test_smb_host_routes_correctly(self):
        smb_hosts = {e["ip"] for e in self.entries if "smb" in e["categories"]}
        self.assertIn("10.0.0.1", smb_hosts)

    def test_database_host_routes_to_three_categories(self):
        db_host_cats = {(e["port"], tuple(e["categories"])) for e in self.entries if e["ip"] == "10.0.0.4"}
        ports_seen = {p for p, _ in db_host_cats}
        self.assertEqual(ports_seen, {1433, 3306, 5432})

    def test_container_orchestration_routes(self):
        host11_cats = [c for e in self.entries if e["ip"] == "10.0.0.11" for c in e["categories"]]
        self.assertIn("docker",     host11_cats)
        self.assertIn("kubernetes", host11_cats)


# --------------------------------------------------------------------- IPv6
class TestIPv6(unittest.TestCase):
    def test_ipv6_targets_are_bracketed_on_stdout(self):
        rc, out, err = _run_cli(str(FIXTURES / "ipv6-host.xml"), "--service", "ssh")
        self.assertEqual(rc, 0, f"stderr: {err}")
        self.assertEqual(out.strip(), "[2001:db8::1]:22",
                         "IPv6 target must be bracketed for dispatcher consumption")

    def test_ipv6_targets_in_json_use_raw_ip(self):
        rc, out, err = _run_cli(str(FIXTURES / "ipv6-host.xml"), "--json")
        self.assertEqual(rc, 0, f"stderr: {err}")
        d = json.loads(out)
        ips = {e["ip"] for e in d["entries"]}
        # JSON ip field carries the raw v6 (consistent with v4 — no brackets in JSON)
        self.assertEqual(ips, {"2001:db8::1"})


# --------------------------------------------------------------------- Port-state filtering
class TestPortStateFiltering(unittest.TestCase):
    def test_closed_and_filtered_ports_excluded(self):
        entries = list(M.dispatch(FIXTURES / "closed-and-filtered.xml"))
        # Fixture has one open + one filtered + one closed; only open survives
        self.assertEqual(len(entries), 1, f"expected 1 open entry, got {entries}")
        self.assertEqual(entries[0]["port"], 22)
        self.assertEqual(entries[0]["state"], "open")


# --------------------------------------------------------------------- XXE / billion-laughs
class TestXMLHardening(unittest.TestCase):
    """A.2 hardening must reject malicious XML even on hosts without
    defusedxml installed (the stdlib fallback pre-scans the prolog)."""

    def test_xxe_external_entity_rejected(self):
        rc, _, _ = _run_cli(str(MALICIOUS_DIR / "malicious_xxe.xml"), "--json")
        self.assertNotEqual(rc, 0, "XXE fixture was accepted — A.2 hardening regressed")

    def test_billion_laughs_rejected(self):
        rc, _, _ = _run_cli(str(MALICIOUS_DIR / "billion_laughs.xml"), "--json")
        self.assertNotEqual(rc, 0, "billion-laughs fixture was accepted — A.2 hardening regressed")


# --------------------------------------------------------------------- CLI surface
class TestCLI(unittest.TestCase):
    def test_list_categories_emits_every_service_map_key(self):
        rc, out, err = _run_cli(str(FIXTURES / "all-services.xml"), "--list-categories")
        self.assertEqual(rc, 0, f"stderr: {err}")
        listed = set(out.split())
        # Every SERVICE_MAP key must appear in --list-categories output
        missing = set(M.SERVICE_MAP.keys()) - listed
        self.assertFalse(missing, f"--list-categories omitted: {missing}")

    def test_unknown_bucket_collects_uncategorized_ports(self):
        rc, out, err = _run_cli(str(FIXTURES / "unknown-service.xml"), "--unknown")
        self.assertEqual(rc, 0, f"stderr: {err}")
        lines = [l for l in out.splitlines() if l.strip()]
        self.assertEqual(set(lines), {"10.0.0.40:48312", "10.0.0.40:51234"})

    def test_json_summary_matches_dispatch_count(self):
        rc, out, err = _run_cli(str(FIXTURES / "all-services.xml"), "--json")
        self.assertEqual(rc, 0, f"stderr: {err}")
        d = json.loads(out)
        # all-services.xml has 13 hosts and 32 open ports across them
        self.assertEqual(d["summary"]["hosts"], 13)
        self.assertEqual(d["summary"]["open_ports"], len(d["entries"]))


# --------------------------------------------------------------------- Cross-format parity
class TestParserParity(unittest.TestCase):
    """The XML, gnmap, and nmap-text parsers must agree on the test.* fixtures
    that come from a real-ish scan (committed in network/)."""

    def test_xml_vs_gnmap_host_count(self):
        if not (REPO / "network" / "test.gnmap").exists():
            self.skipTest("network/test.gnmap missing")
        xml_hosts  = {e["ip"] for e in M.dispatch(REPO / "network" / "test.xml")}
        gnmap_hosts = {e["ip"] for e in M.dispatch(REPO / "network" / "test.gnmap")}
        self.assertEqual(xml_hosts, gnmap_hosts,
                         "XML and gnmap parsers disagree on host set")


if __name__ == "__main__":
    unittest.main()
