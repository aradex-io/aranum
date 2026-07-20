#!/usr/bin/env python3
"""test_structured_findings.py — structured finding fields in findings.json (v2).

The tests are intentionally narrow:
* walker output keeps legacy finding fields;
* default v2 fields are added when no metadata is present;
* optional `service-metadata.json` is loaded when present;
* CLI emits the same fields in findings.json and keeps `schema_version`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import shutil
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"
FIXTURES = REPO / "aranumtoolkit" / "tests" / "fixtures" / "ad-signals" / "certipy-esc1"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_structured", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def _write_ldap_fixture(root: Path) -> None:
    (root / "ldap" / "10.0.0.10_389").mkdir(parents=True)
    fixture = FIXTURES / "certipy_20260520.txt"
    shutil.copy(fixture, root / "ldap" / "10.0.0.10_389" / "certipy.txt")


class TestStructuredFindingDefaults(unittest.TestCase):
    def test_walk_findings_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _write_ldap_fixture(out)

            findings = list(R.walk_findings(out, list(R._AD_DEPTH_RULES)))
            self.assertGreater(len(findings), 0)
            f = findings[0]

            for key in ("host", "port", "service", "severity", "line", "evidence_path"):
                self.assertIn(key, f, f"legacy key missing: {key}")

            for key in ("finding_id", "title", "confidence", "priority", "tags", "next_actions", "triage_status"):
                self.assertIn(key, f, f"structured key missing: {key}")
            self.assertTrue(f["finding_id"].startswith("AR-2-"))
            self.assertIsInstance(f["tags"], list)
            self.assertIsInstance(f["next_actions"], list)
            self.assertEqual(f["triage_status"], "new")

            findings_again = list(R.walk_findings(out, list(R._AD_DEPTH_RULES)))
            self.assertEqual({x["finding_id"] for x in findings}, {x["finding_id"] for x in findings_again},
                             "finding_id should be stable for the same input set")

    def test_walk_findings_ignores_generated_dashboard_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "http" / "10.0.0.5_80").mkdir(parents=True)
            (out / "http" / "10.0.0.5_80" / "probe.txt").write_text(
                "UNAUTH: Docker daemon exposed\n"
            )
            (out / "dashboard" / "assets").mkdir(parents=True)
            (out / "dashboard" / "index.html").write_text(
                "UNAUTH: stale generated dashboard content\n"
            )
            (out / "dashboard" / "assets" / "dashboard.css").write_text("/* generated */")
            (out / "dashboard" / "assets" / "dashboard.js").write_text("// generated")

            findings = list(R.walk_findings(out, R._load_rules(None)))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["service"], "http")
            self.assertEqual(findings[0]["host"], "10.0.0.5")


class TestClassifyPrefilter(unittest.TestCase):
    """The perf prefilter must never change a classification vs the brute loop."""

    def _brute(self, line, rules):
        line = R._clean_line(line)[:4096]
        for pat, sev in rules:
            if pat.search(line):
                return sev
        return None

    def test_prefilter_matches_brute_force(self):
        rules = R._load_rules(None)
        samples = [
            "[!] CRITICAL: UNAUTH NATS monitoring http://x/varz",
            "UNAUTH etcd v2/keys", "OPEN PROXY: 1.2.3.4:3128 forwarded",
            "X11 OPEN DISPLAY: 1.2.3.4:6000", "polkit 0.105 < 0.120 — PwnKit candidate",
            "HARDENING: ptrace_scope=0 — unrestricted", "[+] WRITABLE PIPE: x",
            "EVAL scripting REACHABLE on h", "NTP AMPLIFICATION VECTOR (CVE-2013-5211 monlist): x",
            "some banner OpenSSH_9.6", "nothing interesting", "random 12345",
            "CVE-2024-6387 (regreSSHion) pre-auth RCE candidate",
        ]
        for s in samples:
            self.assertEqual(R._classify(s, rules), self._brute(s, rules), f"mismatch: {s!r}")


class TestWindowsBulkGrading(unittest.TestCase):
    """REVIEW-004 §5 — the winenum grader must actually classify AD-depth signals."""

    def test_writable_pipe_line_classifies(self):
        # Get-NamedPipes.ps1 emits via Hit() which prepends "[+] "; the old
        # "^WRITABLE PIPE:" rule never matched that prefix.
        rules = list(R._BULK_RULES_WIN) + list(R._AD_DEPTH_RULES)
        line = "[+] WRITABLE PIPE: \\\\.\\pipe\\spoolss — FullControl granted to Everyone"
        self.assertEqual(R._classify(line, rules), "high")

    def test_bulk_winenum_grades_writable_pipe(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            host = out / "WIN-DC01"
            host.mkdir()
            (host / "_meta.json").write_text(json.dumps({"rc": 0, "os": "windows"}))
            (host / "winenum.txt").write_text(
                "[+] WRITABLE PIPE: \\\\.\\pipe\\spoolss — FullControl granted to Everyone\n"
            )
            findings = list(R.walk_findings_bulk(out, []))
            self.assertIn("high", {f["severity"] for f in findings})


class TestServiceMetadataIntegration(unittest.TestCase):
    def test_service_metadata_file_is_loaded_when_present(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _write_ldap_fixture(out)
            local_metadata = {
                "services": {
                    "ldap": {
                        "title": "LDAP service hardening finding",
                        "confidence": "very-high",
                        "priority": "P0",
                        "tags": ["ad", "critical"],
                        "next_actions": ["triage", "remove risk"],
                        "triage_status": "open",
                    }
                }
            }
            metadata_path = out / "service-metadata.json"
            metadata_path.write_text(json.dumps(local_metadata))
            cfg = R._load_service_metadata(out)
            self.assertIn("services", cfg)

            metadata = {
                "defaults": cfg.get("defaults", {}),
                "services": {**cfg.get("services", {}), **local_metadata["services"]},
            }

            finding = next(R.walk_findings(out, list(R._AD_DEPTH_RULES), metadata))
            self.assertEqual(finding["title"], "LDAP service hardening finding")
            self.assertEqual(finding["confidence"], "very-high")
            self.assertEqual(finding["priority"], "P0")
            self.assertEqual(finding["triage_status"], "open")
            self.assertIn("ad", finding["tags"])
            self.assertIn("triage", finding["next_actions"])


class TestCLIV2Output(unittest.TestCase):
    def test_findings_json_v2_schema_payload(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _write_ldap_fixture(out)
            p = subprocess.run(
                [sys.executable, str(REPORT_PATH), str(out), "--findings-only"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(p.returncode, 0, f"report.py failed: {p.stderr}")
            payload = json.loads((out / "findings.json").read_text())

            self.assertEqual(payload["schema_version"], "2")
            self.assertIn("findings", payload)
            self.assertGreater(len(payload["findings"]), 0)
            f = payload["findings"][0]
            self.assertEqual(payload["label"], out.name)
            for key in ("finding_id", "title", "confidence", "priority", "tags", "next_actions", "triage_status", "schema_version"):
                self.assertIn(key, f)
            self.assertIn("line", f)
            self.assertIn("evidence_path", f)
            self.assertIn("host", f)


if __name__ == "__main__":
    unittest.main()
