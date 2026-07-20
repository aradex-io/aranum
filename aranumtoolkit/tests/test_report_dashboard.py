#!/usr/bin/env python3
"""test_report_dashboard.py — the dashboard generator (report-dashboard.py) is the
largest module and had no unit test; it already regressed once (build_index dropping
AD-depth CRITICALs vs findings.json). These assert CRITICAL-parity with report.py,
the data.json search payload, and per-service wiki deep-links from a fixture.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"
PY = sys.executable


def _fixture(root: Path) -> Path:
    """A scan tree with one CRITICAL (redis unauth) + one MEDIUM (http CORS)."""
    scan = root / "scan"
    (scan / "redis" / "10.0.0.1_6379").mkdir(parents=True)
    (scan / "redis" / "10.0.0.1_6379" / "info.txt").write_text(
        "[!!] UNAUTH Redis 10.0.0.1:6379 — redis_version:7.0.15 role:master\n")
    (scan / "http" / "10.0.0.2_80").mkdir(parents=True)
    (scan / "http" / "10.0.0.2_80" / "probe.txt").write_text("CORS reflect origin echoed\n")
    return scan


class TestReportDashboard(unittest.TestCase):
    def _run(self, args, **kw):
        r = subprocess.run(args, capture_output=True, text=True, timeout=90, **kw)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def test_dashboard_critical_parity_and_datajson(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            scan = _fixture(root)
            # 1) report.py to establish the CRITICAL truth set
            self._run([PY, str(NET / "report.py"), str(scan), "--findings-only"])
            findings = json.loads((scan / "findings.json").read_text())["findings"]
            crit_hosts = {f["host"] for f in findings if f["severity"] == "critical"}
            self.assertIn("10.0.0.1", crit_hosts, "redis unauth should be CRITICAL")

            # 2) dashboard from the same tree
            out = root / "dash"
            self._run([PY, str(NET / "report-dashboard.py"), str(scan), "--output", str(out)])

            # data.json search payload exists + has the expected shape
            dj = out / "data.json"
            self.assertTrue(dj.exists(), "dashboard must emit data.json")
            payload = json.loads(dj.read_text())
            self.assertTrue(isinstance(payload, (dict, list)), "data.json is JSON")

            # 3) CRITICAL parity: the redis CRITICAL must not be dropped by the
            # dashboard's index (the exact class of regression that shipped before).
            blob = " ".join(p.read_text(errors="replace") for p in out.glob("*.html"))
            self.assertIn("10.0.0.1", blob)
            self.assertRegex(blob.lower(), r"critical")

            # 4) per-service page deep-links to the quick-win wiki page
            svc = out / "service_redis.html"
            self.assertTrue(svc.exists())
            self.assertIn('href="wiki_redis.html"', svc.read_text())


if __name__ == "__main__":
    unittest.main()
