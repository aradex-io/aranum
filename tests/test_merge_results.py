#!/usr/bin/env python3
"""test_merge_results.py — unit tests for network/merge-results.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MERGE = REPO / "network" / "merge-results.py"

spec = importlib.util.spec_from_file_location("merge_mod", MERGE)
MERGE_MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MERGE_MOD)


def _write_run(out_dir: Path, findings: list[dict], evidence: dict[str, str]) -> None:
    for rel, contents in evidence.items():
        fp = out_dir / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(contents, encoding="utf-8")

    payload = {
        "label": out_dir.name,
        "generated_utc": "2026-01-01T00:00:00Z",
        "mode": "auto-enum",
        "redacted": False,
        "summary": {"hosts": ["x"], "services": [], "counts": {}, "by_service": {}},
        "findings": findings,
    }
    (out_dir / "findings.json").write_text(json.dumps(payload), encoding="utf-8")


class TestMergeResults(unittest.TestCase):
    def test_merge_dedup_and_evidence_rewrite(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src1 = base / "run1"
            src2 = base / "run2"
            src1.mkdir()
            src2.mkdir()

            _write_run(
                src1,
                [
                    {
                        "host": "10.0.0.10",
                        "port": "80",
                        "service": "http",
                        "severity": "high",
                        "line": "HTTP banner: OK",
                        "evidence_path": "http/host-80/info.txt",
                    },
                    {
                        "host": "10.0.0.20",
                        "port": "",
                        "service": "linenum",
                        "severity": "low",
                        "line": "linux: baseline",
                        "evidence_path": "linenum/host.txt",
                    },
                ],
                {
                    "http/host-80/info.txt": "alpha-data",
                    "linenum/host.txt": "line-data-1",
                },
            )
            _write_run(
                src2,
                [
                    {
                        # same tuple as source1[0] => should dedupe out
                        "host": "10.0.0.10",
                        "port": "80",
                        "service": "http",
                        "severity": "high",
                        "line": "HTTP banner: OK",
                        "evidence_path": "http/host-80/also-info.txt",
                    },
                    {
                        # same evidence content as source1[0] => evidence paths dedup
                        "host": "10.0.0.30",
                        "port": "22",
                        "service": "ssh",
                        "severity": "medium",
                        "line": "SSH banner: ok",
                        "evidence_path": "ssh/host-22/alt.txt",
                    },
                ],
                {
                    "http/host-80/also-info.txt": "alpha-data",
                    "ssh/host-22/alt.txt": "alpha-data",
                },
            )

            merged = base / "merged"
            argv = [
                str(MERGE),
                "-o", str(merged),
                str(src1),
                str(src2),
            ]
            old_argv = MERGE_MOD.sys.argv
            MERGE_MOD.sys.argv = argv
            try:
                rc = MERGE_MOD.main()
            finally:
                MERGE_MOD.sys.argv = old_argv

            self.assertEqual(rc, 0)
            payload = json.loads((merged / "findings.json").read_text(encoding="utf-8"))
            findings = payload["findings"]
            self.assertEqual(len(findings), 3, f"unexpected finding count: {findings}")

            # evidence paths should be rewritten to merged/evidence/* and deduplicated
            paths = [f["evidence_path"] for f in findings]
            for p in paths:
                self.assertTrue(p.startswith("evidence/"), f"not rewritten: {p}")
            self.assertIn("evidence/src00-run1/http/host-80/info.txt", paths)

            # dedupe by file hash: two outputs with same file content should share path
            p1 = next(f["evidence_path"] for f in findings if f["host"] == "10.0.0.10")
            p2 = next(f["evidence_path"] for f in findings if f["host"] == "10.0.0.30")
            self.assertEqual(p1, p2)

            # summary counts match merged findings
            counts = payload["summary"]["counts"]
            self.assertEqual(counts["high"], 1)
            self.assertEqual(counts["medium"], 1)
            self.assertEqual(counts["low"], 1)

            copied = list((merged / "evidence").rglob("*"))
            # only 2 unique evidence files should be copied (alpha-data reused)
            self.assertEqual(len([p for p in copied if p.is_file()]), 2)

    def test_merge_refuses_missing_findings_directory(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            good = base / "good"
            bad = base / "bad"
            good.mkdir()
            bad.mkdir()
            _write_run(good, [], {})
            (bad / "readme.txt").write_text("no findings", encoding="utf-8")

            merged = base / "out"
            argv = [str(MERGE), "-o", str(merged), str(good), str(bad)]
            old_argv = MERGE_MOD.sys.argv
            MERGE_MOD.sys.argv = argv
            try:
                rc = MERGE_MOD.main()
            finally:
                MERGE_MOD.sys.argv = old_argv
            self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
