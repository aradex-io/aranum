#!/usr/bin/env python3
"""test_planner.py — tests for network/plan.py planning output generation."""
from __future__ import annotations

import json
import glob
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
PLANER = REPO / "network" / "plan.py"
PARSER = REPO / "network" / "nmap-parse.py"
METADATA = REPO / "network" / "service-metadata.json"
FIXTURE = REPO / "tests" / "fixtures" / "services" / "all-services.xml"


def _load_parser():
    spec = importlib.util.spec_from_file_location("nmap_parse", PARSER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_plan(*, output: Path, input_file: Path = FIXTURE, extra_args: list[str] | None = None) -> tuple[int, str, str]:
    cmd = [sys.executable, str(PLANER), str(input_file), "--output", str(output)]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


class TestPlanWriter(unittest.TestCase):
    """Planner CLI should emit all three expected files and include executable tasks."""

    def test_default_profile_writes_plan_queue_and_guidance(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            rc, out, err = _run_plan(output=out_dir)
            self.assertEqual(rc, 0, f"planner failed: out={out} err={err}")

            plan_path = out_dir / "plan.json"
            queue_path = out_dir / "queue.jsonl"
            guidance_path = out_dir / "guidance.json"
            self.assertTrue(plan_path.is_file())
            self.assertTrue(queue_path.is_file())
            self.assertTrue(guidance_path.is_file())

            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            guidance = json.loads(guidance_path.read_text(encoding="utf-8"))
            queue_lines = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]

            self.assertIn("tasks", plan)
            self.assertIn("summary", plan)
            self.assertGreater(len(plan["tasks"]), 0, "plan should include at least one task")
            self.assertEqual(len(plan["tasks"]), len(queue_lines))
            self.assertEqual(guidance["counts"]["queue_tasks"], len(plan["tasks"]))
            first = plan["tasks"][0]
            for key in ("schema_version", "priority", "risk", "cost", "requires_opt_in",
                        "requires_auth", "target_label", "output_hint", "status", "reason"):
                self.assertIn(key, first)

    def test_phase_filter_cli_restricts_tasks(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            rc, out, err = _run_plan(output=out_dir, extra_args=["--phase", "2"])
            self.assertEqual(rc, 0, f"planner failed: out={out} err={err}")
            plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))

            self.assertGreater(len(plan["tasks"]), 0)
            self.assertTrue(all(task["phase"] == "2" for task in plan["tasks"]))


class TestMetadataCoverage(unittest.TestCase):
    def test_every_service_map_category_has_metadata(self):
        parser = _load_parser()
        metadata = json.loads(METADATA.read_text(encoding="utf-8"))
        services = set(metadata["services"])
        missing = set(parser.SERVICE_MAP) - services
        self.assertFalse(missing, f"service-metadata.json missing SERVICE_MAP categories: {sorted(missing)}")

    def test_every_dispatcher_has_metadata(self):
        metadata = json.loads(METADATA.read_text(encoding="utf-8"))
        services = set(metadata["services"])
        dispatchers = {
            Path(path).stem.removeprefix("enum-")
            for path in glob.glob(str(REPO / "network" / "enum-*.sh"))
        }
        missing = dispatchers - services
        self.assertFalse(missing, f"service-metadata.json missing dispatcher entries: {sorted(missing)}")


if __name__ == "__main__":
    unittest.main()
