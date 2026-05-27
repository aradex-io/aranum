#!/usr/bin/env python3
"""test_queue.py — tests for queue slicing and task filtering in plan.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLANER = REPO / "aranumtoolkit" / "network" / "plan.py"
FIXTURE = REPO / "aranumtoolkit" / "tests" / "fixtures" / "services" / "all-services.xml"


def _run_plan(*, output: Path, extra_args: list[str] | None = None) -> tuple[int, Path]:
    args = [sys.executable, str(PLANER), str(FIXTURE), "--output", str(output)]
    if extra_args:
        args.extend(extra_args)
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return result.returncode, output, result.stdout + result.stderr


def _queue_ids(path: Path) -> list[str]:
    ids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        ids.append(payload["task_id"])
    return ids


class TestQueueSharding(unittest.TestCase):
    """Sharding must split queue IDs without overlap or loss."""

    def test_shards_cover_complete_queue(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            full_dir = root / "all"
            full_dir.mkdir()
            rc, _, details = _run_plan(output=full_dir)
            self.assertEqual(rc, 0, details)
            full_ids = _queue_ids(full_dir / "queue.jsonl")
            self.assertGreater(len(full_ids), 5, "fixture should produce many queue tasks")

            shard1_dir = root / "shard1"
            shard1_dir.mkdir()
            rc, _, details = _run_plan(output=shard1_dir, extra_args=["--shard", "1/2"])
            self.assertEqual(rc, 0, details)
            shard1_ids = _queue_ids(shard1_dir / "queue.jsonl")

            shard2_dir = root / "shard2"
            shard2_dir.mkdir()
            rc, _, details = _run_plan(output=shard2_dir, extra_args=["--shard", "2/2"])
            self.assertEqual(rc, 0, details)
            shard2_ids = _queue_ids(shard2_dir / "queue.jsonl")

            self.assertEqual(len(shard1_ids) + len(shard2_ids), len(full_ids))
            self.assertEqual(set(shard1_ids) & set(shard2_ids), set())
            self.assertEqual(set(full_ids), set(shard1_ids) | set(shard2_ids))

    def test_invalid_shard_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            rc, _, details = _run_plan(output=out_dir, extra_args=["--shard", "0/2"])
            self.assertNotEqual(rc, 0, details)


if __name__ == "__main__":
    unittest.main()
