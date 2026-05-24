#!/usr/bin/env python3
"""test_unified_cli.py — unit tests for network/aranum.py CLI delegation."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
ARANUM = REPO / "network" / "aranum.py"


spec = importlib.util.spec_from_file_location("aranum_mod", ARANUM)
ARANUM_MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ARANUM_MOD)


class TestRootCLI(unittest.TestCase):
    def test_root_help_includes_all_subcommands(self):
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            rc = ARANUM_MOD.main(["--help"])
        self.assertEqual(rc, 0)
        help_text = out.getvalue()
        for cmd in ["plan", "run", "report", "dashboard", "merge", "queue", "bulk-linux", "bulk-windows"]:
            self.assertIn(cmd, help_text)

    def test_unknown_command_returns_error(self):
        self.assertEqual(ARANUM_MOD.main(["bogus"]), 2)


class TestSubcommandDelegation(unittest.TestCase):
    def test_plan_delegates_to_plan_script(self):
        with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call:
            run_call.return_value = mock.Mock(returncode=0)
            ARANUM_MOD.main(["plan", "-i", "scan.xml", "-o", "/tmp/out"])
        called = run_call.call_args.args[0]
        self.assertIn("-i", called)
        self.assertIn("scan.xml", called)
        self.assertEqual(called[1].endswith("plan.py"), True)

    def test_run_delegates_to_auto_enum(self):
        with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call:
            run_call.return_value = mock.Mock(returncode=0)
            ARANUM_MOD.main(["run", "-i", "scan.xml"])
        called = run_call.call_args.args[0]
        self.assertEqual(called[1].endswith("auto-enum.sh"), True)

    def test_other_command_runners(self):
        checks = [
            ("report", "report.py", sys.executable),
            ("dashboard", "report-dashboard.py", sys.executable),
            ("merge", "merge-results.py", sys.executable),
            ("bulk-linux", "bulk-enum-linux.sh", "bash"),
            ("bulk-windows", "bulk-enum-windows.py", sys.executable),
        ]
        for cmd, script, runner in checks:
            with self.subTest(cmd=cmd):
                with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call:
                    run_call.return_value = mock.Mock(returncode=0)
                    ARANUM_MOD.main([cmd])
                called = run_call.call_args.args[0]
                self.assertEqual(called[0], runner)
                self.assertEqual(called[1].endswith(script), True)


class TestQueueBuiltin(unittest.TestCase):
    def test_queue_lists_planner_items(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "queue.jsonl").write_text(json.dumps({
                "priority": 900,
                "status": "pending",
                "phase": "1",
                "service": "smb",
                "target_label": "10.0.0.5:445",
                "task_id": "smb::10.0.0.5:445:1",
            }) + "\n")
            with mock.patch("sys.stdout", new=io.StringIO()) as out:
                rc = ARANUM_MOD.main(["queue", str(root), "--list"])
            self.assertEqual(rc, 0)
            text = out.getvalue()
            self.assertIn("smb", text)
            self.assertIn("10.0.0.5:445", text)


if __name__ == "__main__":
    unittest.main()
