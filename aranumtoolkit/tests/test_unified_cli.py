#!/usr/bin/env python3
"""test_unified_cli.py — unit tests for top-level aranum.py CLI delegation."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
ARANUM = REPO / "aranum.py"


spec = importlib.util.spec_from_file_location("aranum_mod", ARANUM)
ARANUM_MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ARANUM_MOD)


class TestRootCLI(unittest.TestCase):
    def test_root_help_includes_all_subcommands(self):
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            rc = ARANUM_MOD.main(["--help"])
        self.assertEqual(rc, 0)
        help_text = out.getvalue()
        for cmd in ["plan", "run", "report", "dashboard", "merge", "queue", "iter", "bulk-linux", "bulk-windows"]:
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
            ("merge", "merge-results.py", sys.executable),
            ("iter", "iterative-enum.sh", "bash"),
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

    def test_dashboard_defaults_to_sibling_output(self):
        with tempfile.TemporaryDirectory() as td:
            outdir = Path(td) / "enum-results"
            outdir.mkdir()
            (outdir / "inventory.json").write_text("{}")
            with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call, \
                 mock.patch.object(ARANUM_MOD, "_first_free_port", return_value=8765):
                run_call.return_value = mock.Mock(returncode=0)
                rc = ARANUM_MOD.main(["dashboard", str(outdir)])
        self.assertEqual(rc, 0)
        self.assertEqual(run_call.call_count, 2)
        called = run_call.call_args_list[0].args[0]
        self.assertEqual(called[0], sys.executable)
        self.assertEqual(called[1].endswith("report-dashboard.py"), True)
        self.assertIn(str(outdir), called)
        self.assertIn("--output", called)
        self.assertIn(str(outdir.parent / "enum-results-dashboard"), called)
        server = run_call.call_args_list[1]
        self.assertEqual(server.args[0][:3], [sys.executable, "-m", "http.server"])
        self.assertEqual(server.kwargs["cwd"], str(outdir.parent / "enum-results-dashboard"))

    def test_run_report_flag_chains_report_and_dashboard(self):
        # -report chains report + dashboard but is NON-BLOCKING: it generates the
        # dashboard (--no-serve) and does not start http.server, so a scheduled/CI
        # wrapper doesn't hang. See test_run_serve_flag_also_serves for the opt-in.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan01.xml"
            scan.write_text("<nmaprun/>")
            (root / "scan01").mkdir()
            with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call, \
                 mock.patch.object(ARANUM_MOD, "_first_free_port", return_value=8765):
                run_call.return_value = mock.Mock(returncode=0)
                old_cwd = Path.cwd()
                os.chdir(root)
                try:
                    rc = ARANUM_MOD.main(["run", "scan01", "-report", "--session-name", "scan01"])
                finally:
                    os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        calls = [c.args[0] for c in run_call.call_args_list]
        self.assertEqual(len(calls), 3)  # auto-enum, report.py, report-dashboard.py — NO http.server
        self.assertEqual(calls[0][1].endswith("auto-enum.sh"), True)
        self.assertIn("-i", calls[0])
        self.assertIn("scan01.xml", calls[0])
        self.assertIn("-o", calls[0])
        self.assertIn(str(REPO / "outputs" / "scan01" / "raw"), calls[0])
        self.assertEqual(calls[1][1].endswith("report.py"), True)
        self.assertIn("--label", calls[1])
        self.assertIn("scan01", calls[1])
        self.assertEqual(calls[2][1].endswith("report-dashboard.py"), True)
        self.assertIn("--output", calls[2])
        self.assertIn(str(REPO / "outputs" / "scan01" / "reports" / "dashboard"), calls[2])
        # No 4th http.server call ⇒ non-blocking (the --no-serve is consumed by
        # _run_dashboard to skip the server, not forwarded to the generator).

    def test_run_serve_flag_also_serves(self):
        # -serve opts into the blocking report server on top of the report+dashboard chain.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan01.xml"
            scan.write_text("<nmaprun/>")
            (root / "scan01").mkdir()
            with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call, \
                 mock.patch.object(ARANUM_MOD, "_first_free_port", return_value=8765):
                run_call.return_value = mock.Mock(returncode=0)
                old_cwd = Path.cwd()
                os.chdir(root)
                try:
                    rc = ARANUM_MOD.main(["run", "scan01", "-serve", "--session-name", "scan01"])
                finally:
                    os.chdir(old_cwd)
        self.assertEqual(rc, 0)
        calls = [c.args[0] for c in run_call.call_args_list]
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[2][1].endswith("report-dashboard.py"), True)
        self.assertNotIn("--no-serve", calls[2])
        self.assertEqual(calls[3][:3], [sys.executable, "-m", "http.server"])

    def test_dashboard_no_serve_only_generates(self):
        with tempfile.TemporaryDirectory() as td:
            outdir = Path(td) / "enum-results"
            outdir.mkdir()
            (outdir / "inventory.json").write_text("{}")
            with mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call:
                run_call.return_value = mock.Mock(returncode=0)
                rc = ARANUM_MOD.main(["dashboard", str(outdir), "--no-serve"])
        self.assertEqual(rc, 0)
        self.assertEqual(run_call.call_count, 1)

    def test_dashboard_session_name_uses_session_raw(self):
        with tempfile.TemporaryDirectory() as td:
            outputs = Path(td) / "outputs"
            raw = outputs / "acme" / "raw"
            raw.mkdir(parents=True)
            (raw / "inventory.json").write_text("{}")
            with mock.patch.object(ARANUM_MOD, "OUTPUTS_DIR", outputs), \
                 mock.patch.object(ARANUM_MOD.subprocess, "run") as run_call:
                run_call.return_value = mock.Mock(returncode=0)
                rc = ARANUM_MOD.main(["dashboard", "--session-name", "acme", "--no-serve"])
        self.assertEqual(rc, 0)
        self.assertEqual(run_call.call_count, 1)
        called = run_call.call_args.args[0]
        self.assertIn(str(raw), called)
        self.assertIn(str(outputs / "acme" / "reports" / "dashboard"), called)


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
