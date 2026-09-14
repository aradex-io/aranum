#!/usr/bin/env python3
"""R1 executable dependency/lint/CI gate regressions."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


class TestQualityGateR1(unittest.TestCase):
    @staticmethod
    def _shim(path: Path, body: str = "exit 0\n") -> None:
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def test_dependency_check_rejects_broken_required_shim(self):
        with tempfile.TemporaryDirectory() as td:
            shim = Path(td) / "nmap"
            shim.write_text("#!/usr/bin/env bash\nexit 127\n")
            shim.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = td + os.pathsep + env["PATH"]
            proc = subprocess.run(["bash", str(REPO / "deps-check.sh")], env=env,
                                  capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("nmap", proc.stdout)
        self.assertIn("dependency preflight failed", proc.stdout)

    def test_dependency_alias_probe_and_optional_miss_do_not_false_fail(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td)
            required = ("python3", "nmap", "curl", "ldapsearch", "smbclient",
                        "rpcclient", "showmount", "rsync")
            for name in required:
                self._shim(bindir / name)
            probe_log = bindir / "dig.args"
            self._shim(bindir / "dig", f'printf "%s\\n" "$*" > "{probe_log}"\nexit 0\n')
            # A present but unusable optional shim must remain informational.
            self._shim(bindir / "nuclei", "exit 127\n")
            env = dict(os.environ)
            env["PATH"] = td + os.pathsep + env["PATH"]
            proc = subprocess.run(["bash", str(REPO / "deps-check.sh")], env=env,
                                  capture_output=True, text=True, timeout=30)
            dig_args = probe_log.read_text().strip()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(dig_args, "-v")
        self.assertIn("nuclei", proc.stdout)
        self.assertIn("dependency preflight passed", proc.stdout)

    def test_lint_falls_back_when_shellcheck_shim_is_broken(self):
        with tempfile.TemporaryDirectory() as td:
            shim = Path(td) / "shellcheck"
            shim.write_text("#!/usr/bin/env bash\nexit 127\n")
            shim.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = td + os.pathsep + env["PATH"]
            proc = subprocess.run(["make", "lint"], cwd=REPO, env=env,
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Falling back to 'bash -n'", proc.stdout)

    def test_ci_and_local_gate_inventory_match(self):
        makefile = (REPO / "Makefile").read_text()
        workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("test: lint unittest pytest smoke data-audit", makefile)
        for target in ("lint", "unittest", "pytest", "smoke", "data-audit"):
            self.assertIn(f"make {target}", workflow)


if __name__ == "__main__":
    unittest.main()
