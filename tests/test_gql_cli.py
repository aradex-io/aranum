#!/usr/bin/env python3
"""test_gql_cli.py — CLI subcommand smoke tests for graphql/gql.py.

test_gql_internals.py covers pure helpers (cache_key, type_str, etc). This
file covers the CLI shape — does `gql.py --help`, `gql.py <sub> --help`,
and the no-side-effect dry/refused paths actually run without crashing?

These are the surfaces operators hit first; a regression here breaks every
engagement. Tests are network-isolated — every `--url` points at port 1
which is guaranteed closed, so the subcommand prints an error and exits
without touching anything.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GQL = REPO / "graphql" / "gql.py"


def _run(args, timeout=10):
    return subprocess.run(
        [sys.executable, str(GQL), *args],
        capture_output=True, text=True, timeout=timeout,
    )


class TestHelp(unittest.TestCase):
    """Every advertised subcommand must respond to --help with rc=0."""

    SUBCOMMANDS = [
        "introspect", "ls", "describe", "call", "loop", "diff",
        "raw", "suggest", "apq-probe", "csrf-probe",
    ]

    def test_root_help(self):
        r = _run(["--help"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("introspect", r.stdout)
        self.assertIn("suggest", r.stdout)
        self.assertIn("apq-probe", r.stdout)

    def test_each_subcommand_help(self):
        for sub in self.SUBCOMMANDS:
            with self.subTest(subcommand=sub):
                # `--url` is a required parent option in some argparse setups;
                # provide a dummy so the parser reaches the subcommand level.
                r = _run(["--url", "http://127.0.0.1:1/graphql", sub, "--help"])
                self.assertEqual(r.returncode, 0,
                                 f"{sub} --help failed: {r.stderr}")
                self.assertIn("usage:", r.stdout)


class TestUnreachableTarget(unittest.TestCase):
    """Subcommands that initiate network IO must degrade cleanly when the
    target is unreachable — informative output, no Python traceback leaked
    to stderr. Port 1 is the closed-port sentinel."""

    def _assert_no_traceback(self, args, must_contain_marker=None):
        r = _run(args)
        # No raw Python traceback should reach the operator (the dispatchers
        # are meant to wrap network errors and produce structured output).
        self.assertNotIn("Traceback (most recent call last)", r.stderr,
                         f"traceback leaked to stderr: {r.stderr}")
        if must_contain_marker:
            haystack = r.stdout + r.stderr
            self.assertIn(must_contain_marker, haystack,
                          f"missing marker {must_contain_marker!r}: "
                          f"stdout={r.stdout!r} stderr={r.stderr!r}")

    def test_suggest_empty_corpus_clean_exit(self):
        # Empty corpus + unreachable target: must print "harvested" marker.
        self._assert_no_traceback(
            ["--url", "http://127.0.0.1:1/graphql",
             "suggest", "--corpus", "/dev/null"],
            must_contain_marker="harvested",
        )

    def test_apq_probe_unreachable(self):
        # apq-probe degrades to "server does not implement APQ" on unreachable;
        # what we care about is "no traceback" + "marker present".
        self._assert_no_traceback(
            ["--url", "http://127.0.0.1:1/graphql", "apq-probe"],
            must_contain_marker="APQ",
        )

    def test_csrf_probe_unreachable(self):
        # csrf-probe degrades to "indeterminate" on unreachable.
        self._assert_no_traceback(
            ["--url", "http://127.0.0.1:1/graphql", "csrf-probe"],
            must_contain_marker="CSRF",
        )


if __name__ == "__main__":
    unittest.main()
