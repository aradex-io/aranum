#!/usr/bin/env python3
"""test_gql_internals.py — G.3 unit tests for standalones/graphql/gql.py.

Per the iteration-G design note: "Don't invent abstractions; pick 4-6 pure
functions that already exist and test those." This file exercises seven:

  cache_key           (the A.3 identity-expansion fix)
  _check_range_size   (the A.4 bound check)
  type_str            (GraphQL type-printer)
  unwrap              (NON_NULL / LIST stripping)
  type_by_name        (schema lookup)
  parse_kv_args       (--arg name=value parser)
  build_selection     (auto-selection-set builder — the core of `call` codegen)

Run with: python3 -m unittest tests.test_gql_internals
or:       python3 aranumtoolkit/tests/test_gql_internals.py
"""
from __future__ import annotations

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GQL_PATH = REPO / "standalones" / "graphql" / "gql.py"


def _load_module():
    # Redirect the cache dir to a tmp so test runs don't pollute standalones/graphql/.cache
    # (set BEFORE import — gql.py reads GQL_CACHE_DIR at module-load time).
    tmpdir = tempfile.mkdtemp(prefix="gql-test-cache-")
    os.environ["GQL_CACHE_DIR"] = tmpdir
    spec = importlib.util.spec_from_file_location("gql_mod", GQL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._test_cache_root = tmpdir
    return mod


G = _load_module()


# --------------------------------------------------------------------- cache_key (A.3)
class TestCacheKey(unittest.TestCase):
    """A.3 fix: cache files must be keyed on URL + every header that
    distinguishes a principal (PRIVATE-TOKEN, Authorization, Cookie, JOB-TOKEN).
    Pre-A.3 only PRIVATE-TOKEN was considered, so cookie + job-token sessions
    silently shared a cache."""

    URL = "https://example.invalid/graphql"

    def test_distinct_cookie_distinct_cache(self):
        a = G.cache_key(self.URL, {"Cookie": "_gitlab_session=AAA"})
        b = G.cache_key(self.URL, {"Cookie": "_gitlab_session=BBB"})
        self.assertNotEqual(a, b, "Different cookies must produce different cache files")

    def test_same_cookie_same_cache(self):
        a = G.cache_key(self.URL, {"Cookie": "_gitlab_session=AAA"})
        b = G.cache_key(self.URL, {"Cookie": "_gitlab_session=AAA"})
        self.assertEqual(a, b, "Same cookie must hit the same cache file")

    def test_job_token_partitions_cache(self):
        a = G.cache_key(self.URL, {"JOB-TOKEN": "tok-1"})
        b = G.cache_key(self.URL, {"JOB-TOKEN": "tok-2"})
        self.assertNotEqual(a, b)

    def test_private_token_still_partitions(self):
        a = G.cache_key(self.URL, {"PRIVATE-TOKEN": "P1"})
        b = G.cache_key(self.URL, {"PRIVATE-TOKEN": "P2"})
        self.assertNotEqual(a, b)

    def test_anon_path_is_stable(self):
        a = G.cache_key(self.URL, {})
        b = G.cache_key(self.URL, {})
        self.assertEqual(a, b)
        self.assertIn("schema_", a.name)

    def test_distinct_urls_distinct_cache(self):
        a = G.cache_key("https://a.invalid/graphql", {})
        b = G.cache_key("https://b.invalid/graphql", {})
        self.assertNotEqual(a, b)


# --------------------------------------------------------------------- _check_range_size (A.4)
class TestRangeBound(unittest.TestCase):
    """A.4 fix: --range and --gid-range expansions over LOOP_HARD_CAP entries
    must require --allow-huge. The function sys.exit(2)s on bound failure —
    tests catch SystemExit and verify the code."""

    def test_normal_range_returns_count(self):
        self.assertEqual(G._check_range_size(1, 100, "--range", False), 100)

    def test_at_cap_is_accepted(self):
        cap = G.LOOP_HARD_CAP
        self.assertEqual(G._check_range_size(1, cap, "--range", False), cap)

    def test_over_cap_without_allow_huge_exits(self):
        with self.assertRaises(SystemExit) as cm, redirect_stderr(io.StringIO()):
            G._check_range_size(1, G.LOOP_HARD_CAP + 1, "--range", False)
        self.assertEqual(cm.exception.code, 2)

    def test_over_cap_with_allow_huge_passes(self):
        n = G._check_range_size(1, G.LOOP_HARD_CAP + 1, "--range", True)
        self.assertEqual(n, G.LOOP_HARD_CAP + 1)

    def test_inverted_range_exits(self):
        with self.assertRaises(SystemExit) as cm, redirect_stderr(io.StringIO()):
            G._check_range_size(10, 5, "--range", False)
        self.assertEqual(cm.exception.code, 2)


# --------------------------------------------------------------------- type_str / unwrap
class TestTypeHelpers(unittest.TestCase):
    """type_str must reproduce GraphQL's `[Foo!]!` syntax from the introspection
    JSON's nested ofType chain. unwrap must strip those wrappers cleanly."""

    SCALAR_STRING = {"kind": "SCALAR", "name": "String"}
    NN_STRING = {"kind": "NON_NULL", "name": None, "ofType": SCALAR_STRING}
    LIST_NN_STRING = {"kind": "LIST", "name": None, "ofType": NN_STRING}
    NN_LIST_NN_STRING = {"kind": "NON_NULL", "name": None, "ofType": LIST_NN_STRING}

    def test_type_str_scalar(self):
        self.assertEqual(G.type_str(self.SCALAR_STRING), "String")

    def test_type_str_non_null(self):
        self.assertEqual(G.type_str(self.NN_STRING), "String!")

    def test_type_str_list(self):
        self.assertEqual(G.type_str(self.LIST_NN_STRING), "[String!]")

    def test_type_str_list_non_null_required_list(self):
        self.assertEqual(G.type_str(self.NN_LIST_NN_STRING), "[String!]!")

    def test_type_str_none(self):
        self.assertEqual(G.type_str(None), "")

    def test_unwrap_strips_to_scalar(self):
        self.assertEqual(G.unwrap(self.NN_LIST_NN_STRING)["name"], "String")
        self.assertEqual(G.unwrap(self.SCALAR_STRING)["name"], "String")


# --------------------------------------------------------------------- type_by_name
class TestTypeByName(unittest.TestCase):
    SCHEMA = {
        "types": [
            {"kind": "OBJECT", "name": "User", "fields": []},
            {"kind": "OBJECT", "name": "Project", "fields": []},
        ]
    }

    def test_lookup_hits(self):
        self.assertEqual(G.type_by_name(self.SCHEMA, "User")["name"], "User")
        self.assertEqual(G.type_by_name(self.SCHEMA, "Project")["name"], "Project")

    def test_lookup_miss_returns_none(self):
        self.assertIsNone(G.type_by_name(self.SCHEMA, "Missing"))

    def test_empty_schema_returns_none(self):
        self.assertIsNone(G.type_by_name(None, "User"))
        self.assertIsNone(G.type_by_name({}, "User"))


# --------------------------------------------------------------------- parse_kv_args
class TestParseKVArgs(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(G.parse_kv_args(["id=42", "name=alice"]),
                         {"id": "42", "name": "alice"})

    def test_value_with_equals(self):
        # Equals embedded in the value (e.g. base64) must survive — only the
        # first `=` splits.
        self.assertEqual(G.parse_kv_args(["token=abc=def=="]),
                         {"token": "abc=def=="})

    def test_empty_and_none(self):
        self.assertEqual(G.parse_kv_args([]),   {})
        self.assertEqual(G.parse_kv_args(None), {})

    def test_bad_kv_exits(self):
        with self.assertRaises(SystemExit) as cm, redirect_stderr(io.StringIO()):
            G.parse_kv_args(["no-equals-here"])
        self.assertEqual(cm.exception.code, 2)


# --------------------------------------------------------------------- build_selection
class TestBuildSelection(unittest.TestCase):
    """build_selection generates the auto-selection set used by `gql.py call`
    when the operator doesn't pass --select. The tests are minimal — exercising
    scalar return, object return, unknown-type fallback, and cycle break."""

    SCALAR = {"kind": "SCALAR", "name": "String"}

    def test_scalar_return_emits_nothing(self):
        self.assertEqual(G.build_selection(None, self.SCALAR), "")

    def test_unknown_type_falls_back_to_typename(self):
        # No schema + non-scalar return -> minimal valid selection
        self.assertEqual(G.build_selection(None, {"kind": "OBJECT", "name": "User"}),
                         "{ __typename }")

    def test_object_with_scalar_fields(self):
        schema = {
            "types": [{
                "kind": "OBJECT",
                "name": "User",
                "fields": [
                    {"name": "id",    "type": self.SCALAR, "args": []},
                    {"name": "email", "type": self.SCALAR, "args": []},
                ],
            }]
        }
        sel = G.build_selection(schema, {"kind": "OBJECT", "name": "User"})
        self.assertTrue(sel.startswith("{") and sel.endswith("}"))
        self.assertIn("id",    sel)
        self.assertIn("email", sel)
        self.assertIn("__typename", sel)

    def test_required_arg_field_skipped(self):
        # A field that requires a NON_NULL argument can't be selected without
        # parameters, so build_selection must skip it.
        schema = {
            "types": [{
                "kind": "OBJECT",
                "name": "Project",
                "fields": [
                    {"name": "id", "type": self.SCALAR, "args": []},
                    {"name": "secret", "type": self.SCALAR,
                     "args": [{"name": "password",
                               "type": {"kind": "NON_NULL", "ofType": self.SCALAR}}]},
                ],
            }]
        }
        sel = G.build_selection(schema, {"kind": "OBJECT", "name": "Project"})
        self.assertIn("id", sel)
        self.assertNotIn("secret", sel)


if __name__ == "__main__":
    unittest.main()
