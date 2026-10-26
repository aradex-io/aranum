#!/usr/bin/env python3
"""Shared dispatcher-emission extractor (D1.2 — plan PLAN-001-25OCT2026).

Single source of truth for the static emission corpus: every literal
hit/miss/err/crit/log "..." call in ``aranumtoolkit/network/enum-*.sh``,
rendered the way ``_lib.sh`` prints it (``[+]`` / ``[-]`` / ``[!]`` / ``[!!]`` /
``[HH:MM:SS]``) with shell vars substituted by plausible tokens.

Both the benefit harness (``docs/test-strategy/harness/emission_audit.py``) and
the S1 gates (``tests/test_findings_fidelity.py``, ``tests/test_rule_shadowing.py``)
import ``extract_emissions`` so the corpus a test asserts on is exactly the
corpus the benefit number is measured on — they cannot drift apart.
"""
from __future__ import annotations

import re
from pathlib import Path

# How _lib.sh renders each emitter's marker prefix. The log timestamp is frozen
# so the corpus is deterministic across runs.
MARK = {"hit": "[+] ", "miss": "[-] ", "err": "[!] ", "crit": "[!!] ", "log": "[10:00:00] "}

# A literal `kind "..."` call. The `(?<![\w-])` left-guard avoids matching a
# substring of a longer identifier (e.g. `_hit`), matching the harness exactly.
_CALL = re.compile(r'(?<![\w-])(hit|miss|err|crit|log)\s+"((?:[^"\\]|\\.)*)"')

_VARS = {"ip": "10.0.0.9", "port": "8080", "host": "10.0.0.9", "url": "http://10.0.0.9:8080"}


def _render(s: str) -> str:
    """Substitute shell command/variable expansions with stable placeholders."""
    s = re.sub(r"\$\(([^()]*)\)", "3", s)
    s = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)[^}\s]*\}?",
               lambda m: _VARS.get(m.group(1).lower(), "x"), s)
    return s.replace('\\"', '"')


def extract_emissions(repo_root) -> "list[dict]":
    """Return one row per literal dispatcher emission.

    Each row is ``{"file": str, "line": int, "kind": str, "text": str}`` where
    ``text`` is the rendered line WITH its ``_lib.sh`` marker prefix. Comment
    lines are skipped. Order is stable (sorted by file, then source order).
    """
    net = Path(repo_root) / "aranumtoolkit" / "network"
    rows: list[dict] = []
    for f in sorted(net.glob("enum-*.sh")):
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for m in _CALL.finditer(line):
                kind = m.group(1)
                rows.append({"file": f.name, "line": n, "kind": kind,
                             "text": MARK[kind] + _render(m.group(2))})
    return rows
