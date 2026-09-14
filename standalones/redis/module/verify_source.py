#!/usr/bin/env python3
"""Fail closed unless every vendored Redis module input matches SOURCE.json."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "SOURCE.json"


def main() -> int:
    try:
        body = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for name in ("redis_header", "module_source"):
            entry = body[name]
            rel = Path(entry["path"])
            expected = entry["sha256"]
            if rel.is_absolute() or ".." in rel.parts or len(expected) != 64:
                raise ValueError(f"unsafe/invalid {name} provenance")
            source = (ROOT / rel).resolve()
            source.relative_to(ROOT.resolve())
            actual = hashlib.sha256(source.read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"{name} checksum mismatch for {rel}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: Redis module source provenance invalid: {exc}", file=sys.stderr)
        return 1
    print("[+] Redis module vendored source provenance verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
