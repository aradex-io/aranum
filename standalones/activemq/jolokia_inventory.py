#!/usr/bin/env python3
"""Parse Jolokia search results without shell word splitting."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.parse
from pathlib import Path


def parse_object_name(value: str) -> dict[str, str]:
    props = value.split(":", 1)[1] if ":" in value else value
    parts, buf, quoted, escaped = [], [], False, False
    for char in props:
        if escaped:
            buf.append(char); escaped = False
        elif char == "\\":
            buf.append(char); escaped = True
        elif char == '"':
            buf.append(char); quoted = not quoted
        elif char == "," and not quoted:
            parts.append("".join(buf)); buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    result: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        if len(raw) >= 2 and raw[0] == raw[-1] == '"':
            raw = re.sub(r"\\(.)", r"\1", raw[1:-1])
        result[key] = raw
    return result


def records(path: Path, kind: str):
    body = json.loads(path.read_text(encoding="utf-8"))
    values = body.get("value", [])
    if isinstance(values, dict):
        values = list(values)
    for obj in values if isinstance(values, list) else []:
        if not isinstance(obj, str):
            continue
        props = parse_object_name(obj)
        if kind == "Broker":
            if props.get("type") != "Broker" or "destinationType" in props:
                continue
            name = props.get("brokerName")
        else:
            if props.get("destinationType") != kind:
                continue
            name = props.get("destinationName")
        if name is None:
            continue
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "unnamed"
        safe = f"{safe[:48]}-{hashlib.sha256(obj.encode()).hexdigest()[:10]}"
        broker = props.get("brokerName", "")
        yield broker, safe, name, urllib.parse.quote(obj, safe="")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=("Broker", "Queue", "Topic"))
    ap.add_argument("file", type=Path)
    args = ap.parse_args()
    seen = set()
    for broker, safe, name, encoded in records(args.file, args.kind):
        key = (name, encoded)
        if key in seen:
            continue
        seen.add(key)
        if args.kind == "Broker":
            print(f"{safe}\t{name}\t{encoded}")
        else:
            print(f"{broker}\t{safe}\t{name}\t{encoded}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
