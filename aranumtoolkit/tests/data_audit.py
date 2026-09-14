#!/usr/bin/env python3
"""Audit the manifest-driven provenance and freshness of embedded data/rules."""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "aranumtoolkit" / "data-sources.json"
TODAY = datetime.date.today()
REQUIRED = {"id", "source", "owner", "refreshed", "max_age_days", "freshness_policy"}


def _safe_repo_path(value: str) -> Path:
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"unsafe repository path: {value!r}")
    path = (REPO / rel).resolve()
    path.relative_to(REPO.resolve())
    return path


def _paths(entry: dict) -> list[Path]:
    if "path" in entry:
        return [_safe_repo_path(entry["path"])]
    discover = entry.get("discover")
    if not isinstance(discover, dict):
        raise ValueError("entry needs path or structured discover rule")
    roots, suffixes, regex = discover.get("roots"), discover.get("suffixes"), discover.get("marker_regex")
    if not isinstance(roots, list) or not roots or not all(isinstance(x, str) for x in roots):
        raise ValueError("discover.roots must be a nonempty string list")
    if not isinstance(suffixes, list) or not suffixes or not all(isinstance(x, str) for x in suffixes):
        raise ValueError("discover.suffixes must be a nonempty string list")
    if not isinstance(regex, str) or not regex:
        raise ValueError("discover.marker_regex must be nonempty")
    marker = re.compile(regex)
    found = []
    for root_name in roots:
        root = _safe_repo_path(root_name)
        if not root.is_dir():
            raise ValueError(f"discover root missing: {root_name}")
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in suffixes:
                if marker.search(path.read_text(encoding="utf-8", errors="replace")):
                    found.append(path)
    return sorted(set(found))


def _verify_derivation(entry: dict, paths: list[Path]) -> None:
    derivation = entry.get("derivation")
    if not isinstance(derivation, dict):
        raise ValueError("derivation must be a structured object")
    kind = derivation.get("type")
    if kind == "json-structure":
        keys = derivation.get("required_keys")
        if len(paths) != 1 or not isinstance(keys, list) or not keys or not all(isinstance(k, str) for k in keys):
            raise ValueError("json-structure needs one path and required_keys")
        body = json.loads(paths[0].read_text(encoding="utf-8"))
        if not isinstance(body, dict) or any(key not in body for key in keys):
            raise ValueError("JSON source does not satisfy required_keys")
    elif kind == "source-manifest":
        sections = derivation.get("input_sections")
        if len(paths) != 1 or not isinstance(sections, list) or not sections or not all(isinstance(s, str) for s in sections):
            raise ValueError("source-manifest needs one manifest and input_sections")
        body = json.loads(paths[0].read_text(encoding="utf-8"))
        if not isinstance(body, dict):
            raise ValueError("source manifest must be an object")
        base = paths[0].parent.resolve()
        for section in sections:
            item = body.get(section)
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ValueError(f"source section {section!r} lacks path")
            if not isinstance(item.get("source"), str) or not item["source"].strip():
                raise ValueError(f"source section {section!r} lacks provenance source")
            expected = item.get("sha256")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError(f"source section {section!r} lacks a valid SHA-256")
            rel = Path(item["path"])
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"unsafe source input path in {section!r}")
            source = (base / rel).resolve()
            source.relative_to(base)
            actual = hashlib.sha256(source.read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"source checksum mismatch: {section}/{rel}")
    elif kind == "discovered-content":
        minimum = derivation.get("minimum_files")
        if "discover" not in entry or not isinstance(minimum, int) or minimum < 1:
            raise ValueError("discovered-content needs discover rules and positive minimum_files")
        if len(paths) < minimum:
            raise ValueError(f"discovered only {len(paths)} files; minimum is {minimum}")
    else:
        raise ValueError(f"unsupported derivation type: {kind!r}")


def main() -> int:
    failures = 0
    try:
        body = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] data manifest unreadable: {exc}")
        return 1
    entries = body.get("entries")
    if not isinstance(entries, list) or not entries:
        print("[!] data manifest has no entries")
        return 1
    seen = set()
    for entry in entries:
        missing = REQUIRED - set(entry)
        if missing or not (entry.get("sha256") or entry.get("derivation")):
            print(f"[!] {entry.get('id', '?')}: missing metadata {sorted(missing)} or checksum/derivation")
            failures += 1; continue
        if entry["id"] in seen:
            print(f"[!] duplicate id: {entry['id']}"); failures += 1; continue
        seen.add(entry["id"])
        try:
            paths = _paths(entry)
        except (OSError, ValueError, re.error) as exc:
            print(f"[!] {entry['id']}: invalid source selection: {exc}")
            failures += 1; continue
        if not paths:
            print(f"[!] {entry['id']}: declared source resolves to no files")
            failures += 1; continue
        if entry.get("sha256"):
            if len(paths) != 1:
                print(f"[!] {entry['id']}: checksum entry must resolve to one file")
                failures += 1; continue
            expected = entry["sha256"]
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                print(f"[!] {entry['id']}: invalid SHA-256 metadata")
                failures += 1; continue
            actual = hashlib.sha256(paths[0].read_bytes()).hexdigest()
            if actual != expected:
                print(f"[!] {entry['id']}: checksum mismatch")
                failures += 1; continue
        else:
            try:
                _verify_derivation(entry, paths)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"[!] {entry['id']}: derivation failed: {exc}")
                failures += 1; continue
        try:
            refreshed = datetime.date.fromisoformat(entry["refreshed"])
            age = (TODAY - refreshed).days
            stale = age > int(entry["max_age_days"])
        except (ValueError, TypeError):
            print(f"[!] {entry['id']}: invalid freshness metadata")
            failures += 1; continue
        state = "STALE" if stale else "ok"
        print(f"[{state}] {entry['id']}: {len(paths)} file(s), reviewed {entry['refreshed']} "
              f"({age}d; owner={entry['owner']})")
        failures += int(stale)
    print("Manifest: aranumtoolkit/data-sources.json; policy: aranumtoolkit/docs/DATA-SOURCES.md")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
