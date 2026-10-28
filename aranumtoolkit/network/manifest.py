#!/usr/bin/env python3
"""manifest.py — per-stage completion records and a derived bundle manifest.

PLAN-002 A1.3. An aranum run is produced by up to three stages — ``run``
(auto-enum.sh), ``local`` (local-enum.py), and ``report`` (report.py) — that
execute as separate processes, in any subset, over one output directory.

Two artifacts make a bundle's completeness legible to an offline consumer:

* ``<outdir>/stages/<stage>.json`` — one record per stage, owned by that stage
  alone. ``stage_begin`` writes ``{status: "running", …}``; ``stage_end``
  rewrites it ``{status ∈ complete|partial|failed, exit_code, …, produced[]}``.
  A stage that is SIGKILLed never reaches ``stage_end`` and is left
  ``running`` — which the manifest folds to *interrupted*.

* ``<outdir>/bundle-manifest.json`` — a **pure function of the tree**, rebuilt
  at every stage boundary. It reads every present ``stages/*.json``, digests
  the files they list *now* (no digest carried forward), and folds the per-
  stage statuses into one bundle status. The manifest is therefore never
  authoritative over the tree: rebuilding is always safe.

**purge-on-mint**: a stage that *mints* a new ``run_id`` deletes every other
``stages/*.json`` at its ``stage_begin``, so records from two runs can never
coexist in one directory. Outputs left on disk from the previous run are then
listed by no stage and are reported by the importer as unlisted, never
imported as complete.

Usable as a library (local-enum.py, report.py call the functions directly) or
as a CLI (auto-enum.sh shells out):

    python3 manifest.py stage-begin <outdir> run  --mint --run-id ID
    python3 manifest.py stage-end   <outdir> run  <exit_code>
    python3 manifest.py build       <outdir>
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Optional

MANIFEST_SCHEMA_VERSION = "1"
MANIFEST_NAME = "bundle-manifest.json"
STAGES_DIRNAME = "stages"
STAGE_NAMES = ("run", "local", "report")

# A listed file's schema id (the schema basename without ``.schema.json``), or
# None for a listed file that carries no schema (plan/queue/guidance/report
# renders). Only files a stage declares in ``produced[]`` are digested.
SCHEMA_BY_BASENAME = {
    "inventory.json": "inventory-1",
    "findings.json": "findings-2",
    "posture.json": "posture-1",
    "run-state.json": "run-state-1",
    "dispatchers.json": "dispatchers-1",
}

# Root-level files each stage is responsible for. ``produced[]`` is scoped to
# the output root: the importer's unlisted-file diagnostic only inspects
# root-level ``*.json`` (nested service/host trees are evidence, not bundle
# documents), so listing the root files a stage wrote keeps them from tripping
# that diagnostic (R-28, H15). A caller may override with an explicit list.
STAGE_ROOT_OUTPUTS = {
    "run": ["inventory.json", "run-state.json", "plan.json", "queue.jsonl", "guidance.json"],
    "local": [],
    "report": ["findings.json", "posture.json", "report.md", "report.html", "findings.sarif"],
}


# --------------------------------------------------------------------- helpers
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _tool_version() -> str:
    """aranum's version — the VERSION file, else the CHANGELOG top released
    block, else ``unknown``."""
    root = _repo_root()
    vf = root / "VERSION"
    if vf.is_file():
        base = vf.read_text().strip()
        if base:
            return base
    ch = root / "CHANGELOG.md"
    if ch.is_file():
        for line in ch.read_text().splitlines():
            s = line.strip()
            if s.startswith("## [v"):
                return s[len("## [v"):].split("]", 1)[0]
    return "unknown"


def _kb_digest() -> Optional[str]:
    """sha256 of the installed finding knowledge base, or None if absent."""
    kb = _repo_root() / "aranumtoolkit" / "network" / "finding-kb.json"
    if kb.is_file():
        return hashlib.sha256(kb.read_bytes()).hexdigest()
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    directory = str(path.parent) or "."
    fd, tmp = tempfile.mkstemp(prefix=".manifest.", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _stages_dir(outdir: Path) -> Path:
    return outdir / STAGES_DIRNAME


def _schema_for(basename: str) -> Optional[str]:
    return SCHEMA_BY_BASENAME.get(basename)


def _discover_produced(outdir: Path, stage: str) -> list[dict[str, Any]]:
    """Root-level files this stage is responsible for that exist on disk now."""
    produced = []
    for name in STAGE_ROOT_OUTPUTS.get(stage, []):
        if (outdir / name).is_file():
            produced.append({"path": name, "schema": _schema_for(name)})
    return produced


# ----------------------------------------------------------------- public API
def stage_begin(
    outdir: os.PathLike | str,
    stage: str,
    run_id: Optional[str],
    *,
    mint: bool = False,
    invocation: Optional[dict] = None,
    account_label: Optional[str] = None,
    consumed: Optional[Iterable[str]] = None,
) -> None:
    """Open a stage: write its record as ``running`` and rebuild the manifest.

    When ``mint`` is true this stage owns a fresh ``run_id``; every other
    ``stages/*.json`` (and the old manifest) is deleted first so two runs'
    records can never coexist (purge-on-mint).
    """
    outdir = Path(outdir)
    sdir = _stages_dir(outdir)
    sdir.mkdir(parents=True, exist_ok=True)
    if mint:
        for other in sdir.glob("*.json"):
            other.unlink()
        mpath = outdir / MANIFEST_NAME
        if mpath.exists():
            mpath.unlink()
    record: dict[str, Any] = {
        "status": "running",
        "run_id": run_id,
        "started_utc": _now(),
        "consumed": list(consumed) if consumed else [],
    }
    if invocation is not None:
        record["invocation"] = invocation
    if account_label is not None:
        record["account_label"] = account_label
    _atomic_write(sdir / f"{stage}.json", json.dumps(record, indent=2) + "\n")
    build_manifest(outdir)


def stage_end(
    outdir: os.PathLike | str,
    stage: str,
    exit_code: int,
    *,
    status: Optional[str] = None,
    produced: Optional[list[dict[str, Any]]] = None,
) -> None:
    """Close a stage: rewrite its record with a terminal status, exit code,
    finish time, and the files it produced, then rebuild the manifest.

    ``status`` defaults from ``exit_code`` (0⇒complete, 4⇒partial, else
    failed); a caller with stage-specific semantics (report rc 1 ⇒ partial)
    passes it explicitly.
    """
    outdir = Path(outdir)
    sdir = _stages_dir(outdir)
    path = sdir / f"{stage}.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # No open record (stage_begin never ran, or it was purged): recreate a
        # minimal one so the terminal state is never lost.
        record = {"status": "running", "run_id": None, "started_utc": _now(), "consumed": []}
    exit_code = int(exit_code)
    if status is None:
        status = "complete" if exit_code == 0 else "partial" if exit_code == 4 else "failed"
    record["status"] = status
    record["exit_code"] = exit_code
    record["finished_utc"] = _now()
    record["produced"] = produced if produced is not None else _discover_produced(outdir, stage)
    sdir.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, json.dumps(record, indent=2) + "\n")
    build_manifest(outdir)


def build_manifest(outdir: os.PathLike | str) -> dict[str, Any]:
    """Rebuild ``bundle-manifest.json`` as a pure function of the tree.

    Reads every present ``stages/*.json``, digests the files each lists now,
    and folds the per-stage statuses into one bundle status. Returns the
    manifest dict (also written to disk).
    """
    outdir = Path(outdir)
    sdir = _stages_dir(outdir)
    stages: dict[str, Any] = {}
    files: list[dict[str, Any]] = []
    run_ids: set[str] = set()

    for spath in sorted(sdir.glob("*.json")):
        name = spath.stem
        if name not in STAGE_NAMES:
            continue
        try:
            record = json.loads(spath.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        stages[name] = record
        rid = record.get("run_id")
        if rid:
            run_ids.add(rid)
        for entry in record.get("produced", []):
            rel = entry.get("path")
            if not rel:
                continue
            abspath = outdir / rel
            if abspath.is_file():
                files.append({
                    "path": rel,
                    "schema": entry.get("schema", _schema_for(Path(rel).name)),
                    "sha256": _sha256(abspath),
                    "produced_by": name,
                })

    statuses = {rec.get("status") for rec in stages.values()}
    if not stages:
        status = "unknown"
    elif "failed" in statuses:
        status = "failed"
    elif "running" in statuses:
        status = "interrupted"
    elif len(run_ids) > 1:
        # Should be unreachable given purge-on-mint; kept as a defensive fold.
        status = "stale"
    elif "partial" in statuses:
        status = "partial"
    else:
        status = "complete"

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": next(iter(run_ids)) if len(run_ids) == 1 else None,
        "tool_version": _tool_version(),
        "kb": {"digest": _kb_digest()},
        "stages": stages,
        "files": sorted(files, key=lambda f: f["path"]),
        "status": status,
    }
    _atomic_write(outdir / MANIFEST_NAME, json.dumps(manifest, indent=2) + "\n")
    return manifest


# ------------------------------------------------------------------------- CLI
def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="manifest.py", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sb = sub.add_parser("stage-begin", help="open a stage (status=running)")
    sb.add_argument("outdir")
    sb.add_argument("stage", choices=STAGE_NAMES)
    sb.add_argument("--run-id", default=None)
    sb.add_argument("--mint", action="store_true")
    sb.add_argument("--invocation-json", default=None,
                    help="JSON invocation facts authored by the stage argument builder")
    sb.add_argument("--account-label", default=None,
                    help="non-secret operator account label for auth-context stamping")

    se = sub.add_parser("stage-end", help="close a stage (terminal status)")
    se.add_argument("outdir")
    se.add_argument("stage", choices=STAGE_NAMES)
    se.add_argument("exit_code", type=int)
    se.add_argument("--status", default=None,
                    choices=["complete", "partial", "failed"])

    bl = sub.add_parser("build", help="rebuild the manifest from the tree")
    bl.add_argument("outdir")

    args = parser.parse_args(argv)
    if args.cmd == "stage-begin":
        invocation = None
        if args.invocation_json is not None:
            try:
                invocation = json.loads(args.invocation_json)
            except (ValueError, TypeError) as exc:
                parser.error(f"--invocation-json must be a JSON object: {exc}")
            if not isinstance(invocation, dict):
                parser.error("--invocation-json must be a JSON object")
        stage_begin(args.outdir, args.stage, args.run_id, mint=args.mint,
                    invocation=invocation, account_label=args.account_label)
    elif args.cmd == "stage-end":
        stage_end(args.outdir, args.stage, args.exit_code, status=args.status)
    elif args.cmd == "build":
        build_manifest(args.outdir)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
