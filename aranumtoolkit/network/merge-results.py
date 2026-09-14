#!/usr/bin/env python3
"""merge-results.py — merge findings.json exports from multiple aranum runs.

The script only manipulates `findings.json` plus referenced evidence files:
- Reads findings.json from each output directory.
- Rewrites `evidence_path` to a consolidated output tree (`evidence/`).
- Deduplicates copied evidence files by SHA-256.
- Deduplicates findings across runs by `(host, port, service, severity, line)`.
- Writes merged `findings.json` to the requested output directory.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SCHEMA_VERSION = "2"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("sources", nargs="+", help="Input aranum output directories")
    p.add_argument("-o", "--output", required=True, type=Path, help="Output directory")
    p.add_argument("--label", default="merged", help="Merged report label")
    return p.parse_args()


def _read_findings_json(source: Path) -> dict[str, Any]:
    path = source / "findings.json"
    if not path.is_file():
        raise FileNotFoundError(f"findings.json missing: {path}")
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"error: malformed findings.json: {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(obj, dict):
        print(f"error: findings.json is not a JSON object: {path}", file=sys.stderr)
        sys.exit(2)
    return obj


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(text: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)


def _summary(findings: list[dict]) -> dict[str, Any]:
    counts = defaultdict(int)
    by_service = defaultdict(lambda: defaultdict(int))
    hosts = set()
    services = set()

    for finding in findings:
        sev = str(finding.get("severity", "low")).lower()
        service = str(finding.get("service", ""))
        host = str(finding.get("host", ""))

        counts[sev] += 1
        by_service[service][sev] += 1
        if host and host != "(dispatcher)":
            hosts.add(host)
        if service:
            services.add(service)

    return {
        "hosts": sorted(hosts),
        "services": sorted(services),
        "counts": dict(counts),
        "by_service": {svc: dict(v) for svc, v in by_service.items()},
    }


def _merge_findings(source_dirs: list[Path], output: Path) -> tuple[list[dict], dict[str, Any]]:
    evidence_to_digest: dict[str, str] = {}
    dedupe_map: dict[tuple[Any, ...], dict] = {}
    warnings: list[str] = []
    redacted_inputs: list[bool] = []

    merged: list[dict] = []

    for idx, source in enumerate(source_dirs):
        source_id = f"src{idx:02d}-{_safe_name(source.name)}"
        data = _read_findings_json(source)
        redacted_inputs.append(bool(data.get("redacted", False)))
        for finding in data.get("findings", []):
            host = finding.get("host", "")
            port = finding.get("port", "")
            service = finding.get("service", "")
            protocol = finding.get("protocol", "")
            severity = finding.get("severity", "")
            line = finding.get("line", "")
            evidence_identity = finding.get("evidence_identity") or hashlib.sha256(
                str(line).encode()).hexdigest()
            key = (
                str(host).strip(),
                str(port).strip(),
                str(protocol).strip(),
                str(service).strip(),
                str(severity).strip(),
                str(evidence_identity).strip(),
            )

            # Keep all source metadata we care about, then rewrite path
            merged_finding = dict(finding)
            merged_finding["host"] = host
            merged_finding["port"] = port
            merged_finding["protocol"] = protocol
            merged_finding["service"] = service
            merged_finding["severity"] = severity
            merged_finding["line"] = line
            merged_finding["evidence_identity"] = evidence_identity
            merged_finding["evidence_paths"] = []

            evidence = str(finding.get("evidence_path", "")).strip()
            # Containment (OPSEC §9): an evidence_path is only ever a relative
            # path inside the source tree. Reject absolute paths or any `..`
            # component so a crafted findings.json cannot make merge read/copy a
            # file from outside the source dir into the consolidated output.
            if evidence and (Path(evidence).is_absolute() or ".." in Path(evidence).parts):
                warnings.append(f"unsafe evidence_path skipped (escapes source): {evidence}")
                merged_finding["evidence_path"] = ""
                merged_finding["evidence_status"] = "unsafe"
                evidence = ""
            if evidence and not (source / evidence).resolve().is_relative_to(source.resolve()):
                warnings.append(f"unsafe evidence_path skipped (escapes source): {evidence}")
                merged_finding["evidence_path"] = ""
                merged_finding["evidence_status"] = "unsafe"
                evidence = ""
            if evidence:
                src = source / evidence
                if not src.exists():
                    warnings.append(f"missing evidence: {source}/{evidence}")
                    merged_finding["source_evidence_path"] = f"{source_id}/{evidence}"
                    merged_finding["evidence_path"] = ""
                    merged_finding["evidence_status"] = "missing"
                else:
                    digest = _hash_file(src)
                    if digest in evidence_to_digest:
                        merged_finding["evidence_path"] = evidence_to_digest[digest]
                        merged_finding["evidence_status"] = "copied"
                    else:
                        rel = Path("evidence") / source_id / Path(evidence)
                        dst = output / rel
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            shutil.copy2(src, dst)
                        except OSError as exc:
                            warnings.append(f"failed evidence copy: {src}: {exc}")
                            merged_finding["source_evidence_path"] = f"{source_id}/{evidence}"
                            merged_finding["evidence_path"] = ""
                            merged_finding["evidence_status"] = "copy_failed"
                        else:
                            evidence_to_digest[digest] = str(rel.as_posix())
                            merged_finding["evidence_path"] = str(rel.as_posix())
                            merged_finding["evidence_status"] = "copied"
                if merged_finding.get("evidence_path"):
                    merged_finding["evidence_paths"] = [merged_finding["evidence_path"]]
            prior = dedupe_map.get(key)
            if prior is None:
                dedupe_map[key] = merged_finding
            else:
                for path in merged_finding.get("evidence_paths", []):
                    if path not in prior.setdefault("evidence_paths", []):
                        prior["evidence_paths"].append(path)

    merged = list(dedupe_map.values())
    merged.sort(
        key=lambda f: (
            _SEV_ORDER.get(str(f.get("severity", "")).lower(), 9),
            str(f.get("host", "")),
            str(f.get("service", "")),
            str(f.get("line", "")),
        )
    )
    if not redacted_inputs or not any(redacted_inputs):
        redaction_state = "unredacted"
    elif all(redacted_inputs):
        redaction_state = "redacted"
    else:
        redaction_state = "mixed"
    return merged, {"evidence_warnings": warnings, "redaction_state": redaction_state,
                    "redacted": any(redacted_inputs), "complete": not warnings}


def main() -> int:
    args = _parse_args()
    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[!] cannot create output directory {output}: {exc}", file=sys.stderr)
        return 2

    source_dirs = [Path(p).resolve() for p in args.sources]
    for source in source_dirs:
        if not source.is_dir():
            print(f"[!] source is not a directory: {source}", file=sys.stderr)
            return 2
        if not (source / "findings.json").is_file():
            print(f"[!] findings.json missing in: {source}", file=sys.stderr)
            return 2
        data = _read_findings_json(source)
        if str(data.get("schema_version", "")) != _SCHEMA_VERSION:
            print(f"[!] unsupported findings schema in {source}: "
                  f"{data.get('schema_version')!r} (expected {_SCHEMA_VERSION!r})",
                  file=sys.stderr)
            return 2

    findings, meta = _merge_findings(source_dirs, output)
    out_payload = {
        "schema_version": _SCHEMA_VERSION,
        "label": args.label,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "merged",
        "redacted": meta["redacted"],
        "redaction_state": meta["redaction_state"],
        "complete": meta["complete"],
        "sources": [str(s) for s in source_dirs],
        "summary": _summary(findings),
        "findings": findings,
    }
    if meta.get("evidence_warnings"):
        out_payload["warnings"] = meta["evidence_warnings"]

    (output / "findings.json").write_text(
        json.dumps(out_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return 0 if meta["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
