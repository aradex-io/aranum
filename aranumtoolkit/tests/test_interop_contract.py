#!/usr/bin/env python3
"""PLAN-002 A1 published-contract and completion-semantics tests."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jsonschema

REPO = Path(__file__).resolve().parents[2]
NETWORK = REPO / "aranumtoolkit" / "network"
SCHEMAS = REPO / "aranumtoolkit" / "schemas"
FIXTURES = REPO / "aranumtoolkit" / "tests" / "fixtures"
INTEROP = FIXTURES / "interop"
AUTO_ENUM = NETWORK / "auto-enum.sh"
REPORT = NETWORK / "report.py"
LOCAL_ENUM = NETWORK / "local-enum.py"
MANIFEST_CLI = NETWORK / "manifest.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


MANIFEST = _load(MANIFEST_CLI, "interop_contract_manifest")
ARANUM = _load(REPO / "aranum.py", "interop_contract_aranum")


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate(document: Path, schema_name: str) -> None:
    jsonschema.Draft202012Validator(_json(SCHEMAS / f"{schema_name}.schema.json")).validate(
        _json(document))


def _digest_mismatches(bundle: Path) -> list[str]:
    mismatches = []
    for item in _json(bundle / "bundle-manifest.json")["files"]:
        actual = hashlib.sha256((bundle / item["path"]).read_bytes()).hexdigest()
        if actual != item["sha256"]:
            mismatches.append(item["path"])
    return mismatches


def _minimal_inventory() -> dict:
    return {
        "schema_version": "1", "tool": "aranum-nmap-parse", "tool_version": "test",
        "summary": {"hosts": 0, "hosts_up": 0, "hosts_with_open_ports": 0,
                    "open_ports": 0, "unknown": [], "categories": {}},
        "hosts": [], "entries": [],
    }


def test_every_emitter_document_validates_against_published_schema():
    schema_by_name = {
        "inventory.json": "inventory-1",
        "findings.json": "findings-2",
        "posture.json": "posture-1",
        "run-state.json": "run-state-1",
        "bundle-manifest.json": "bundle-manifest-1",
    }
    seen = set()
    for bundle in sorted(path for path in INTEROP.iterdir() if path.is_dir()):
        for name, schema in schema_by_name.items():
            document = bundle / name
            if document.is_file():
                _validate(document, schema)
                seen.add(schema)
    _validate(NETWORK / "dispatchers.json", "dispatchers-1")
    seen.add("dispatchers-1")
    assert seen == set(schema_by_name.values()) | {"dispatchers-1"}


def test_manifest_digests_match_tree_and_corruption_is_detected(tmp_path: Path):
    bundle = tmp_path / "bundle"
    shutil.copytree(INTEROP / "FX-1", bundle)
    assert _digest_mismatches(bundle) == []
    with (bundle / "inventory.json").open("a", encoding="utf-8") as stream:
        stream.write("\n")
    assert _digest_mismatches(bundle) == ["inventory.json"]


def test_two_process_run_then_report_preserves_run_producer(tmp_path: Path):
    out = tmp_path / "bundle"
    out.mkdir()
    subprocess.run([sys.executable, str(MANIFEST_CLI), "stage-begin", str(out), "run",
                    "--mint", "--run-id", "two-process"], check=True)
    _write = out / "inventory.json"
    _write.write_text(json.dumps(_minimal_inventory()), encoding="utf-8")
    subprocess.run([sys.executable, str(MANIFEST_CLI), "stage-end", str(out), "run", "0"],
                   check=True)
    report = subprocess.run([sys.executable, str(REPORT), str(out), "--findings-only"],
                            capture_output=True, text=True)
    assert report.returncode == 0, report.stderr
    entries = {item["path"]: item for item in _json(out / "bundle-manifest.json")["files"]}
    assert entries["inventory.json"]["produced_by"] == "run"
    assert entries["findings.json"]["produced_by"] == "report"
    assert _json(out / "findings.json")["run_id"] == "two-process"


def test_fx4_interrupted_run_is_not_complete(tmp_path: Path):
    bundle = tmp_path / "fx4"
    bundle.mkdir()
    MANIFEST.stage_begin(bundle, "run", "fx4-run-1", mint=True)
    (bundle / "inventory.json").write_text(json.dumps(_minimal_inventory()), encoding="utf-8")
    MANIFEST.stage_end(bundle, "run", 0)
    MANIFEST.stage_begin(bundle, "run", "fx4-run-2", mint=True)
    manifest = _json(bundle / "bundle-manifest.json")
    assert manifest["stages"]["run"]["status"] == "running"
    assert manifest["status"] == "interrupted"


def test_fx4l_prior_report_outputs_are_unlisted_after_local_mint(tmp_path: Path):
    bundle = tmp_path / "fx4l"
    bundle.mkdir()
    MANIFEST.stage_begin(bundle, "local", "fx4l-run-1", mint=True)
    MANIFEST.stage_end(bundle, "local", 0)
    (bundle / "findings.json").write_text("{}\n", encoding="utf-8")
    MANIFEST.stage_begin(bundle, "report", "fx4l-run-1")
    MANIFEST.stage_end(bundle, "report", 0)
    MANIFEST.stage_begin(bundle, "local", "fx4l-run-2", mint=True)
    manifest = _json(bundle / "bundle-manifest.json")
    assert (bundle / "findings.json").is_file()
    assert "findings.json" not in {item["path"] for item in manifest["files"]}
    assert "report" not in manifest["stages"]
    assert manifest["status"] != "complete"


def test_auto_enum_unbound_abort_closes_run_stage_failed(tmp_path: Path):
    script_dir = tmp_path / "network"
    script_dir.mkdir()
    shutil.copy2(MANIFEST_CLI, script_dir / "manifest.py")
    source = AUTO_ENUM.read_text(encoding="utf-8")
    marker = 'RUN_STATE_DIR="$OUTDIR/.run-state-$RUN_ID"'
    assert marker in source
    source = source.replace(marker, 'printf "%s\\n" "$A1_TEST_UNBOUND"\n' + marker, 1)
    script = script_dir / "auto-enum.sh"
    script.write_text(source, encoding="utf-8")
    scan = tmp_path / "scan.xml"
    scan.write_text("<nmaprun/>\n", encoding="utf-8")
    out = tmp_path / "out"
    proc = subprocess.run(["bash", str(script), "-i", str(scan), "-o", str(out)],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    stage = _json(out / "stages" / "run.json")
    assert stage["status"] == "failed"
    assert stage["exit_code"] != 0


def test_auto_enum_plan_only_closes_run_stage_complete(tmp_path: Path):
    out = tmp_path / "plan-only"
    proc = subprocess.run([
        "bash", str(AUTO_ENUM), "-i", str(FIXTURES / "services" / "all-services.xml"),
        "-o", str(out), "--plan-only",
    ], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    stage = _json(out / "stages" / "run.json")
    assert stage["status"] == "complete"
    assert {item["path"] for item in stage["produced"]} == {
        "plan.json", "queue.jsonl", "guidance.json",
    }


def test_local_stage_mints_without_run_and_inherits_existing_run(tmp_path: Path):
    targets = tmp_path / "targets.txt"
    targets.write_text("local-lab.invalid os=linux via=ssh\n", encoding="utf-8")

    local_only = tmp_path / "local-only"
    first = subprocess.run([sys.executable, str(LOCAL_ENUM), "--targets", str(targets),
                            "--dry-run", "-o", str(local_only)],
                           capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    local_record = _json(local_only / "stages" / "local.json")
    assert local_record["status"] == "complete"
    assert local_record["run_id"]

    inherited = tmp_path / "inherited"
    inherited.mkdir()
    MANIFEST.stage_begin(inherited, "run", "parent-run", mint=True)
    MANIFEST.stage_end(inherited, "run", 0)
    second = subprocess.run([sys.executable, str(LOCAL_ENUM), "--targets", str(targets),
                             "--dry-run", "-o", str(inherited)],
                            capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    manifest = _json(inherited / "bundle-manifest.json")
    assert set(manifest["stages"]) == {"run", "local"}
    assert manifest["stages"]["local"]["run_id"] == "parent-run"


def test_rc4_launcher_continues_to_report_dashboard_and_returns_4(
        tmp_path: Path, monkeypatch):
    outputs = tmp_path / "outputs"
    scan = tmp_path / "scan.xml"
    scan.write_text("<nmaprun/>\n", encoding="utf-8")
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        script = Path(command[1]).name
        raw = outputs / "rc4" / "raw"
        if script == "auto-enum.sh":
            _json_path = raw / "inventory.json"
            _json_path.parent.mkdir(parents=True, exist_ok=True)
            _json_path.write_text(json.dumps(_minimal_inventory()), encoding="utf-8")
            MANIFEST.stage_begin(raw, "run", "rc4-run", mint=True)
            MANIFEST.stage_end(raw, "run", 4)
            return SimpleNamespace(returncode=4)
        if script == "report.py":
            findings = {
                "schema_version": "2", "run_id": "rc4-run", "label": "rc4",
                "generated_utc": "2026-10-27T12:00:00Z",
                "redacted": False, "mode": "auto-enum", "summary": {}, "findings": [],
                "partial": True, "errors": [{"type": "synthetic"}],
            }
            (raw / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
            MANIFEST.stage_begin(raw, "report", "rc4-run")
            MANIFEST.stage_end(raw, "report", 1, status="partial")
            return SimpleNamespace(returncode=1)
        if script == "report-dashboard.py":
            return SimpleNamespace(returncode=0)
        raise AssertionError(command)

    monkeypatch.setattr(ARANUM, "OUTPUTS_DIR", outputs)
    monkeypatch.setattr(ARANUM.subprocess, "run", fake_run)
    rc = ARANUM.main(["run", str(scan), "-report", "--session-name", "rc4"])
    raw = outputs / "rc4" / "raw"
    assert rc == 4
    assert (raw / "findings.json").is_file()
    assert _json(raw / "bundle-manifest.json")["status"] == "partial"
    assert [Path(call[1]).name for call in calls] == [
        "auto-enum.sh", "report.py", "report-dashboard.py",
    ]


def test_dispatcher_registry_exactly_matches_tree_and_is_idempotent(tmp_path: Path):
    registry = _json(NETWORK / "dispatchers.json")
    listed = {item["script"] for item in registry["dispatchers"]}
    actual = {path.name for path in NETWORK.glob("enum-*.sh")}
    assert listed == actual
    assert sum(item["uses_credentials"] for item in registry["dispatchers"]) == 16
    generated = tmp_path / "dispatchers.json"
    subprocess.run([sys.executable, str(NETWORK / "gen-dispatchers.py"),
                    "--output", str(generated)], check=True)
    assert generated.read_bytes() == (NETWORK / "dispatchers.json").read_bytes()
