#!/usr/bin/env python3
"""Build the small, deterministic PLAN-002 interop fixture bundles."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[2]
NETWORK = REPO / "aranumtoolkit" / "network"
FIXTURES = REPO / "aranumtoolkit" / "tests" / "fixtures"
OUTPUT = FIXTURES / "interop"
STAMP = "2026-10-27T12:00:00Z"


def _load_manifest_module():
    spec = importlib.util.spec_from_file_location("aranum_fixture_manifest", NETWORK / "manifest.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aranum_fixture_manifest"] = mod
    spec.loader.exec_module(mod)
    return mod


MANIFEST = _load_manifest_module()


def _load_report_module():
    spec = importlib.util.spec_from_file_location("aranum_fixture_report", NETWORK / "report.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aranum_fixture_report"] = mod
    spec.loader.exec_module(mod)
    return mod


REPORT = _load_report_module()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _stage(out: Path, name: str, run_id: str, status: str, exit_code: Optional[int],
           produced: Optional[list[dict[str, Any]]] = None) -> None:
    record: dict[str, Any] = {
        "status": status,
        "run_id": run_id,
        "started_utc": STAMP,
        "consumed": [],
    }
    if exit_code is not None:
        record.update({"exit_code": exit_code, "finished_utc": STAMP,
                       "produced": produced if produced is not None
                       else MANIFEST._discover_produced(out, name)})
    _write_json(out / "stages" / f"{name}.json", record)


def _run_state(run_id: str, services: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "execution_mode": "service-batch",
        "queue_authoritative": False,
        "generated_utc": STAMP,
        "services": services,
    }


def _finding(finding_id: str, host: str, service: str, severity: str, title: str,
             *, port: str = "0", line: str = "synthetic lab observation",
             triage: Optional[str] = None, kb_id: Optional[str] = None) -> dict[str, Any]:
    rule_id = kb_id or f"LAB-{finding_id}"
    item = {
        "schema_version": "2",
        "finding_id": finding_id,
        "rule_id": rule_id,
        "host": host,
        "port": port,
        "service": service,
        "severity": severity,
        "title": title,
        "line": line,
        "evidence_path": f"{service}/{host}/synthetic.txt",
        "evidence_paths": [f"{service}/{host}/synthetic.txt"],
    }
    if kb_id:
        raw, _ = REPORT._raw_finding_kb()
        entry = raw.get("classes", {}).get(kb_id) or raw.get("checks", {}).get(kb_id) or {}
        item.update({
            "logical_id": REPORT._logical_finding_id(rule_id, "", host, port, service),
            "category": str(entry.get("category") or ""),
            "kb_id": kb_id,
            "kb_match": "rule",
            "confidence": "high" if severity in ("critical", "high") else "medium",
            "scope": "endpoint" if port != "0" else "host",
        })
    if triage is not None:
        item["triage"] = triage
    return item


def _findings(run_id: str, label: str, mode: str, records: list[dict[str, Any]], *,
              redacted: bool = False, partial: bool = False,
              inline_kb: bool = False) -> dict[str, Any]:
    hosts = sorted({item["host"] for item in records})
    value: dict[str, Any] = {
        "schema_version": "2",
        "run_id": run_id,
        "label": label,
        "generated_utc": STAMP,
        "redacted": redacted,
        "mode": mode,
        "summary": {"total": len(records), "hosts": hosts, "coverage": []},
        "findings": records,
    }
    if inline_kb:
        value["kb"] = REPORT._kb_subset(records)
    if partial:
        value["partial"] = True
        value["errors"] = [{
            "type": "dispatcher_error",
            "path": "smb/<TARGET-1>/_dispatcher.log",
            "error": "synthetic dispatcher returned rc 4",
        }]
    return value


def _posture(run_id: str, label: str, hosts: dict[str, Any], domains: dict[str, Any], *,
             redacted: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "run_id": run_id,
        "label": label,
        "generated_utc": STAMP,
        "redacted": redacted,
        "hosts": hosts,
        "domains": domains,
    }


def _inventory_from_all_services() -> dict[str, Any]:
    source = FIXTURES / "services" / "all-services.xml"
    proc = subprocess.run(
        [sys.executable, str(NETWORK / "nmap-parse.py"), str(source), "--json"],
        check=True, capture_output=True, text=True,
    )
    return json.loads(proc.stdout)


def _synthetic_inventory() -> dict[str, Any]:
    hosts = ["linux-lab.invalid", "windows-lab.invalid", "dc-lab.invalid"]
    entries = [
        {"ip": hosts[0], "port": "22", "proto": "tcp", "service": "ssh",
         "categories": ["ssh"]},
        {"ip": hosts[1], "port": "445", "proto": "tcp", "service": "microsoft-ds",
         "categories": ["smb"]},
        {"ip": hosts[2], "port": "389", "proto": "tcp", "service": "ldap",
         "categories": ["ldap"]},
    ]
    return {
        "schema_version": "1",
        "tool": "aranum-nmap-parse",
        "tool_version": MANIFEST._tool_version(),
        "summary": {"hosts": 3, "hosts_up": 3, "hosts_with_open_ports": 3,
                    "open_ports": 3, "unknown": [],
                    "categories": {"ssh": ["linux-lab.invalid:22"],
                                   "smb": ["windows-lab.invalid:445"],
                                   "ldap": ["dc-lab.invalid:389"]}},
        "hosts": [{"ip": host, "state": "up"} for host in hosts],
        "entries": entries,
    }


def _render_placeholders(out: Path, label: str) -> None:
    (out / "report.md").write_text(f"# {label}\n\nSynthetic interop fixture.\n", encoding="utf-8")
    (out / "report.html").write_text(
        f"<!doctype html><title>{label}</title><p>Synthetic interop fixture.</p>\n",
        encoding="utf-8",
    )


def _fx1() -> Path:
    out = OUTPUT / "FX-1"
    out.mkdir(parents=True)
    run_id = "fx-1-run"
    _write_json(out / "inventory.json", _inventory_from_all_services())
    _write_json(out / "run-state.json", _run_state(run_id, [
        {"service": "inventory", "status": "done", "rc": 0},
    ]))
    _stage(out, "run", run_id, "complete", 0)
    MANIFEST.build_manifest(out)
    return out


def _fx2() -> Path:
    out = OUTPUT / "FX-2-v1"
    out.mkdir(parents=True)
    run_id = "fx-2-v1-run"
    _write_json(out / "inventory.json", _synthetic_inventory())
    _write_json(out / "run-state.json", _run_state(run_id, [
        {"service": "ssh", "status": "done", "rc": 0},
        {"service": "smb", "status": "done", "rc": 0},
        {"service": "ldap", "status": "done", "rc": 0},
    ]))
    records = [
        _finding("FX2-LOCAL-LINUX", "linux-lab.invalid", "linlocal", "medium",
                 "Local account labadmin on Linux host",
                 line="local labadmin context on linux-lab.invalid",
                 kb_id="LIN-ACCT-NOPASSWD"),
        _finding("FX2-LOCAL-WINDOWS", "windows-lab.invalid", "winlocal", "high",
                 "Local account labadmin on Windows host",
                 line="local labadmin context on windows-lab.invalid",
                 kb_id="WIN-UAC-LATFP"),
        _finding("FX2-DOMAIN", "dc-lab.invalid", "ldap", "high",
                 "Domain account lab-reader exposure", port="389",
                 line="domain lab-reader context in LAB.INVALID",
                 kb_id="kerberoastable-hash-es-captured-aada6591"),
        _finding("FX2-MACHINE", "windows-lab.invalid", "smb", "medium",
                 "Machine principal WINLAB$ observation", port="445",
                 line="machine WINLAB$ context", kb_id="AD-MAQ"),
        _finding("FX2-NULL", "windows-lab.invalid", "smb", "high",
                 "Null-session share listing", port="445",
                 line="null-session synthetic share exposure",
                 kb_id="bsigning-disabled-b-bsigning-enabled-but-not-required-b-65edaf46"),
    ]
    _write_json(out / "findings.json", _findings(
        run_id, "FX-2 v1", "mixed", records, inline_kb=True))
    _write_json(out / "posture.json", _posture(run_id, "FX-2 v1", {
        "linux-lab.invalid": {"os": "linux", "checks": [{"id": "LIN-SUDO", "status": "WARN"}]},
        "windows-lab.invalid": {"os": "windows", "checks": [{"id": "WIN-SMB", "status": "FAIL"}]},
    }, {"LAB.INVALID": {"checks": [{"id": "AD-LDAP-SIGN", "status": "WARN"}]}}))
    _render_placeholders(out, "FX-2 v1")
    _stage(out, "run", run_id, "complete", 0)
    _stage(out, "local", run_id, "complete", 0)
    _stage(out, "report", run_id, "complete", 0)
    MANIFEST.build_manifest(out)
    return out


def _fx2l() -> Path:
    out = OUTPUT / "FX-2L-v0"
    out.mkdir(parents=True)
    run_id = "fx-2l-v0-run"
    records = [
        _finding("FX2L-LINUX", "local-linux.invalid", "linlocal", "medium",
                 "Local Linux posture finding"),
        _finding("FX2L-WINDOWS", "local-windows.invalid", "winlocal", "high",
                 "Local Windows posture finding"),
    ]
    _write_json(out / "findings.json", _findings(run_id, "FX-2L v0", "bulk-enum", records))
    _write_json(out / "posture.json", _posture(run_id, "FX-2L v0", {
        "local-linux.invalid": {"os": "linux", "checks": [{"id": "LIN-PATH", "status": "WARN"}]},
        "local-windows.invalid": {"os": "windows", "checks": [{"id": "WIN-UAC", "status": "FAIL"}]},
    }, {}))
    _render_placeholders(out, "FX-2L v0")
    _stage(out, "local", run_id, "complete", 0)
    _stage(out, "report", run_id, "complete", 0)
    MANIFEST.build_manifest(out)
    return out


def _fx3() -> Path:
    out = OUTPUT / "FX-3"
    out.mkdir(parents=True)
    run_id = "fx-3-run"
    _write_json(out / "inventory.json", {
        **_synthetic_inventory(),
        "summary": {"hosts": 1, "hosts_up": 1, "hosts_with_open_ports": 1,
                    "open_ports": 1, "unknown": [], "categories": {"smb": ["<TARGET-1>:445"]}},
        "hosts": [{"ip": "<TARGET-1>", "state": "up"}],
        "entries": [{"ip": "<TARGET-1>", "port": "445", "proto": "tcp",
                     "service": "microsoft-ds", "categories": ["smb"]}],
    })
    _write_json(out / "run-state.json", _run_state(run_id, [
        {"service": "smb", "status": "failed", "rc": 4,
         "reason": "synthetic partial dispatcher"},
    ]))
    records = [_finding("FX3-REDACTED", "<TARGET-1>", "smb", "high",
                        "Redacted partial finding", port="445",
                        line="credential=<REDACTED>", triage="operator-review-required")]
    findings = _findings(run_id, "FX-3", "auto-enum", records, redacted=True, partial=True)
    findings["posture_quarantine"] = [{
        "type": "posture_quarantine", "host": "<TARGET-1>",
        "path": "smb/<TARGET-1>/posture.txt", "line": "<REDACTED>",
        "error": "synthetic malformed posture record",
    }]
    _write_json(out / "findings.json", findings)
    _write_json(out / "posture.json", _posture(run_id, "FX-3", {
        "<TARGET-1>": {"os": "windows", "checks": []},
    }, {}, redacted=True))
    _render_placeholders(out, "FX-3")
    _stage(out, "run", run_id, "partial", 4)
    _stage(out, "report", run_id, "partial", 1)
    MANIFEST.build_manifest(out)
    return out


def _fx4() -> Path:
    out = OUTPUT / "FX-4"
    out.mkdir(parents=True)
    _write_json(out / "inventory.json", _synthetic_inventory())
    _write_json(out / "run-state.json", _run_state("fx-4-run-1", [
        {"service": "smb", "status": "done", "rc": 0},
    ]))
    # Final tree after run 1 completed and run 2 minted, then was interrupted.
    _stage(out, "run", "fx-4-run-2", "running", None)
    MANIFEST.build_manifest(out)
    return out


def _fx4l() -> Path:
    out = OUTPUT / "FX-4L"
    out.mkdir(parents=True)
    records = [_finding("FX4L-OLD", "local-rerun.invalid", "linlocal", "medium",
                        "Prior local-only finding")]
    _write_json(out / "findings.json", _findings("fx-4l-run-1", "FX-4L prior", "bulk-enum", records))
    _write_json(out / "posture.json", _posture("fx-4l-run-1", "FX-4L prior", {
        "local-rerun.invalid": {"os": "linux", "checks": []},
    }, {}))
    _render_placeholders(out, "FX-4L prior")
    # Final tree after the prior local+report bundle and a new interrupted
    # local-only mint. Old report outputs remain visible but are unlisted.
    _stage(out, "local", "fx-4l-run-2", "running", None)
    MANIFEST.build_manifest(out)
    return out


def main() -> int:
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.mkdir(parents=True)
    bundles = [_fx1(), _fx2(), _fx2l(), _fx3(), _fx4(), _fx4l()]
    digests = {
        bundle.name: hashlib.sha256((bundle / "bundle-manifest.json").read_bytes()).hexdigest()
        for bundle in bundles
    }
    _write_json(OUTPUT / "manifest-digests.json", digests)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
