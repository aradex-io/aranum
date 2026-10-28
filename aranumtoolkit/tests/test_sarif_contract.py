#!/usr/bin/env python3
"""PLAN-002 A2 SARIF, ATT&CK, and cross-run logical-id contracts."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"
KERBEROASTABLE = "kerberoastable-hash-es-captured-aada6591"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_sarif_contract", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["report_mod_sarif_contract"] = mod
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def _finding(**updates):
    finding = {
        "rule_id": KERBEROASTABLE,
        "kb_id": KERBEROASTABLE,
        "service": "ldap",
        "severity": "high",
        "title": "Kerberoastable service account",
        "line": "synthetic lab observation",
        "host": "dc-lab.invalid",
        "port": "389",
        "evidence_path": "ldap/dc-lab.invalid/synthetic.txt",
        "finding_id": "AR-2-synthetic",
        "category": "ad",
        "confidence": "high",
        "scope": None,
    }
    finding.update(updates)
    return finding


def test_sarif_21_structure_tool_version_rules_and_locations():
    findings = [
        _finding(),
        _finding(rule_id="", kb_id="WIN-UAC-LATFP", service="winlocal",
                 host="workstation-lab.invalid", port="", severity="medium",
                 evidence_path="", category="winlocal", confidence="medium",
                 finding_id="AR-2-check"),
        _finding(rule_id="", kb_id="", service="custom", host="app-lab.invalid",
                 port="8443", finding_id="AR-2-custom"),
    ]
    sarif = R._to_sarif(findings, "A2 synthetic")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "aranum"
    assert driver["version"] == (REPO / "VERSION").read_text().strip()
    assert isinstance(driver["rules"], list)
    assert {rule["id"] for rule in driver["rules"]} == {
        KERBEROASTABLE, "WIN-UAC-LATFP",
    }
    descriptor = next(rule for rule in driver["rules"] if rule["id"] == KERBEROASTABLE)
    assert descriptor["name"] == descriptor["shortDescription"]["text"]
    assert descriptor["fullDescription"]["text"]
    assert descriptor["help"]["text"]
    assert descriptor["helpUri"].startswith("https://")

    assert [result["ruleId"] for result in run["results"]] == [
        KERBEROASTABLE, "WIN-UAC-LATFP", "custom",
    ]
    for finding, result in zip(findings, run["results"]):
        assert result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert isinstance(result["message"]["text"], str)
        assert result["locations"]
        logical = result["locations"][0]["logicalLocations"][0]
        assert logical["fullyQualifiedName"] == f"{finding['host']}:{finding['port']}"
        for key in ("category", "kb_id", "confidence", "scope"):
            assert key in result["properties"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] \
        == findings[0]["evidence_path"]


def test_kerberoastable_subset_entry_carries_attack_subtechnique():
    subset = R._kb_subset([_finding()])
    assert subset["classes"][KERBEROASTABLE]["attack_ids"] == ["T1558.003"]


def test_logical_id_is_stable_across_banner_change_with_rule_id():
    metadata = {"defaults": {}, "services": {}}
    first = R._structured_finding(
        "host-lab.invalid", "443", "https", "high", "Banner version 1",
        "https/host-lab.invalid/one.txt", metadata, protocol="tcp",
        rule_id="synthetic-banner-rule",
    )
    second = R._structured_finding(
        "host-lab.invalid", "443", "https", "high", "Banner version 2",
        "https/host-lab.invalid/two.txt", metadata, protocol="tcp",
        rule_id="synthetic-banner-rule",
    )
    assert first["logical_id"] == second["logical_id"]
    assert first["finding_id"] != second["finding_id"]
