#!/usr/bin/env python3
"""Generate the deterministic PLAN-002 dispatcher registry."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_OUTPUT = HERE / "dispatchers.json"

# Family names are stable consumer-facing labels. Patterns intentionally cover
# executable spellings used by the dispatcher fleet (including common aliases).
TOOL_FAMILIES = (
    ("nxc", r"\b(?:nxc|netexec)\b"),
    ("impacket", r"\b(?:impacket-[a-z0-9_-]+|GetUserSPNs\.py|GetNPUsers\.py|"
                 r"wmiexec\.py|smbexec\.py|psexec\.py|ntlmrelayx\.py)\b"),
    ("ldapsearch", r"\bldapsearch\b"),
    ("ssh", r"\b(?:ssh|sshpass|ssh-keyscan)\b"),
    ("nmap", r"\bnmap\b"),
    ("curl", r"\bcurl\b"),
    ("openssl", r"\bopenssl\b"),
    ("samba", r"\b(?:smbclient|rpcclient|net|smbcacls)\b"),
    ("enum4linux", r"\benum4linux(?:-ng)?\b"),
    ("smbmap", r"\bsmbmap\b"),
    ("dns", r"\b(?:dig|nslookup|dnsrecon|fierce)\b"),
    ("snmp", r"\b(?:snmpwalk|snmpget|onesixtyone)\b"),
    ("http-enum", r"\b(?:ffuf|gobuster|feroxbuster|nikto|nuclei|whatweb)\b"),
    ("database-client", r"\b(?:mysql|psql|redis-cli|mongosh?|cqlsh|sqlcmd)\b"),
)


def _tool_version() -> str:
    version = REPO / "VERSION"
    if version.is_file():
        value = version.read_text(encoding="utf-8").strip()
        if value:
            return value
    return "unknown"


def _alias_of(script: Path) -> Optional[str]:
    if not script.is_symlink():
        return None
    target = script.resolve().name
    if target.startswith("enum-") and target.endswith(".sh"):
        return target[5:-3]
    return Path(target).stem


def _tool_family(text: str) -> list[str]:
    shell = "\n".join(line for line in text.splitlines()
                      if not line.lstrip().startswith("#"))
    return sorted(name for name, pattern in TOOL_FAMILIES
                  if re.search(pattern, shell, flags=re.IGNORECASE))


def build_registry() -> dict:
    """Return one generated record for every enum-*.sh dispatcher."""
    records = []
    for script in sorted(HERE.glob("enum-*.sh"), key=lambda path: path.name):
        name = script.name[5:-3]
        text = script.read_text(encoding="utf-8", errors="replace")
        records.append({
            "name": name,
            "script": script.name,
            "alias_of": _alias_of(script),
            "category": name,
            "uses_credentials": "ENUM_USER" in text,
            "tool_family": _tool_family(text),
        })
    return {
        "schema_version": "1",
        "tool": "aranum",
        "tool_version": _tool_version(),
        "dispatchers": records,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    payload = json.dumps(build_registry(), indent=2, sort_keys=False) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
