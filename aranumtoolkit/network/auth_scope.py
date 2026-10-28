#!/usr/bin/env python3
"""Apply operator-declared authentication scope using the shipped mapping table."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

_MAP_PATH = Path(__file__).with_name("auth-scope-map.json")
with _MAP_PATH.open(encoding="utf-8") as _stream:
    _MAP = json.load(_stream)

_FAMILIES = ("nxc", "impacket", "ldap", "ssh", "other")
_SCOPES = ("local", "domain", "machine")


def family_for(tool_family: list[str]) -> str:
    """Return the mapping family for a dispatcher registry tool-family list."""
    names = {str(item).lower() for item in tool_family}
    if names & {"netexec", "nxc"}:
        return "nxc"
    if names & {"impacket", "wmiexec", "smbexec", "psexec"}:
        return "impacket"
    if names & {"ldapsearch", "ldap"}:
        return "ldap"
    if "ssh" in names:
        return "ssh"
    return "other"


def apply(family: str, scope: Optional[str], *, domain: str, user: str, host: str) -> dict:
    """Purely apply one declared scope rule; ``None`` is the identity mapping."""
    if family not in _FAMILIES:
        family = "other"
    if scope is not None and scope not in _SCOPES:
        raise ValueError(f"unknown auth scope: {scope}")
    result = {
        "extra_args": [],
        "username": user,
        "principal": None,
        "bind": None,
        "skip": False,
    }
    if scope is None:
        return result
    rule = _MAP["families"][family][scope]
    values = {"domain": domain, "user": user, "host": host}
    result["extra_args"] = [str(item).format(**values) for item in rule.get("extra_args", [])]
    suffix = str(rule.get("username_suffix", ""))
    result["username"] = user if not suffix or user.endswith(suffix) else user + suffix
    for field in ("principal", "bind"):
        if field in rule:
            result[field] = str(rule[field]).format(**values)
    result["skip"] = bool(rule.get("skip", False))
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=_FAMILIES)
    parser.add_argument("--scope", choices=_SCOPES)
    parser.add_argument("--domain", default="")
    parser.add_argument("--user", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--field", choices=("extra_args", "username", "principal", "bind", "skip"),
                        default="extra_args", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    mapped = apply(args.family, args.scope, domain=args.domain, user=args.user, host=args.host)
    value = mapped[args.field]
    if isinstance(value, list):
        for item in value:
            print(item)
    elif isinstance(value, bool):
        print("true" if value else "false")
    elif value is not None:
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
