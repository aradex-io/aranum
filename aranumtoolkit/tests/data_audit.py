#!/usr/bin/env python3
"""data_audit.py — warn when embedded offline datasets look stale.

Provenance index: aranumtoolkit/docs/DATA-SOURCES.md. Invoked by `make data-audit`.
Exit 1 if any dataset is older than ~9 months. Date is stamped (offline/no-network).
"""
from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CUTOFF_DAYS = 9 * 30
TODAY = datetime.date.today()

CHECKS = [
    ("standalones/creds/default-creds.json", r'"updated"\s*:\s*"(\d{4}-\d{2}-\d{2})"'),
    ("standalones/linux/suid-gtfobins.sh",  r'updated:\s*(\d{4}-\d{2})'),
]


def main() -> int:
    stale = 0
    for rel, pat in CHECKS:
        path = REPO / rel
        try:
            text = path.read_text()
        except OSError:
            print(f"[!] {rel}: not found"); stale += 1; continue
        m = re.search(pat, text)
        if not m:
            print(f"[!] {rel}: no `updated` date found"); stale += 1; continue
        raw = m.group(1)
        d = datetime.date.fromisoformat(raw if len(raw) == 10 else raw + "-01")
        age = (TODAY - d).days
        is_stale = age > CUTOFF_DAYS
        print(f"[{'STALE' if is_stale else 'ok'}] {rel}: updated {raw} ({age}d ago)")
        stale += is_stale
    print("See aranumtoolkit/docs/DATA-SOURCES.md for refresh policy.")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
