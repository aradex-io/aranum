# tests/fixtures/bulk-enum/

Synthetic per-host fixtures for the J.3 smoke + unit tests. **No real-target
captures.** Each subdir mimics what `bulk-enum-linux.sh` writes for one host:
a `linenum.txt` (raw stdout from `linux/linenum-fast.sh`) plus a stub
`_meta.json` (the layout-detection markers `report.py` looks for).

The four hosts exercise each verdict tier — assertions live in
`tests/test_bulk_enum_report.py` and `tests/smoke.sh` section 13.

| Host  | Verdict tier | Trigger                                                     |
|---    |---           |---                                                          |
| web01 | CRITICAL     | `(ALL) NOPASSWD: /usr/bin/find` (sudo)                      |
| db02  | CRITICAL     | `python3 cap_setuid+ep` (capability) + `/usr/bin/perl` SUID |
| app03 | HIGH         | writable `/etc/systemd/system/app.service` + cred in history |
| old04 | MEDIUM       | non-gtfobin SUID + old kernel (5.x ≤ 5.15 / 4.x / 3.x)      |

These fixtures are intentionally minimal (1–10 lines of `linenum.txt`
output each). If a new severity rule lands in `report.py::_BULK_RULES`,
either extend an existing fixture's `linenum.txt` to exercise it OR
add a new host subdir here — and update the verdict table above.
