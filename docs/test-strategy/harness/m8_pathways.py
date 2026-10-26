#!/usr/bin/env python3
"""M8 harness (PLAN-001 S4/S5): access pathways runnable via the --local layer,
counted by capability tier.

Written and first run at the S4 base (41860c8), before any S4 code existed.

Each pathway gets a PASS or FAIL. Tiers come from the pre-registered M8 row:
  full     local, linux-ssh, windows-winrm, windows-ssh   (whole collector)
  compact  wmiexec, smbexec, psexec                       (compact probe)
  desktop  rdp, vnc                                       (S5: native capture or assisted)

How each pathway is decided:
  local   A REAL self-scan: `aranum.py local --self -o <work>/self`. PASS iff
          <work>/self/linux/localhost/_meta.json has status OK and
          report.collect() over <work>/self yields posture for "localhost".
          --privesc-script replaces only the privesc collector (on a host whose
          SUID walk exceeds the time limit); the posture collector always runs
          for real. The script used is printed.
  others  A dry-run plan: `aranum.py local --targets <fixture> --dry-run ...`.
          This opens no connection. PASS iff the plan has a
          `PLAN|<host>|<os>|<pathway>|<tier>|<engine>|<note>` row with the
          expected os, tier and engine. A compact row must also say `fits=yes`.
          Only the operator-chosen exec method is in the plan, so each method is
          planned in its own invocation.

The `aranum run --local` wiring itself is asserted by the S4 unit tests
(argv partitioning), not here: this harness never runs a network scan.

Usage: m8_pathways.py <repo> --work DIR [--privesc-script PATH]
"""
import argparse, json, subprocess, sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("repo")
ap.add_argument("--work", required=True)
ap.add_argument("--privesc-script", default="")
a = ap.parse_args()
repo = Path(a.repo).resolve()
work = Path(a.work).resolve()
work.mkdir(parents=True, exist_ok=True)
cli = [sys.executable, str(repo / "aranum.py")]
fixture = work / "targets.txt"
fixture.write_text("# M8 fixture: documentation-range addresses, never contacted (dry-run)\n"
                   "192.0.2.11 os=linux\n192.0.2.21 os=windows\n")

def plan_rows(extra):
    out = work / ("plan-" + "-".join(x.strip("-") for x in extra if x.startswith("-"))[:60])
    p = subprocess.run(cli + ["local", "--targets", str(fixture), "--dry-run",
                              "-u", "m8user", "-p", "m8-not-a-secret", "-o", str(out)] + extra,
                       capture_output=True, text=True, timeout=120)
    rows = [l.split("|") for l in p.stdout.splitlines() if l.startswith("PLAN|")]
    return p.returncode, rows

def has(rows, host, os_, pathway, tier, engine, need_fit=False):
    for r in rows:
        if len(r) >= 7 and r[1:6] == [host, os_, pathway, tier, engine]:
            return (not need_fit) or "fits=yes" in r[6]
    return False

results = {}
# local (real)
self_out = work / "self"
cmd = cli + ["local", "--self", "-o", str(self_out)]
if a.privesc_script:
    cmd += ["--linux-script", a.privesc_script]
p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
ok = False
meta = self_out / "linux" / "localhost" / "_meta.json"
if p.returncode == 0 and meta.is_file():
    status = json.loads(meta.read_text()).get("status")
    sys.path.insert(0, str(repo / "aranumtoolkit" / "network"))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("report", repo / "aranumtoolkit/network/report.py")
        report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)
        col = report.collect(self_out, report._load_rules(None))
        ok = status == "OK" and bool(col.posture) and "localhost" in col.posture["hosts"]
    except Exception as e:  # noqa: BLE001
        print(f"local: collect failed: {type(e).__name__}: {e}", file=sys.stderr)
results[("full", "local")] = ok
print(f"local: rc={p.returncode} privesc_script={a.privesc_script or 'default'}")

rc, rows = plan_rows(["--transport", "ssh"])
results[("full", "linux-ssh")] = has(rows, "192.0.2.11", "linux", "ssh", "full", "bulk-enum-linux.sh")
results[("full", "windows-ssh")] = has(rows, "192.0.2.21", "windows", "ssh", "full", "bulk-enum-windows.py")
rc, rows = plan_rows(["--transport", "winrm"])
results[("full", "windows-winrm")] = has(rows, "192.0.2.21", "windows", "winrm", "full", "bulk-enum-windows.py")
for m in ("wmiexec", "smbexec", "psexec"):
    rc, rows = plan_rows(["--transport", "exec", "--win-exec", m, "--use-smb-admin"])
    results[("compact", m)] = has(rows, "192.0.2.21", "windows", m, "compact", "compact-probe", need_fit=True)
for d in ("rdp", "vnc"):
    rc, rows = plan_rows(["--transport", d, "--desktop-ok"])
    results[("desktop", d)] = any(len(r) >= 7 and r[3] == d and r[4] == "desktop" for r in rows)

for tier in ("full", "compact", "desktop"):
    names = [n for (t, n) in results if t == tier]
    passed = [n for n in names if results[(tier, n)]]
    print(f"M8 {tier}: {len(passed)}/{len(names)} {sorted(passed)}")
print("M8 total: " + str(sum(results.values())) + "/" + str(len(results)))
