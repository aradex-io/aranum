#!/usr/bin/env python3
"""Adversarial regressions for the 14SEP2026 R1 remediation phase."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
NETWORK = REPO / "aranumtoolkit" / "network"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REPORT = load("r1_report", NETWORK / "report.py")
PLAN = load("r1_plan", NETWORK / "plan.py")
MERGE = load("r1_merge", NETWORK / "merge-results.py")
RECCE = load("r1_recce", REPO / "aranumtoolkit" / "interop" / "aranum_to_recce.py")
WINDOWS = load("r1_windows_bulk", NETWORK / "bulk-enum-windows.py")


class TestReportIdentityAndSemantics(unittest.TestCase):
    def test_ephemeral_rule_cache_matches_bruteforce_thousands_of_times(self):
        for i in range(5000):
            token = f"TOKEN_{i}"
            rules = [(REPORT.re.compile(token), "critical")]
            self.assertEqual(REPORT._classify(token, rules), "critical")

    def test_metadata_priority_override_and_custom_rule_precedence(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "service-metadata.json").write_text(json.dumps({
                "services": {"redis": {"title": "LOCAL OVERRIDE", "priority": "P1"}}
            }))
            metadata = REPORT._load_service_metadata(out)
            finding = REPORT._structured_finding(
                "192.0.2.1", "6379", "redis", "critical", "CRITICAL Redis", "x.txt", metadata, "tcp")
            self.assertEqual(finding["title"], "LOCAL OVERRIDE")
            self.assertEqual(finding["priority"], "P1")
            rules_path = out / "rules.jsonl"
            rules_path.write_text('{"pattern":"OpenSSH","severity":"high"}\n')
            self.assertEqual(REPORT._classify("OpenSSH 9.8", REPORT._load_rules(rules_path)), "high")

        default_finding = REPORT._structured_finding(
            "192.0.2.1", "6379", "redis", "critical", "CRITICAL Redis", "x.txt",
            REPORT._load_service_metadata(), "tcp")
        self.assertEqual(default_finding["priority"], "P0")
        self.assertEqual(default_finding["confidence"], "high")

    def test_clean_coverage_dedup_and_ipv6_dispatcher_attribution(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            inventory = {
                "entries": [{"ip": "2001:db8::1", "port": 6379, "proto": "tcp",
                             "service": "redis", "categories": ["redis"]}]
            }
            (out / "inventory.json").write_text(json.dumps(inventory))
            host_dir = out / "redis" / "2001:db8::1_6379"
            host_dir.mkdir(parents=True)
            line = "CRITICAL: UNAUTH Redis [2001:db8::1]:6379"
            (host_dir / "finding.txt").write_text(line + "\n")
            (out / "redis" / "_dispatcher.log").write_text(line + "\n")
            findings = REPORT.finalize_findings(
                out, REPORT.walk_findings(out, REPORT._load_rules(None)))
            self.assertEqual(len(findings), 1)
            self.assertEqual((findings[0]["host"], findings[0]["port"], findings[0]["protocol"]),
                             ("2001:db8::1", "6379", "tcp"))
            self.assertEqual(len(findings[0]["evidence_paths"]), 2)

            (host_dir / "finding.txt").write_text("ordinary completed banner\n")
            (out / "redis" / "_dispatcher.log").unlink()
            clean = REPORT.finalize_findings(out, REPORT.walk_findings(out, REPORT._load_rules(None)))
            summary = REPORT._summary(clean, out)
            self.assertEqual(clean, [])
            self.assertIn("2001:db8::1", summary["hosts_assessed"])
            self.assertEqual(summary["coverage_counts"]["assessed_clean"], 1)

    def test_structural_endpoint_attribution_has_no_prefix_collisions(self):
        endpoints = [
            {"host": "10.0.0.1", "port": "6379", "protocol": "tcp", "service": "redis"},
            {"host": "10.0.0.10", "port": "6379", "protocol": "tcp", "service": "redis"},
            {"host": "2001:db8::1", "port": "6379", "protocol": "tcp", "service": "redis"},
            {"host": "2001:db8::2", "port": "6379", "protocol": "tcp", "service": "redis"},
        ]
        ipv4 = REPORT._endpoint_in_text("CRITICAL Redis 10.0.0.10:6379", endpoints, "redis")
        self.assertEqual(ipv4["host"], "10.0.0.10")
        self.assertFalse(REPORT._line_mentions_endpoint(
            "CRITICAL Redis 10.0.0.10:6379", "10.0.0.1", "6379"))
        bare_v6 = REPORT._endpoint_in_text(
            "CRITICAL Redis 2001:db8::1:6379", endpoints, "redis")
        bracketed_v6 = REPORT._endpoint_in_text(
            "CRITICAL Redis [2001:db8::2]:6379", endpoints, "redis")
        self.assertEqual((bare_v6["host"], bare_v6["port"]), ("2001:db8::1", "6379"))
        self.assertEqual((bracketed_v6["host"], bracketed_v6["port"]),
                         ("2001:db8::2", "6379"))
        self.assertIsNone(REPORT._endpoint_in_text(
            "CRITICAL Redis 10.0.0.100:6379", endpoints, "redis"))
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "inventory.json").write_text(json.dumps({"entries": [
                {"ip": endpoint["host"], "port": int(endpoint["port"]),
                 "proto": endpoint["protocol"], "service": "redis",
                 "categories": ["redis"]} for endpoint in endpoints]}))
            raw_findings = [REPORT._structured_finding(
                "(dispatcher)", "", "redis", "critical", line, "redis/_dispatcher.log",
                REPORT._load_service_metadata(), "") for line in (
                    "CRITICAL Redis 10.0.0.10:6379",
                    "CRITICAL Redis 2001:db8::1:6379",
                    "CRITICAL Redis [2001:db8::2]:6379")]
            finalized = REPORT.finalize_findings(out, raw_findings)
        self.assertEqual({finding["host"] for finding in finalized},
                         {"10.0.0.10", "2001:db8::1", "2001:db8::2"})

    def test_queue_failed_and_skipped_override_stale_success_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            entries = [
                {"ip": "192.0.2.20", "port": 22, "proto": "tcp",
                 "service": "ssh", "categories": ["ssh"]},
                {"ip": "192.0.2.21", "port": 22, "proto": "tcp",
                 "service": "ssh", "categories": ["ssh"]},
            ]
            (out / "inventory.json").write_text(json.dumps({"entries": entries}))
            svc = out / "ssh"; svc.mkdir()
            (svc / ".done").touch()
            (svc / ".rc").write_text("0\n")
            (svc / "stale.txt").write_text("HIGH stale evidence\n")
            states = [
                {"task_id": "a", "service": "ssh", "status": "failed",
                 "reason": "current dispatch failed",
                 "target": {"ip": "192.0.2.20", "port": 22, "proto": "tcp"}},
                {"task_id": "b", "service": "ssh", "status": "skipped",
                 "reason": "current dispatch skipped",
                 "target": {"ip": "192.0.2.21", "port": 22, "proto": "tcp"}},
            ]
            (out / "queue.state.jsonl").write_text(
                "".join(json.dumps(state) + "\n" for state in states))
            findings = [
                REPORT._structured_finding(entry["ip"], "22", "ssh", "high",
                                           "HIGH stale evidence", "ssh/stale.txt",
                                           REPORT._load_service_metadata(), "tcp")
                for entry in entries
            ]
            coverage = REPORT._coverage(out, findings)

        by_host = {record["host"]: record["status"] for record in coverage}
        self.assertEqual(by_host, {"192.0.2.20": "failed", "192.0.2.21": "skipped"})
        # Even a duplicate older success record cannot make Recce mark either
        # authoritative incomplete endpoint vuln_scanned/enumerated.
        doc = {"summary": {"coverage": [
            {"host": "192.0.2.20", "port": 22, "protocol": "tcp",
             "status": "assessed_clean"},
            *coverage,
        ]}}
        self.assertEqual(RECCE._successful_coverage(doc), set())
        self.assertEqual(RECCE._authoritative_incomplete_coverage(doc), {
            ("192.0.2.20", 22, "tcp"), ("192.0.2.21", 22, "tcp")})

    def test_authoritative_queue_keeps_unselected_endpoint_unassessed_despite_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "run"; service = out / "ssh"
            service.mkdir(parents=True)
            entries = [
                {"ip": "192.0.2.30", "port": 22, "proto": "tcp",
                 "service": "ssh", "categories": ["ssh"]},
                {"ip": "192.0.2.31", "port": 22, "proto": "tcp",
                 "service": "ssh", "categories": ["ssh"]},
            ]
            (out / "inventory.json").write_text(json.dumps({"entries": entries}))
            (out / "queue.state.jsonl").write_text(json.dumps({
                "task_id": "ssh::selected", "service": "ssh", "status": "done",
                "target": {"ip": "192.0.2.30", "port": 22, "proto": "tcp"}}) + "\n")
            (service / ".done").write_text("stale service completion\n")
            (service / ".rc").write_text("0\n")
            (service / "stale.txt").write_text("HIGH 192.0.2.31:22 stale finding\n")
            findings = [
                REPORT._structured_finding("192.0.2.30", "22", "ssh", "high",
                                           "HIGH selected", "ssh/selected.txt",
                                           REPORT._load_service_metadata(), "tcp"),
                REPORT._structured_finding("192.0.2.31", "22", "ssh", "high",
                                           "HIGH stale", "ssh/stale.txt",
                                           REPORT._load_service_metadata(), "tcp"),
            ]
            coverage = REPORT._coverage(out, findings)

        by_host = {record["host"]: record for record in coverage}
        self.assertEqual(by_host["192.0.2.30"]["status"], "confirmed")
        self.assertEqual(by_host["192.0.2.31"]["status"], "unassessed")
        self.assertEqual(by_host["192.0.2.31"]["execution_authority"], "queue")
        doc = {"summary": {"coverage": coverage}}
        self.assertEqual(RECCE._successful_coverage(doc), {("192.0.2.30", 22, "tcp")})
        self.assertIn(("192.0.2.31", 22, "tcp"),
                      RECCE._authoritative_incomplete_coverage(doc))

    def test_external_queue_parent_state_never_contaminates_local_current_run(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            out = base / "run"
            service = out / "ssh"
            service.mkdir(parents=True)
            entries = [
                {"ip": "192.0.2.40", "port": 22, "proto": "tcp",
                 "service": "ssh", "categories": ["ssh"]},
                {"ip": "192.0.2.41", "port": 22, "proto": "tcp",
                 "service": "ssh", "categories": ["ssh"]},
            ]
            (out / "inventory.json").write_text(json.dumps({"entries": entries}))
            (out / "run-state.json").write_text(json.dumps({
                "schema_version": 1, "run_id": "current-run",
                "execution_mode": "queue", "queue_authoritative": True,
                "services": []}))
            current = {
                "task_id": "ssh::current", "service": "ssh", "status": "done",
                "run_id": "current-run",
                "target": {"ip": "192.0.2.40", "port": 22, "proto": "tcp"}}
            stale = {
                "task_id": "ssh::stale", "service": "ssh", "status": "done",
                "run_id": "older-external-queue",
                "target": {"ip": "192.0.2.41", "port": 22, "proto": "tcp"}}
            (out / "queue.state.jsonl").write_text(json.dumps(current) + "\n")
            (base / "queue.state.jsonl").write_text(json.dumps(stale) + "\n")
            (service / ".done").write_text("stale service completion\n")

            coverage = REPORT._coverage(out, [])
            by_host = {record["host"]: record for record in coverage}
            self.assertEqual(by_host["192.0.2.40"]["status"], "assessed_clean")
            self.assertEqual(by_host["192.0.2.41"]["status"], "unassessed")

            # With no local file, the parent is a legacy fallback, but its old
            # run ID still cannot become authority for this current run.
            (out / "queue.state.jsonl").unlink()
            fallback = {record["host"]: record for record in REPORT._coverage(out, [])}
            self.assertEqual(fallback["192.0.2.40"]["status"], "unassessed")
            self.assertEqual(fallback["192.0.2.41"]["status"], "unassessed")

            # A parent snapshot bound to the current run remains a functioning
            # compatibility fallback when the local copy is unavailable.
            (base / "queue.state.jsonl").write_text(json.dumps(current) + "\n")
            compatible = {record["host"]: record for record in REPORT._coverage(out, [])}
            self.assertEqual(compatible["192.0.2.40"]["status"], "assessed_clean")
            self.assertEqual(compatible["192.0.2.41"]["status"], "unassessed")


class TestPlannerInventoryAndIteration(unittest.TestCase):
    class Parser:
        @staticmethod
        def dispatch(_path):
            base = {"ip": "192.0.2.53", "hostname": "", "port": 53,
                    "state": "open", "service": "domain", "product": "",
                    "version": "", "extrainfo": ""}
            return [dict(base, proto="tcp"), dict(base, proto="udp"), dict(base, proto="udp")]

        @staticmethod
        def categorize(_port, _service):
            return ["dns"]

        @staticmethod
        def parse_hosts(_path):
            return [{"ip": "192.0.2.53", "state": "up"},
                    {"ip": "192.0.2.99", "state": "up"}]

    def test_protocol_identity_dedup_precedes_disjoint_shards(self):
        cfg = {"dns": {"phases": {"1": {"name": "one", "description": "one"},
                                    "2": {"name": "two", "description": "two"}},
                       "manual": False, "dispatcher": "enum-dns.sh"}}
        defaults = {"risk": "read-safe", "cost": "low", "phases": {}}
        profile = {"include": ["*"], "exclude": []}
        all_tasks, summary = PLAN._build_tasks(self.Parser, Path("unused"), cfg, defaults,
                                               None, profile, None)
        shard1, _ = PLAN._build_tasks(self.Parser, Path("unused"), cfg, defaults,
                                      None, profile, (1, 2))
        shard2, _ = PLAN._build_tasks(self.Parser, Path("unused"), cfg, defaults,
                                      None, profile, (2, 2))
        self.assertEqual(len(all_tasks), 4)
        self.assertEqual({t["proto"] for t in all_tasks}, {"tcp", "udp"})
        self.assertFalse({t["task_id"] for t in shard1} & {t["task_id"] for t in shard2})
        self.assertEqual(summary["hosts_up"], 2)
        self.assertEqual(summary["hosts_with_open_ports"], 1)

    def test_parser_preserves_up_host_without_open_ports(self):
        xml = """<?xml version='1.0'?><nmaprun>
        <host><status state='up'/><address addr='192.0.2.1' addrtype='ipv4'/><ports/></host>
        <host><status state='up'/><address addr='192.0.2.2' addrtype='ipv4'/><ports>
        <port protocol='tcp' portid='22'><state state='open'/><service name='ssh'/></port>
        </ports></host></nmaprun>"""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "scan.xml"; path.write_text(xml)
            proc = subprocess.run([sys.executable, str(NETWORK / "nmap-parse.py"),
                                   str(path), "--json"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(proc.stdout)
        self.assertEqual(doc["summary"]["hosts_up"], 2)
        self.assertEqual(doc["summary"]["hosts_with_open_ports"], 1)
        self.assertEqual(len(doc["hosts"]), 2)

    def test_iterative_mines_prior_raw_smb_users_deterministically(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); raw = base / "raw"; out = base / "inputs"
            (raw / "smb").mkdir(parents=True)
            (raw / "smb" / "prior.txt").write_text("user: alice\nuser: alice\nuser: bob\n")
            (raw / "inventory.json").write_text(json.dumps({"entries": [{
                "ip": "192.0.2.44", "hostname": "", "port": 445, "proto": "tcp",
                "service": "microsoft-ds", "categories": ["smb"]}], "summary": {}}))
            cmd = ["bash", str(NETWORK / "iterative-enum.sh"), "--enum-output", str(raw),
                   "--output", str(out), "--dry-run", "--no-default-creds", "--no-fs-scrape"]
            first = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            users1 = (out / "smb" / "users.txt").read_text()
            second = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(users1, (out / "smb" / "users.txt").read_text())
            self.assertEqual(users1.splitlines(), ["alice", "bob"])


class TestOrchestratorStateMachine(unittest.TestCase):
    def make_fixture(self, root: Path, dispatcher_rc: int = 0):
        scripts = root / "network"; scripts.mkdir()
        for name in ("auto-enum.sh", "nmap-parse.py", "plan.py", "service-metadata.json",
                     "engagement-profiles.json", "_lib.sh", "enum-ssh.sh"):
            shutil.copy2(NETWORK / name, scripts / name)
        dispatcher = scripts / "enum-ssh.sh"
        if dispatcher_rc:
            real_dispatcher = scripts / "enum-ssh-real.sh"
            dispatcher.rename(real_dispatcher)
            dispatcher.write_text(
                "#!/usr/bin/env bash\n"
                f"bash {real_dispatcher!s} \"$@\"\n"
                f"exit {dispatcher_rc}\n")
        dispatcher.chmod(0o755)
        shims = root / "shims"; shims.mkdir()
        (shims / "nc").write_text(
            "#!/usr/bin/env bash\nprintf 'nc:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n"
            "printf 'SSH-2.0-OpenSSH_9.9\\n'\n")
        (shims / "ssh").write_text(
            "#!/usr/bin/env bash\nprintf 'ssh:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n"
            "printf 'Authentication methods: publickey\\n' >&2\nexit 1\n")
        for shim in shims.iterdir():
            shim.chmod(0o755)
        scan = root / "scan.xml"
        scan.write_text("""<?xml version='1.0'?><nmaprun><host><status state='up'/>
        <address addr='192.0.2.22' addrtype='ipv4'/><ports><port protocol='tcp' portid='22'>
        <state state='open'/><service name='ssh'/></port></ports></host>
        <host><status state='up'/><address addr='192.0.2.23' addrtype='ipv4'/><ports>
        <port protocol='tcp' portid='22'><state state='open'/><service name='ssh'/>
        </port></ports></host></nmaprun>""")
        env = {**os.environ, "PATH": f"{shims}:/usr/bin:/bin",
               "DISPATCH_PROBE_LOG": str(root / "probe.log")}
        return scripts, scan, env

    def make_ftp_fixture(self, root: Path, port: int = 21):
        scripts = root / "network"
        scripts.mkdir()
        for name in ("auto-enum.sh", "nmap-parse.py", "plan.py",
                     "service-metadata.json", "engagement-profiles.json",
                     "_lib.sh", "enum-ftp.sh"):
            shutil.copy2(NETWORK / name, scripts / name)
        shims = root / "shims"
        shims.mkdir()
        (shims / "timeout").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'timeout:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n"
            "shift\n"
            "if [ \"${1:-}\" = bash ]; then printf '220 fixture FTP\\n'; exit 0; fi\n"
            "exec \"$@\"\n")
        (shims / "curl").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'curl:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n"
            "case \"${1:-}\" in --version) printf 'curl fixture\\n';; "
            "*) printf 'drwxr-xr-x fixture\\n';; esac\n")
        (shims / "nmap").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'nmap:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n"
            "[ \"${1:-}\" != --version ] || printf 'nmap fixture\\n'\n")
        (shims / "nxc").write_text(
            "#!/usr/bin/env bash\n"
            "if [ \"${1:-}\" = --version ]; then printf 'nxc fixture\\n'; exit 0; fi\n"
            "input=$(paste -sd, -)\n"
            "printf 'nxc:%s|stdin=%s\\n' \"$*\" \"$input\" >> \"$DISPATCH_PROBE_LOG\"\n")
        for shim in shims.iterdir():
            shim.chmod(0o755)
        scan = root / "scan.xml"
        scan.write_text(f"""<?xml version='1.0'?><nmaprun><host><status state='up'/>
        <address addr='192.0.2.21' addrtype='ipv4'/><ports><port protocol='tcp' portid='{port}'>
        <state state='open'/><service name='ftp'/></port></ports></host></nmaprun>""")
        env = {**os.environ, "PATH": f"{shims}:/usr/bin:/bin",
               "DISPATCH_PROBE_LOG": str(root / "probe.log")}
        return scripts, scan, env

    def make_smb_fixture(self, root: Path):
        scripts = root / "network"
        scripts.mkdir()
        for name in ("auto-enum.sh", "nmap-parse.py", "plan.py",
                     "service-metadata.json", "engagement-profiles.json",
                     "_lib.sh", "enum-smb.sh"):
            shutil.copy2(NETWORK / name, scripts / name)
        shims = root / "shims"
        shims.mkdir()
        (shims / "nmap").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'nmap:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n"
            "[ \"${1:-}\" != --version ] || printf 'nmap fixture\\n'\n")
        for name in ("nxc", "enum4linux-ng", "smbmap", "rpcclient"):
            (shims / name).write_text(
                "#!/usr/bin/env bash\n"
                f"printf '{name}:%s\\n' \"$*\" >> \"$DISPATCH_PROBE_LOG\"\n")
        for shim in shims.iterdir():
            shim.chmod(0o755)
        scan = root / "scan.xml"
        scan.write_text("""<?xml version='1.0'?><nmaprun><host><status state='up'/>
        <address addr='192.0.2.45' addrtype='ipv4'/><ports><port protocol='tcp' portid='445'>
        <state state='open'/><service name='microsoft-ds'/></port></ports></host></nmaprun>""")
        env = {**os.environ, "PATH": f"{shims}:/usr/bin:/bin",
               "DISPATCH_PROBE_LOG": str(root / "probe.log")}
        return scripts, scan, env

    @staticmethod
    def task(task_id: str, phase: str, priority: int):
        return {"task_id": task_id, "service": "ssh", "phase": phase,
                "risk": "read-safe", "priority": priority,
                "target": {"ip": "192.0.2.22", "port": 22, "proto": "tcp"}}

    def test_dispatch_failure_propagates_and_malformed_queue_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); scripts, scan, env = self.make_fixture(root, 7)
            queue = root / "queue.jsonl"
            queue.write_text(json.dumps(self.task("ssh::one", "1", 900)) + "\n")
            out = root / "out"
            proc = subprocess.run(["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                                   "-o", str(out), "--queue", str(queue)],
                                  capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
            self.assertFalse((out / "ssh" / ".done").exists())
            run_state = json.loads((out / "run-state.json").read_text())
            self.assertEqual(run_state["services"][0]["status"], "failed")
            self.assertEqual(run_state["execution_mode"], "queue")
            self.assertTrue(run_state["queue_authoritative"])

            queue.write_text("{broken json\n")
            malformed = subprocess.run(["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                                        "-o", str(root / "bad"), "--queue", str(queue)],
                                       capture_output=True, text=True, timeout=30, env=env)
            self.assertNotEqual(malformed.returncode, 0)
            self.assertFalse((root / "bad" / "run-state.json").exists())

    def test_priority_filter_state_and_parallel_resume_are_current_run_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); scripts, scan, env = self.make_fixture(root, 0)
            queue = root / "queue.jsonl"
            queue.write_text("\n".join(json.dumps(item) for item in (
                self.task("ssh::phase1", "1", 900), self.task("ssh::phase2", "2", 100))) + "\n")
            out = root / "out"
            proc = subprocess.run(["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                                   "-o", str(out), "--queue", str(queue),
                                   "--skip-low-priority", "500", "--service-parallel", "2"],
                                  capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            task_dirs = list((out / "ssh").glob("task-*"))
            self.assertEqual(len(task_dirs), 1)
            context = json.loads((task_dirs[0] / "_task-context.json").read_text())
            self.assertEqual(context, {
                "phase": "1", "priority": 900, "protocol": "tcp", "risk": "read-safe",
                "schema_version": 1, "service": "ssh", "target": {
                    "ip": "192.0.2.22", "port": 22, "proto": "tcp"},
                "target_label": "192.0.2.22:22", "task_id": "ssh::phase1"})
            self.assertFalse(any(task_dirs[0].rglob("_key_only_*_22.txt")),
                             "phase-1 queue task executed phase-2 auth-posture logic")
            probes = (root / "probe.log").read_text().splitlines()
            self.assertEqual(len([line for line in probes if line.startswith("nc:")]), 1)
            self.assertTrue(all("192.0.2.22" in line for line in probes))
            self.assertIn("192.0.2.22 22", next(line for line in probes if line.startswith("nc:")))
            state = [json.loads(line) for line in (root / "queue.state.jsonl").read_text().splitlines()]
            self.assertEqual([item["task_id"] for item in state], ["ssh::phase1"])
            self.assertEqual(state[0]["target"]["proto"], "tcp")
            self.assertEqual((out / "queue.state.jsonl").read_text(),
                             (root / "queue.state.jsonl").read_text())
            raw_findings = list(REPORT.walk_findings(out, REPORT._DEFAULT_RULES))
            findings = REPORT.finalize_findings(out, raw_findings)
            self.assertTrue(all(f["host"] == "192.0.2.22" and f["protocol"] == "tcp"
                                for f in findings))
            coverage = {record["host"]: record["status"]
                        for record in REPORT._coverage(out, findings)}
            self.assertEqual(coverage["192.0.2.23"], "unassessed")

            (out / "ssh" / ".rc").write_text("9\n")
            resumed = subprocess.run(["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                                      "-o", str(out), "--queue", str(queue), "--resume",
                                      "--skip-low-priority", "500", "--service-parallel", "2"],
                                     capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
            self.assertIn("OK=0  FAIL=0  SKIP=1", resumed.stdout)

            queue.write_text(json.dumps(self.task("ssh::phase2-only", "2", 900)) + "\n")
            phase2 = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(root / "phase2"), "--queue", str(queue)],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(phase2.returncode, 0, phase2.stdout + phase2.stderr)
            phase2_dir = next((root / "phase2" / "ssh").glob("task-*"))
            self.assertTrue(any(phase2_dir.rglob("_key_only_*_22.txt")),
                            "phase-2 queue task did not execute auth-posture logic")

    def test_explicit_empty_fails_filtered_zero_succeeds_and_exact_duplicate_is_one_task(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); scripts, scan, env = self.make_fixture(root)
            queue = root / "queue.jsonl"
            queue.write_text("\n")
            empty = subprocess.run(["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                                    "-o", str(root / "empty"), "--queue", str(queue)],
                                   capture_output=True, text=True, timeout=30, env=env)
            self.assertNotEqual(empty.returncode, 0)
            self.assertIn("explicit queue contains no records", empty.stderr)

            low = self.task("ssh::low", "2", 100)
            queue.write_text(json.dumps(low) + "\n")
            filtered = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(root / "filtered"), "--queue", str(queue),
                 "--skip-low-priority", "500"], capture_output=True, text=True,
                timeout=30, env=env)
            self.assertEqual(filtered.returncode, 0, filtered.stdout + filtered.stderr)
            self.assertIn("selected unique tasks: 0", filtered.stdout)
            self.assertEqual((root / "queue.state.jsonl").read_text(), "")
            filtered_state = json.loads((root / "filtered" / "run-state.json").read_text())
            self.assertEqual(filtered_state["execution_mode"], "queue")
            self.assertTrue(filtered_state["queue_authoritative"])

            item = self.task("ssh::duplicate", "1", 900)
            queue.write_text(json.dumps(item) + "\n" + json.dumps(item) + "\n")
            duplicate = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(root / "duplicate"), "--queue", str(queue)],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(duplicate.returncode, 0, duplicate.stdout + duplicate.stderr)
            duplicate_state = (root / "queue.state.jsonl").read_text().splitlines()
            self.assertEqual(len(duplicate_state), 1)
            self.assertEqual(len(list((root / "duplicate" / "ssh").glob("task-*"))), 1)

    def test_common_dispatcher_contract_rejects_service_wide_target_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); scripts, _scan, env = self.make_fixture(root)
            targets = root / "targets.txt"
            targets.write_text("192.0.2.22:22\n192.0.2.23:22\n")
            proc = subprocess.run(
                ["bash", str(scripts / "enum-ssh.sh"), "--targets", str(targets),
                 "--output", str(root / "out"), "--task-id", "ssh::one",
                 "--task-service", "ssh", "--task-phase", "1", "--task-protocol", "tcp",
                 "--task-risk", "read-safe", "--task-priority", "900",
                 "--task-target", "192.0.2.22:22"], capture_output=True, text=True,
                timeout=30, env=env)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("task target constraint mismatch", proc.stdout + proc.stderr)

    def test_real_ftp_queue_tasks_execute_distinct_phase_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scripts, scan, env = self.make_ftp_fixture(root, 2121)
            env = {**env, "ENUM_USER": "fixture-user", "ENUM_PASS": "fixture-pass"}
            queue = root / "queue.jsonl"
            tasks = ({"task_id": "ftp::phase1", "service": "ftp", "phase": "1",
                      "risk": "read-safe", "priority": 700,
                      "target": {"ip": "192.0.2.21", "port": 2121, "proto": "tcp"}},
                     {"task_id": "ftp::phase2", "service": "ftp", "phase": "2",
                      "risk": "read-safe", "priority": 680,
                      "target": {"ip": "192.0.2.21", "port": 2121, "proto": "tcp"}})
            queue.write_text("\n".join(json.dumps(task) for task in tasks) + "\n")
            out = root / "out"
            proc = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(out), "--queue", str(queue),
                 "-u", "fixture-user", "-p", "fixture-pass"],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

            evidence = {}
            for task_dir in (out / "ftp").glob("task-*"):
                context = json.loads((task_dir / "_task-context.json").read_text())
                evidence[context["phase"]] = (task_dir / "192.0.2.21" / "ftp.txt").read_text()
            self.assertEqual(set(evidence), {"1", "2"})
            self.assertIn("220 fixture FTP", evidence["1"])
            self.assertNotIn("anonymous listing", evidence["1"])
            self.assertIn("anonymous listing", evidence["2"])
            self.assertIn("drwxr-xr-x fixture", evidence["2"])
            self.assertNotIn("--- banner ---", evidence["2"])
            states = [json.loads(line) for line in (out / "queue.state.jsonl").read_text().splitlines()]
            self.assertEqual({(item["phase"], item["status"]) for item in states},
                             {("1", "done"), ("2", "done")})
            actual_nmap = [line for line in (root / "probe.log").read_text().splitlines()
                           if line.startswith("nmap:-Pn")]
            self.assertEqual(len(actual_nmap), 1)
            self.assertRegex(actual_nmap[0], r"-p\s*2121(?:\s|$)")
            actual_nxc = [line for line in (root / "probe.log").read_text().splitlines()
                          if line.startswith("nxc:ftp ")]
            self.assertEqual(len(actual_nxc), 1)
            self.assertIn("--port 2121", actual_nxc[0])
            self.assertIn("stdin=192.0.2.21", actual_nxc[0])
            self.assertNotRegex(actual_nxc[0], r"--port 21(?:\s|$)")

            unsupported = dict(tasks[0], task_id="ftp::phase9", phase="9")
            queue.write_text(json.dumps(unsupported) + "\n")
            refused_out = root / "refused"
            refused = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(refused_out), "--queue", str(queue)],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(refused.returncode, 3, refused.stdout + refused.stderr)
            self.assertIn("unsupported queue phase for ftp: 9", refused.stdout + refused.stderr)
            self.assertFalse((refused_out / "ftp").exists(),
                             "unsupported constrained phase reached the dispatcher")

    def test_real_ftp_credential_checks_group_exact_endpoints_by_selected_port(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scripts, _scan, env = self.make_ftp_fixture(root, 2121)
            env = {**env, "ENUM_USER": "fixture-user", "ENUM_PASS": "fixture-pass"}
            targets = root / "ftp-targets.txt"
            targets.write_text(
                "192.0.2.21:2121\n"
                "192.0.2.22:2021\n"
                "192.0.2.23:2121\n")
            proc = subprocess.run(
                ["bash", str(scripts / "enum-ftp.sh"), "--targets", str(targets),
                 "--output", str(root / "out")],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

            nxc_calls = [line for line in (root / "probe.log").read_text().splitlines()
                         if line.startswith("nxc:ftp ")]
            self.assertEqual(len(nxc_calls), 2)
            by_port = {re.search(r"--port (\d+)", line).group(1): line
                       for line in nxc_calls}
            self.assertEqual(set(by_port), {"2021", "2121"})
            self.assertIn("stdin=192.0.2.22", by_port["2021"])
            self.assertIn("stdin=192.0.2.21,192.0.2.23", by_port["2121"])
            self.assertTrue(all(not re.search(r"--port 21(?:\s|$)", line)
                                for line in nxc_calls))

    def test_real_smb_is_one_monolithic_task_and_staged_tasks_fail_predispatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scripts, scan, env = self.make_smb_fixture(root)
            queue = root / "queue.jsonl"
            canonical = {"task_id": "smb::192.0.2.45:445/tcp:all",
                         "service": "smb", "phase": "all",
                         "risk": "read-safe", "priority": 840,
                         "target": {"ip": "192.0.2.45", "port": 445,
                                    "proto": "tcp"}}
            queue.write_text(json.dumps(canonical) + "\n")
            out = root / "canonical"
            proc = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(out), "--queue", str(queue)],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            task_dirs = list((out / "smb").glob("task-*"))
            self.assertEqual(len(task_dirs), 1)
            context = json.loads((task_dirs[0] / "_task-context.json").read_text())
            self.assertEqual((context["service"], context["phase"], context["priority"]),
                             ("smb", "all", 840))
            self.assertIn("nmap smb-vuln-* scripts", (task_dirs[0] / "_dispatcher.log").read_text())
            state = [json.loads(line) for line in (out / "queue.state.jsonl").read_text().splitlines()]
            self.assertEqual([(item["task_id"], item["phase"], item["status"])
                              for item in state], [(canonical["task_id"], "all", "done")])

            probe_before = (root / "probe.log").read_text()
            for phase in ("1", "2"):
                staged = dict(canonical, task_id=f"smb::unsupported:{phase}", phase=phase)
                queue.write_text(json.dumps(staged) + "\n")
                refused_out = root / f"refused-{phase}"
                refused = subprocess.run(
                    ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                     "-o", str(refused_out), "--queue", str(queue)],
                    capture_output=True, text=True, timeout=30, env=env)
                self.assertEqual(refused.returncode, 3, refused.stdout + refused.stderr)
                self.assertIn(f"unsupported queue phase for smb: {phase}",
                              refused.stdout + refused.stderr)
                self.assertFalse((refused_out / "smb").exists())
            self.assertEqual((root / "probe.log").read_text(), probe_before,
                             "unsupported SMB phases invoked a dispatcher tool")

    def test_successful_nonqueue_run_archives_stale_queue_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scripts, scan, env = self.make_ftp_fixture(root)
            out = root / "out"
            queue = root / "queue.jsonl"
            queue.write_text(json.dumps({
                "task_id": "ftp::old", "service": "ftp", "phase": "1",
                "risk": "read-safe", "priority": 700,
                "target": {"ip": "192.0.2.21", "port": 21, "proto": "tcp"}
            }) + "\n")
            queued = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(out), "--queue", str(queue)],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(queued.returncode, 0, queued.stdout + queued.stderr)
            stale = (out / "queue.state.jsonl").read_text()
            self.assertEqual((root / "queue.state.jsonl").read_text(), stale)

            proc = subprocess.run(
                ["bash", str(scripts / "auto-enum.sh"), "-i", str(scan),
                 "-o", str(out), "--only", "ftp"],
                capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertFalse((out / "queue.state.jsonl").exists())
            self.assertFalse((root / "queue.state.jsonl").exists())
            nonqueue_state = json.loads((out / "run-state.json").read_text())
            self.assertEqual(nonqueue_state["execution_mode"], "service-batch")
            self.assertFalse(nonqueue_state["queue_authoritative"])
            archives = (list(out.glob("queue.state.jsonl.stale-*")) +
                        list(root.glob("queue.state.jsonl.stale-*")))
            self.assertEqual(len(archives), 2)
            self.assertTrue(all(path.read_text() == stale for path in archives))
            self.assertIn("archived stale queue authority", (out / "run.log").read_text())


class TestDiffMergeAndInterop(unittest.TestCase):
    def test_diff_identity_detects_port_protocol_and_long_tail(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); previous = base / "previous"; current = base / "current"
            previous.mkdir(); current.mkdir()
            common = {"host": "192.0.2.2", "service": "http", "severity": "high",
                      "line": "A" * 140 + "old", "port": "80", "protocol": "tcp"}
            changed = dict(common, port="443", protocol="udp", line="A" * 140 + "new")
            for path, finding in ((previous, common), (current, changed)):
                (path / "findings.json").write_text(json.dumps({"label": path.name,
                    "summary": {"hosts": ["192.0.2.2"]}, "findings": [finding]}))
            proc = subprocess.run(["bash", str(NETWORK / "autoenum-diff.sh"),
                                   str(previous), str(current)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("192.0.2.2:443/udp", proc.stdout)

    def test_merge_copy_failure_has_no_published_path_and_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); source = base / "source"; output = base / "output"
            (source / "evidence").mkdir(parents=True)
            (source / "evidence" / "x.txt").write_text("evidence")
            (source / "findings.json").write_text(json.dumps({"schema_version": "2",
                "redacted": True, "findings": [{"host": "<TARGET-1>", "port": "53",
                "protocol": "udp", "service": "dns", "severity": "high", "line": "x",
                "evidence_path": "evidence/x.txt"}]}))
            output.mkdir()
            with mock.patch.object(MERGE.shutil, "copy2", side_effect=OSError("fixture")):
                findings, meta = MERGE._merge_findings([source], output)
            self.assertEqual(findings[0]["evidence_path"], "")
            self.assertEqual(findings[0]["evidence_status"], "copy_failed")
            self.assertFalse(meta["complete"])
            self.assertEqual(meta["redaction_state"], "redacted")

    def test_recce_discovery_protocol_and_execution_state_contract(self):
        with tempfile.TemporaryDirectory() as td:
            session = Path(td) / "session"; reports = session / "reports"; raw = session / "raw"
            inputs = session / "inputs"; reports.mkdir(parents=True); raw.mkdir(); inputs.mkdir()
            findings = reports / "findings.json"; findings.write_text('{"findings":[]}')
            (raw / "inventory.json").write_text('{"entries":[]}')
            (inputs / "scan.gnmap").write_text("Host: 192.0.2.1 () Status: Up\n")
            discovered = RECCE._autodiscover(str(findings))
            self.assertEqual(discovered["inventory"], str(raw / "inventory.json"))
            self.assertEqual(discovered["nmap"], str(inputs / "scan.gnmap"))

        inventory = [{"ip": "192.0.2.9", "port": 161, "protocol": "udp",
                      "service": "snmp", "categories": ["snmp"]}]
        self.assertEqual(RECCE._resolve_finding_endpoint(
            {"host": "192.0.2.9", "port": "161", "service": "snmp"}, inventory), (161, "udp"))
        ambiguous = inventory + [dict(inventory[0], protocol="tcp")]
        self.assertEqual(RECCE._resolve_finding_endpoint(
            {"host": "192.0.2.9", "port": "161", "service": "snmp"}, ambiguous), (161, ""))
        states = RECCE._successful_coverage({"summary": {"coverage": [
            {"host": "192.0.2.9", "port": 161, "protocol": "udp", "status": "done"},
            {"host": "192.0.2.9", "port": 22, "protocol": "tcp", "status": "failed"},
            {"host": "192.0.2.9", "port": 80, "protocol": "tcp", "status": "skipped"}]}})
        self.assertEqual(states, {("192.0.2.9", 161, "udp")})

    def test_recce_protocol_absent_inventory_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            inventory = Path(td) / "inventory.json"
            inventory.write_text(json.dumps({"entries": [
                {"ip": "192.0.2.40", "port": 53, "service": "domain",
                 "categories": ["dns"]},
                {"ip": "192.0.2.41", "port": 53, "proto": "udp",
                 "service": "domain", "categories": ["dns"]},
            ]}))
            records = RECCE._ports_from_inventory(str(inventory))
        self.assertEqual([(r["ip"], r["port"], r["protocol"]) for r in records],
                         [("192.0.2.41", 53, "udp")])
        self.assertEqual(RECCE._resolve_finding_endpoint(
            {"host": "192.0.2.40", "port": "53", "service": "dns"}, records),
            (53, ""))


class TestBulkExecutionState(unittest.TestCase):
    def test_windows_endpoint_keys_state_and_worker_bounds(self):
        a = WINDOWS.Target("alice", "192.0.2.4", 5985, "alice@192.0.2.4")
        b = WINDOWS.Target("bob", "192.0.2.4", 5986, "bob@192.0.2.4:5986")
        self.assertNotEqual(WINDOWS.endpoint_key(a), WINDOWS.endpoint_key(b))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); targets = root / "targets.txt"
            targets.write_text("alice@192.0.2.4:5985\nbob@192.0.2.4:5986\n")
            out = root / "out"
            with mock.patch.object(sys, "argv", ["bulk-enum-windows.py", "--targets", str(targets),
                                                   "-o", str(out), "--dry-run", "-P", "1"]):
                self.assertEqual(WINDOWS.main(), 0)
            manifest = json.loads((out / "endpoints.json").read_text())
            self.assertEqual(len({e["endpoint_id"] for e in manifest["endpoints"]}), 2)
            self.assertFalse((out / "192.0.2.4").exists())
            with mock.patch.object(sys, "argv", ["bulk-enum-windows.py", "--targets", str(targets),
                                                   "-o", str(root / "bad"), "--dry-run", "-P", "0"]):
                self.assertEqual(WINDOWS.main(), 2)
            with mock.patch.object(sys, "argv", ["bulk-enum-windows.py", "--targets", str(targets),
                                                   "-o", str(root / "max"), "--dry-run", "-P", "16"]):
                self.assertEqual(WINDOWS.main(), 0)
            with mock.patch.object(sys, "argv", ["bulk-enum-windows.py", "--targets", str(targets),
                                                   "-o", str(root / "over"), "--dry-run", "-P", "17"]):
                self.assertEqual(WINDOWS.main(), 2)

    def test_linux_endpoint_manifest_and_worker_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); targets = root / "targets.txt"
            targets.write_text("alice@192.0.2.4:22\nbob@192.0.2.4:2222\n")
            out = root / "out"
            cmd = ["bash", str(NETWORK / "bulk-enum-linux.sh"), "--targets", str(targets),
                   "--output", str(out), "--dry-run", "--no-preflight", "-P", "1"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            rows = [line for line in (out / "endpoints.tsv").read_text().splitlines()
                    if not line.startswith("#")]
            self.assertEqual(len(rows), 2)
            self.assertEqual(len({row.split("\t")[0] for row in rows}), 2)
            invalid = subprocess.run(cmd[:-1] + ["0"], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(invalid.returncode, 0)
            maximum = subprocess.run(cmd[:-1] + ["16"], capture_output=True, text=True, timeout=30)
            self.assertEqual(maximum.returncode, 0, maximum.stdout + maximum.stderr)
            too_many = subprocess.run(cmd[:-1] + ["17"], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(too_many.returncode, 0)

    def test_legacy_resume_is_unique_only_for_both_bulk_runners(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Linux: one endpoint migrates; two endpoints sharing a host refuse.
            targets = root / "linux-one.txt"; targets.write_text("alice@192.0.2.8:22\n")
            out = root / "linux-out"; (out / "192.0.2.8").mkdir(parents=True)
            (out / "192.0.2.8" / ".done").touch()
            base = ["bash", str(NETWORK / "bulk-enum-linux.sh"), "--targets", str(targets),
                    "--output", str(out), "--dry-run", "--no-preflight", "--resume", "-P", "1"]
            proc = subprocess.run(base, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            endpoint_id = (out / "endpoints.tsv").read_text().splitlines()[1].split("\t")[0]
            self.assertTrue((out / endpoint_id / ".done").exists())
            self.assertFalse((out / "192.0.2.8").exists())

            targets.write_text("alice@192.0.2.8:22\nbob@192.0.2.8:2222\n")
            ambiguous = root / "linux-ambiguous"; (ambiguous / "192.0.2.8").mkdir(parents=True)
            refused = subprocess.run(base[:5] + [str(ambiguous)] + base[6:],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("ambiguous legacy resume", refused.stdout + refused.stderr)

            # Windows follows the same conservative migration policy.
            win_targets = root / "windows-one.txt"; win_targets.write_text("alice@win.example:5985\n")
            win_out = root / "windows-out"; (win_out / "win.example").mkdir(parents=True)
            (win_out / "win.example" / ".done").touch()
            with mock.patch.object(sys, "argv", ["bulk-enum-windows.py", "--targets",
                    str(win_targets), "-o", str(win_out), "--dry-run", "--resume", "-P", "1"]):
                self.assertEqual(WINDOWS.main(), 0)
            win_endpoint = WINDOWS.endpoint_key(
                WINDOWS.Target("alice", "win.example", 5985, "alice@win.example:5985"))
            self.assertTrue((win_out / win_endpoint / ".done").exists())

            win_targets.write_text("alice@win.example:5985\nbob@win.example:5986\n")
            win_ambiguous = root / "windows-ambiguous"; (win_ambiguous / "win.example").mkdir(parents=True)
            with mock.patch.object(sys, "argv", ["bulk-enum-windows.py", "--targets",
                    str(win_targets), "-o", str(win_ambiguous), "--dry-run", "--resume", "-P", "1"]):
                self.assertEqual(WINDOWS.main(), 2)

    def test_nonresume_failure_invalidates_prior_success_markers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Windows direct worker: an authenticated remote error cannot leave
            # a success marker from a preceding invocation.
            target = WINDOWS.Target("alice", "win.example", 5985, "raw")
            out = root / "win"; endpoint = out / WINDOWS.endpoint_key(target)
            endpoint.mkdir(parents=True); (endpoint / ".done").touch()
            args = mock.Mock(resume=False, dry_run=False, auth="ntlm", tls=False,
                             script=Path("fixture.ps1"))
            failure = WINDOWS.TransportResult(1, "partial", "failed", "REMOTE_ERR", "failed")
            with mock.patch.object(WINDOWS.WinRMTransport, "run", return_value=failure):
                result = WINDOWS.run_one_host(target, "Write-Output x", args, out, ["winrm"])
            self.assertEqual(result.status, "REMOTE_ERR")
            self.assertFalse((endpoint / ".done").exists())

            # Linux real shell state path with a local non-network ssh shim.
            targets = root / "linux.txt"; targets.write_text("alice@linux.example:22\n")
            linux_out = root / "linux"
            dry = ["bash", str(NETWORK / "bulk-enum-linux.sh"), "--targets", str(targets),
                   "--output", str(linux_out), "--dry-run", "--no-preflight", "-P", "1"]
            self.assertEqual(subprocess.run(dry, capture_output=True, text=True).returncode, 0)
            linux_endpoint = (linux_out / "endpoints.tsv").read_text().splitlines()[1].split("\t")[0]
            (linux_out / linux_endpoint / ".done").touch()
            bindir = root / "bin"; bindir.mkdir()
            ssh = bindir / "ssh"; ssh.write_text("#!/bin/sh\nexit 1\n"); ssh.chmod(0o755)
            env = dict(os.environ); env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
            actual = subprocess.run([arg for arg in dry if arg != "--dry-run"], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(actual.returncode, 0, actual.stdout + actual.stderr)
            self.assertFalse((linux_out / linux_endpoint / ".done").exists())
            self.assertEqual(json.loads((linux_out / linux_endpoint / "_meta.json").read_text())["status"],
                             "REMOTE_ERR")


if __name__ == "__main__":
    unittest.main()
