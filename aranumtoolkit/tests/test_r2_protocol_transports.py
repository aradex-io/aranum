"""Offline R2 protocol/endpoint regressions; every network tool is shimmed."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _run(script: str, tmp_path: Path, targets: str, shims: dict[str, str], *, env=None):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in shims.items():
        _exe(bindir / name, body)
    target_file = tmp_path / "targets.txt"
    target_file.write_text(targets)
    out = tmp_path / "out"
    run_env = dict(os.environ)
    run_env.update({"PATH": f"{bindir}:/usr/bin:/bin", "NO_COLOR": "1"})
    if env:
        run_env.update(env)
    proc = subprocess.run(
        ["bash", str(NET / script), "--targets", str(target_file), "--output", str(out)],
        capture_output=True, text=True, timeout=30, env=run_env,
    )
    return proc, out


def test_ssh_keeps_banner_auth_and_audit_evidence_per_port(tmp_path):
    nc = '''
port="${@: -1}"
case "$port" in 22) echo 'SSH-2.0-OpenSSH_8.6p1' ;; 2222) echo 'SSH-2.0-OpenSSH_9.9p1' ;; esac
'''
    ssh = '''
port=22
while [ "$#" -gt 0 ]; do
  [ "$1" = -p ] && { port="$2"; shift 2; continue; }
  shift
done
case "$port" in
  22) echo 'authentication methods: publickey' >&2 ;;
  2222) echo 'authentication methods: publickey,password' >&2 ;;
esac
exit 255
'''
    audit = '''
port=22
while [ "$#" -gt 0 ]; do
  [ "$1" = -p ] && { port="$2"; break; }
  shift
done
echo "audit-port=$port"
'''
    nxc = '''
cat >/dev/null
echo "auth-user-port:$*"
'''
    proc, out = _run("enum-ssh.sh", tmp_path, "10.0.0.7:22\n10.0.0.7:2222\n",
                     {"nc": nc, "ssh": ssh, "ssh-audit": audit, "nxc": nxc},
                     env={"ENUM_USER": "alice", "ENUM_PASS": "test-only"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    host = out / "10.0.0.7"
    assert "OpenSSH_8.6" in (host / "banner_22.txt").read_text()
    assert "OpenSSH_9.9" in (host / "banner_2222.txt").read_text()
    assert "audit-port=22" in (host / "ssh-audit_22.txt").read_text()
    assert "audit-port=2222" in (host / "ssh-audit_2222.txt").read_text()
    user_tag = "uhex_616c696365"
    assert (host / f"_key_only_{user_tag}_22.txt").exists()
    assert not (host / f"_key_only_{user_tag}_2222.txt").exists()
    assert "--port 22 -u alice" in (host / f"nxc_ssh_{user_tag}_22.txt").read_text()
    assert "--port 2222 -u alice" in (host / f"nxc_ssh_{user_tag}_2222.txt").read_text()
    assert "8.6" in (host / "_cve-2024-6387_signal_22.txt").read_text()
    assert not (host / "_cve-2024-6387_signal_2222.txt").exists()


def test_ssh_user_evidence_tag_is_reversible_and_noncolliding():
    script = f'''. '{NET / "enum-ssh.sh"}'; ssh_user_tag "$1"'''
    def tag(user: str) -> str:
        proc = subprocess.run(
            ["bash", "-c", script, "_", user], capture_output=True, text=True, timeout=10,
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    domain_user = tag(r"CORP\alice")
    underscore_user = tag("CORP_alice")
    assert domain_user != underscore_user
    assert bytes.fromhex(domain_user.removeprefix("uhex_")).decode() == r"CORP\alice"
    assert bytes.fromhex(underscore_user.removeprefix("uhex_")).decode() == "CORP_alice"


def test_bambu_dispatcher_only_renders_prior_correlation(tmp_path):
    proc, out = _run(
        "enum-bambu.sh", tmp_path,
        "10.0.0.9:990\n10.0.0.9:3000\n10.0.0.9:6000\n", {},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    evidence = (out / "10.0.0.9/bambu_correlation.txt").read_text()
    assert "severity=low confidence=likely" in evidence
    assert "no live Bambu protocol/auth probe performed" in evidence
    source = (NET / "enum-bambu.sh").read_text()
    for live_primitive in ("curl ", "nc ", "nmap ", "openssl ", "/dev/tcp"):
        assert live_primitive not in source


def test_ldap_preserves_ports_and_selects_ldaps_for_implicit_tls(tmp_path):
    log = tmp_path / "ldap.argv"
    ldapsearch = '''printf '%s\\n' "$*" >> "$LDAP_ARGV"; echo 'dn:'
'''
    proc, _ = _run(
        "enum-ldap.sh", tmp_path, "10.0.0.8:389\n10.0.0.8:636\n10.0.0.8:3269\n",
        {"ldapsearch": ldapsearch}, env={"LDAP_ARGV": str(log)},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    argv = log.read_text()
    assert "-H ldap://10.0.0.8:389" in argv
    assert "-H ldaps://10.0.0.8:636" in argv
    assert "-H ldaps://10.0.0.8:3269" in argv


MAIL_TLS_SHIM = '''
printf 'ARGS %s\\n' "$*" >> "$TLS_LOG"
payload=$(cat)
printf 'INPUT %s\\n' "$payload" >> "$TLS_LOG"
if [[ "$payload" == *'a1 LOGIN'* ]]; then
  printf '* OK ready\\r\\na1 OK LOGIN completed\\r\\n* BYE\\r\\na2 OK\\r\\n'
elif [[ "$payload" == *'CAPABILITY'* ]]; then
  printf '* OK ready\\r\\n* CAPABILITY IMAP4rev1 AUTH=PLAIN\\r\\na1 OK\\r\\n* BYE\\r\\na2 OK\\r\\n'
elif [[ "$payload" == *'USER '* ]]; then
  if [ "${POP_PASS_OK:-0}" = 1 ]; then
    printf '+OK ready\\r\\n+OK user\\r\\n+OK pass\\r\\n+OK stat\\r\\n+OK bye\\r\\n'
  else
    printf '+OK ready\\r\\n+OK user\\r\\n-ERR invalid password\\r\\n-ERR auth required\\r\\n+OK bye\\r\\n'
  fi
elif [[ "$payload" == *'CAPA'* ]]; then
  printf '+OK ready\\r\\n+OK capability list\\r\\nUSER\\r\\n.\\r\\n+OK bye\\r\\n'
else
  printf '220 mail.test ESMTP\\r\\n250 mail.test\\r\\n250 OK\\r\\n221 bye\\r\\n'
fi
'''


@pytest.mark.parametrize("script,port,capability,login,success", [
    ("enum-imap.sh", 993, "a1 CAPABILITY", "a1 LOGIN", "IMAP AUTH SUCCESS"),
    ("enum-pop3.sh", 995, "CAPA", "USER alice", "POP3 AUTH SUCCESS"),
])
def test_implicit_tls_mail_sends_capability_and_auth_commands(
    tmp_path, script, port, capability, login, success
):
    log = tmp_path / "tls.log"
    proc, _ = _run(
        script, tmp_path, f"10.0.0.9:{port}\n", {"openssl": MAIL_TLS_SHIM},
        env={"TLS_LOG": str(log), "ENUM_USER": "alice", "ENUM_PASS": "secret",
             "POP_PASS_OK": "1"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    transcript = log.read_text()
    assert capability in transcript
    assert login in transcript
    assert success in proc.stdout


def test_pop3_rejected_pass_is_not_auth_success_despite_other_ok_replies(tmp_path):
    log = tmp_path / "tls.log"
    proc, _ = _run(
        "enum-pop3.sh", tmp_path, "10.0.0.9:995\n", {"openssl": MAIL_TLS_SHIM},
        env={"TLS_LOG": str(log), "ENUM_USER": "alice", "ENUM_PASS": "wrong",
             "POP_PASS_OK": "0"},
    )
    assert proc.returncode == 0
    assert "POP3 AUTH SUCCESS" not in proc.stdout


def test_smtps_465_uses_implicit_tls_for_all_dialogue(tmp_path):
    log = tmp_path / "tls.log"
    proc, _ = _run("enum-smtp.sh", tmp_path, "10.0.0.10:465\n",
                   {"openssl": MAIL_TLS_SHIM}, env={"TLS_LOG": str(log)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    transcript = log.read_text()
    assert "-connect 10.0.0.10:465" in transcript
    assert "EHLO recon.local" in transcript
    assert "RCPT TO:" in transcript


def test_implicit_ftps_990_uses_tls_url_and_discovered_nmap_port(tmp_path):
    tls_log = tmp_path / "tls.log"
    curl_log = tmp_path / "curl.log"
    nmap_log = tmp_path / "nmap.log"
    openssl = '''printf '%s\\n' "$*" >> "$TLS_LOG"; cat >/dev/null; echo '220 BBL-P003 FTP Server'
'''
    curl = '''printf '%s\\n' "$*" >> "$CURL_LOG"; echo 'listing'
'''
    nmap = '''printf '%s\\n' "$*" >> "$NMAP_LOG"
'''
    proc, _ = _run(
        "enum-ftp.sh", tmp_path, "10.0.0.11:990\n",
        {"openssl": openssl, "curl": curl, "nmap": nmap},
        env={"TLS_LOG": str(tls_log), "CURL_LOG": str(curl_log),
             "NMAP_LOG": str(nmap_log)},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "-connect 10.0.0.11:990" in tls_log.read_text()
    assert "ftps://10.0.0.11:990/" in curl_log.read_text()
    assert "-p 990" in nmap_log.read_text()
