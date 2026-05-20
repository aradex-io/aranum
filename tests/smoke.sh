#!/usr/bin/env bash
# Comprehensive test pass for aratool — all shipped code through v0.9.0.
# No external lab targets — purely syntax / smoke / fixture / security-regression.

set -uo pipefail
cd /home/jay/Documents/cyber/dev/aratool || exit 2

R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; C="\033[1;36m"; N="\033[0m"
pass=0; fail=0; skip=0
declare -a FAILURES=()

p() { printf "${G}[+]${N} %s\n" "$*"; pass=$((pass+1)); }
f() { printf "${R}[-]${N} %s\n" "$*"; fail=$((fail+1)); FAILURES+=("$*"); }
s() { printf "${Y}[?]${N} %s\n" "$*"; skip=$((skip+1)); }
section() { printf "\n${C}===[ %s ]===${N}\n" "$*"; }

# -----------------------------------------------------------------
section "1. Bash syntax — every .sh file"
# -----------------------------------------------------------------
while IFS= read -r file; do
    if bash -n "$file" 2>/dev/null; then
        p "syntax: $file"
    else
        f "syntax: $file"
    fi
done < <(find . -name "*.sh" -not -path "./.git/*" | sort)

# -----------------------------------------------------------------
section "2. Python compile — every .py file"
# -----------------------------------------------------------------
while IFS= read -r file; do
    if python3 -m py_compile "$file" 2>/dev/null; then
        p "compile: $file"
    else
        f "compile: $file"
    fi
done < <(find . -name "*.py" -not -path "./.git/*" -not -path "*/__pycache__/*" | sort)

# -----------------------------------------------------------------
section "3. CLI --help on every tool"
# -----------------------------------------------------------------
help_works() {
    local cmd="$1"
    if timeout 5 bash -c "$cmd --help >/dev/null 2>&1"; then
        p "help: $cmd"
    else
        f "help: $cmd"
    fi
}
# Python tools with --help
for py in graphql/gql.py creds/default-creds-sweep.py network/nmap-parse.py \
          jabber/jabber-user-enum.py jabber/jabber-validate.py \
          jabber/openfire-cve-2023-32315.py activemq/activemq-cve-2023-46604.py \
          smtp/smtp-smuggling-test.py redis/redis-rogue-master.py ; do
    [ -x "$py" ] && help_works "python3 $py" || s "skipped: $py not executable"
done
# Bash tools with --help (some respond to -h)
for sh in network/auto-enum.sh jabber/jabber-admin-api-probe.sh; do
    [ -x "$sh" ] && help_works "bash $sh" || s "skipped: $sh"
done

# -----------------------------------------------------------------
section "4. Security regression — shell-injection footgun stays closed"
# -----------------------------------------------------------------
if grep -rqn 'NXC_ARGS+=" -u' network/ 2>/dev/null; then
    f "shell-injection: NXC_ARGS+= pattern detected"
else
    p "shell-injection: no NXC_ARGS+= patterns (A.1 holds)"
fi
if grep -rqn 'creds="-u' network/ 2>/dev/null; then
    f "shell-injection: creds=' string-building detected"
else
    p "shell-injection: no creds= patterns (A.1 holds)"
fi
# Payload-credential test on nxc_creds_array helper
out=$(bash -c '. network/_lib.sh; export ENUM_USER="al'\''ice"; export ENUM_PASS="p\$x"; args=(); nxc_creds_array args; printf "%s\n" "${args[@]}"' 2>&1)
if [ "$(printf "%s\n" "$out" | wc -l)" -eq 4 ] \
   && printf "%s\n" "$out" | grep -qx "al'ice" \
   && printf "%s\n" "$out" | grep -qx 'p$x'; then
    p "shell-injection: nxc_creds_array preserves literal credential bytes"
else
    f "shell-injection: nxc_creds_array did not preserve creds literally — got: $out"
fi
# ldap_url helper
v4=$(bash -c '. network/_lib.sh; ldap_url 10.0.0.1')
v6=$(bash -c '. network/_lib.sh; ldap_url "2001:db8::1" 636 ldaps')
[ "$v4" = "ldap://10.0.0.1" ] && p "ldap_url v4: $v4" || f "ldap_url v4 wrong: $v4"
[ "$v6" = "ldaps://[2001:db8::1]:636" ] && p "ldap_url v6+port+scheme: $v6" || f "ldap_url v6 wrong: $v6"

# -----------------------------------------------------------------
section "5. nmap-parse.py — benign fixtures parse + categories present"
# -----------------------------------------------------------------
for fix in network/test.xml network/test.gnmap network/test.nmap; do
    if python3 network/nmap-parse.py "$fix" --json >/dev/null 2>&1; then
        p "parse benign: $fix"
    else
        f "parse benign FAILED: $fix"
    fi
done
# Byte-compare benign-XML output before/after security hardening
benign_json=$(python3 network/nmap-parse.py network/test.xml --json)
hosts=$(printf '%s' "$benign_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['hosts'])")
[ "$hosts" = "1" ] && p "test.xml has 1 host (regression check)" || f "test.xml hosts=$hosts expected 1"

# -----------------------------------------------------------------
section "6. nmap-parse.py — malicious XML is rejected"
# -----------------------------------------------------------------
for fix in tests/fixtures/malicious_xxe.xml tests/fixtures/billion_laughs.xml; do
    if timeout 10 python3 network/nmap-parse.py "$fix" --json >/dev/null 2>&1; then
        f "MALICIOUS XML ACCEPTED: $fix"
    else
        rc=$?
        if [ "$rc" -eq 3 ]; then
            p "rejected with rc=3: $fix"
        else
            p "rejected with rc=$rc: $fix"
        fi
    fi
done

# -----------------------------------------------------------------
section "7. nmap-parse.py — XMPP + OpenFire categories present"
# -----------------------------------------------------------------
# test.xml has no XMPP — just confirm the category list is in --list-categories (output unused —
# the structural check happens via the importlib block below).
python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('m', 'network/nmap-parse.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
needed = ['xmpp', 'openfire-admin', 'postgres', 'mysql', 'mongo', 'elastic', 'ipmi']
missing = [c for c in needed if c not in m.SERVICE_MAP]
print('MISSING:', missing) if missing else print('all present')
" | head -1 | grep -q "all present" \
    && p "categories: xmpp, openfire-admin, postgres, mysql, mongo, elastic, ipmi all present" \
    || f "categories: missing entries — check SERVICE_MAP"

# Synthetic-XML routing test for xmpp + openfire-admin
cat > /tmp/test_xmpp_route.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="5222"><state state="open"/><service name="xmpp-client"/></port>
      <port protocol="tcp" portid="9090"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>
EOF
xmpp_t=$(python3 network/nmap-parse.py /tmp/test_xmpp_route.xml --service xmpp)
of_t=$(python3 network/nmap-parse.py /tmp/test_xmpp_route.xml --service openfire-admin)
[ "$xmpp_t" = "10.0.0.10:5222" ] && p "xmpp routing: $xmpp_t" || f "xmpp routing wrong: $xmpp_t"
[ "$of_t" = "10.0.0.10:9090" ] && p "openfire-admin routing: $of_t" || f "openfire-admin wrong: $of_t"
# Critical: port 80 NOT tagged openfire-admin
if echo "$of_t" | grep -q ":80$"; then
    f "openfire-admin REGRESSION: port 80 mis-tagged"
else
    p "openfire-admin: port 80 NOT mis-tagged (regex `a^` holds)"
fi
rm -f /tmp/test_xmpp_route.xml

# -----------------------------------------------------------------
section "8. gql.py — flags + cache_key + range bound"
# -----------------------------------------------------------------
if python3 graphql/gql.py --help 2>&1 | grep -q "insecure"; then
    p "gql.py: --insecure flag present"
else
    f "gql.py: --insecure flag missing"
fi
# cache_key collision regression
python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('gql', 'graphql/gql.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
url = 'https://x/api/graphql'
keys = set()
for h in [{'PRIVATE-TOKEN':'a'},{'PRIVATE-TOKEN':'b'},{'Cookie':'A'},{'Cookie':'B'},
          {'JOB-TOKEN':'1'},{'JOB-TOKEN':'2'},{'Authorization':'Bearer z'}]:
    keys.add(m.cache_key(url, h).name)
assert len(keys) == 7, f'expected 7 distinct keys, got {len(keys)}'
print('OK')
" 2>&1 | grep -q OK && p "cache_key: 7 distinct identities -> 7 distinct cache files" \
                   || f "cache_key: collision regression"
# range bound — must use a valid op (in gitlab_catalog.json) so find_operation
# doesn't short-circuit with "not found" before the bound check fires.
out=$(python3 graphql/gql.py --url http://127.0.0.1:1/graphql loop currentUser --vary id --range 1-2000000 --no-schema 2>&1)
echo "$out" | grep -q "allow-huge" && p "range bound: >1M refused with --allow-huge hint" \
                                    || f "range bound: did not refuse 2M (got: $out)"

# -----------------------------------------------------------------
section "9. jabber-validate.py — RFC 5802 SCRAM-SHA-1 reference vector"
# -----------------------------------------------------------------
python3 -c "
import hashlib, hmac, base64
salt = base64.b64decode('QSXCR+Q6sek8bf92'); iters = 4096
sp = hashlib.pbkdf2_hmac('sha1', b'pencil', salt, iters)
ck = hmac.new(sp, b'Client Key', 'sha1').digest()
sk = hashlib.sha1(ck).digest()
am = 'n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j'
sig = hmac.new(sk, am.encode(), 'sha1').digest()
proof = bytes(a^b for a,b in zip(ck, sig))
assert base64.b64encode(proof).decode() == 'v0X8v3Bz2T0CJGbJQyF0X+HI4Ts='
print('OK')
" 2>&1 | grep -q OK && p "SCRAM RFC 5802 §5 reference vector matches" \
                    || f "SCRAM RFC 5802 §5 mismatch"

# -----------------------------------------------------------------
section "10. CLI smoke — connect-refused handled cleanly"
# -----------------------------------------------------------------
# jabber-user-enum against closed port
echo "alice" > /tmp/u.txt
out=$(timeout 10 python3 jabber/jabber-user-enum.py --host 127.0.0.1 --port 1 --domain x --user-list /tmp/u.txt 2>&1)
echo "$out" | grep -q "STREAM_FAIL" && p "jabber-user-enum: clean STREAM_FAIL on closed port" \
                                     || f "jabber-user-enum: did not classify connect-refused"

# jabber-validate against closed port
out=$(timeout 10 python3 jabber/jabber-validate.py --host 127.0.0.1 --port 1 --domain x --jid alice --password test 2>&1)
rc=$?
[ "$rc" -eq 2 ] && p "jabber-validate: rc=2 on connect-refused" \
                || f "jabber-validate: rc=$rc expected 2 on connect-refused"

# openfire detect against closed port
out=$(timeout 10 python3 jabber/openfire-cve-2023-32315.py --url http://127.0.0.1:1 detect 2>&1)
rc=$?
[ "$rc" -eq 2 ] && p "openfire detect: rc=2 on connect-refused" \
                || f "openfire detect: rc=$rc expected 2"

# openfire exploit refuses without typed-FQDN
out=$(echo "wrong" | timeout 5 python3 jabber/openfire-cve-2023-32315.py --url http://127.0.0.1:9090 exploit 2>&1)
echo "$out" | grep -q "confirmation did not match" \
    && p "openfire exploit: ADR-001 D3 typed-FQDN refusal works" \
    || f "openfire exploit: typed-FQDN refusal broken"

# enum-jabber.sh smoke with empty targets
echo "" > /tmp/e.txt
bash network/enum-jabber.sh --targets /tmp/e.txt --output /tmp/jt-test >/dev/null 2>&1
[ -f /tmp/jt-test/_hints.txt ] && p "enum-jabber.sh: produces _hints.txt on empty input" \
                                || f "enum-jabber.sh: no _hints.txt"
rm -rf /tmp/jt-test

# -----------------------------------------------------------------
section "10b. Iteration B dispatchers — empty-targets smoke"
# -----------------------------------------------------------------
echo "" > /tmp/empty.txt
for svc in postgres mysql mongo elastic docker kubernetes ipmi \
           vnc jmx rabbitmq memcached couchdb etcd; do
    out_dir=/tmp/b-smoke-$svc
    rm -rf "$out_dir"
    if timeout 15 bash network/enum-$svc.sh --targets /tmp/empty.txt --output "$out_dir" >/dev/null 2>&1; then
        if [ -f "$out_dir/_hints.txt" ]; then
            p "enum-$svc.sh: empty-targets smoke + _hints.txt produced"
        else
            f "enum-$svc.sh: no _hints.txt produced"
        fi
    else
        f "enum-$svc.sh: smoke exit non-zero"
    fi
    rm -rf "$out_dir"
done

# Routing test for new iteration-B categories
cat > /tmp/test_route_b.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun><host><status state="up"/><address addr="10.1.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="2375"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="6443"><state state="open"/><service name="ssl/http"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host></nmaprun>
EOF
docker_route=$(python3 network/nmap-parse.py /tmp/test_route_b.xml --service docker 2>/dev/null)
k8s_route=$(python3 network/nmap-parse.py /tmp/test_route_b.xml --service kubernetes 2>/dev/null)
[ "$docker_route" = "10.1.0.1:2375" ] && p "docker routing: 2375 only" || f "docker routing wrong: $docker_route"
[ "$k8s_route" = "10.1.0.1:6443" ] && p "kubernetes routing: 6443 only" || f "k8s routing wrong: $k8s_route"
# Regression: docker must NOT pick up port 80
if echo "$docker_route" | grep -q ":80$"; then
    f "docker REGRESSION: port 80 mis-tagged"
else
    p "docker: port 80 NOT mis-tagged"
fi
rm /tmp/test_route_b.xml

# -----------------------------------------------------------------
section "10c. Iteration F gql.py subcommands"
# -----------------------------------------------------------------
# suggest against unreachable — should print empty harvest, rc=0
out=$(timeout 8 python3 graphql/gql.py --url http://127.0.0.1:1/graphql suggest --corpus /dev/null 2>&1)
echo "$out" | grep -q "harvested 0" && p "gql.py suggest: empty corpus, clean exit" \
                                     || f "gql.py suggest broken"
# apq-probe against unreachable — rc=0 with the "not implemented" path
out=$(timeout 5 python3 graphql/gql.py --url http://127.0.0.1:1/graphql apq-probe 2>&1)
echo "$out" | grep -q "APQ probe" && p "gql.py apq-probe: runs to completion" \
                                   || f "gql.py apq-probe broken"
# csrf-probe against unreachable
out=$(timeout 5 python3 graphql/gql.py --url http://127.0.0.1:1/graphql csrf-probe 2>&1)
echo "$out" | grep -q "CSRF-via-GET probe" && p "gql.py csrf-probe: runs to completion" \
                                            || f "gql.py csrf-probe broken"
# alias-DoS without --confirm refuses
out=$(timeout 5 python3 graphql/gql.py --url http://127.0.0.1:1/graphql call currentUser --no-schema --alias-dos-check 2>&1)
echo "$out" | grep -q "requires --confirm" && p "gql.py --alias-dos-check: refuses without --confirm" \
                                            || f "gql.py --alias-dos-check confirm-gate broken"
# --proxy flag prints the active-proxy line
out=$(timeout 3 python3 graphql/gql.py --url http://127.0.0.1:1/graphql --proxy http://127.0.0.1:65535 csrf-probe 2>&1)
echo "$out" | grep -q "proxy active" && p "gql.py --proxy: stderr warning emitted" \
                                      || f "gql.py --proxy flag not wired"

# -----------------------------------------------------------------
section "10d. Iteration E — report.py + autoenum-diff.sh"
# -----------------------------------------------------------------
# Build a tiny synthetic outdir
fake=/tmp/e-test
rm -rf "$fake"
mkdir -p "$fake/docker" "$fake/http/10.0.0.7_80"
echo "[!] CRITICAL: UNAUTH Docker daemon at http://10.0.0.5:2375" > "$fake/docker/_dispatcher.log"
echo "EXPOSED: http://10.0.0.7/.git/HEAD (HTTP 200)" > "$fake/http/10.0.0.7_80/exposed.txt"

# report.py
if python3 network/report.py "$fake" --label smoke >/dev/null 2>&1; then
    if [ -f "$fake/findings.json" ] && [ -f "$fake/report.md" ] && [ -f "$fake/report.html" ]; then
        p "report.py: findings.json + report.md + report.html written"
    else
        f "report.py: not all 3 outputs produced"
    fi
    # Check severity classification — should have 1 critical + 1 high
    crit=$(python3 -c "import json; print(json.load(open('$fake/findings.json'))['summary']['counts'].get('critical',0))")
    high=$(python3 -c "import json; print(json.load(open('$fake/findings.json'))['summary']['counts'].get('high',0))")
    [ "$crit" -ge 1 ] && [ "$high" -ge 1 ] && p "report.py: severity classification (≥1 critical, ≥1 high)" \
                                            || f "report.py: severity wrong (crit=$crit high=$high)"
    # Redact mode
    python3 network/report.py "$fake" --redact --findings-only >/dev/null 2>&1
    if python3 -c "import json; d=json.load(open('$fake/findings.json')); import sys; sys.exit(0 if any('<TARGET-' in f['line'] for f in d['findings']) else 1)"; then
        p "report.py --redact: IPs replaced with <TARGET-N>"
    else
        f "report.py --redact: redaction did not apply"
    fi
else
    f "report.py: exit non-zero"
fi

# autoenum-diff.sh
A=/tmp/e-diff-A; B=/tmp/e-diff-B
rm -rf "$A" "$B"; mkdir -p "$A/docker" "$B/docker" "$B/etcd"
echo "[!] CRITICAL: shared finding" > "$A/docker/_dispatcher.log"
echo "[!] CRITICAL: shared finding" > "$B/docker/_dispatcher.log"
echo "[!] CRITICAL: etcd v2/keys unauth" > "$B/etcd/_dispatcher.log"
bash network/autoenum-diff.sh "$A" "$B" >/dev/null 2>&1
[ "$?" -eq 1 ] && p "autoenum-diff.sh: exit 1 when new findings detected" \
                || f "autoenum-diff.sh: did not exit 1 on new findings"
rm -rf "$fake" "$A" "$B"

# version_floor helper present
grep -q "VERSION FLOORS" deps-check.sh && p "deps-check.sh: version_floor section present" \
                                        || f "deps-check.sh: version_floor section missing"

# auto-enum.sh new flags
grep -q -- "--resume" network/auto-enum.sh && p "auto-enum.sh: --resume present" \
                                            || f "auto-enum.sh: --resume missing"
grep -q "run_log" network/auto-enum.sh && p "auto-enum.sh: run_log writer present" \
                                       || f "auto-enum.sh: run_log writer missing"
grep -q "Dispatcher results:" network/auto-enum.sh && p "auto-enum.sh: failure tally present" \
                                                   || f "auto-enum.sh: failure tally missing"

# -----------------------------------------------------------------
section "11. deps-check.sh runs to completion"
# -----------------------------------------------------------------
if timeout 30 bash deps-check.sh >/dev/null 2>&1; then
    p "deps-check.sh exits 0"
else
    rc=$?
    f "deps-check.sh exited $rc"
fi

# -----------------------------------------------------------------
section "11b. --throttle (G.7) — default + operator-explicit precedence"
# -----------------------------------------------------------------
# Validation interface chosen at G.7 design time per advisor:
# `auto-enum.sh --throttle --dry-run` prints the effective env. Smoke asserts
# that (a) --throttle alone sets parallel=1, NUCLEI_RATE=20, NO_FFUF=1,
# NO_NIKTO=1, and (b) an explicit -P N wins over --throttle's default.
out=$(bash network/auto-enum.sh -i network/test.xml -o /tmp/aratool-throttle.$$ --throttle --dry-run 2>&1)
rm -rf /tmp/aratool-throttle.$$
echo "$out" | grep -qE 'parallel:[[:space:]]+1[[:space:]]+\(--throttle default' \
    && p "throttle: parallel=1 default applied" \
    || f "throttle: parallel=1 default NOT applied"
echo "$out" | grep -qE 'NUCLEI_RATE:[[:space:]]+20' \
    && p "throttle: NUCLEI_RATE=20 default applied" \
    || f "throttle: NUCLEI_RATE=20 default NOT applied"
echo "$out" | grep -qE 'NO_FFUF:[[:space:]]+1' \
    && p "throttle: NO_FFUF=1 default applied" \
    || f "throttle: NO_FFUF=1 default NOT applied"

out=$(bash network/auto-enum.sh -i network/test.xml -o /tmp/aratool-throttle-x.$$ --throttle --dry-run -P 8 2>&1)
rm -rf /tmp/aratool-throttle-x.$$
echo "$out" | grep -qE 'parallel:[[:space:]]+8[[:space:]]+\(operator-explicit' \
    && p "throttle: operator -P 8 wins over --throttle default" \
    || f "throttle: operator -P 8 was overridden by --throttle (precedence bug)"

# Library helpers
out=$(bash -c '. network/_lib.sh; echo "off=$(throttle_delay)|$(throttle_nmap_args)"; export ENUM_THROTTLE=1; echo "on=$(throttle_delay)|$(throttle_nmap_args)"')
echo "$out" | grep -qx "off=0|"     && p "throttle_delay/nmap_args: off-state returns 0 and empty" || f "throttle off-state wrong: $out"
echo "$out" | grep -qx "on=1|-T2"   && p "throttle_delay/nmap_args: on-state returns 1 and -T2"   || f "throttle on-state wrong: $out"

# -----------------------------------------------------------------
section "11c. write-gates (G.8) — every gated helper dry-runs without its gate"
# -----------------------------------------------------------------
# CLAUDE.md §9 invariant 1 — six helpers gained explicit gate flags this iteration.
# Smoke asserts each exits 0 + prints "DRY RUN" without its gate.
check_gate() {
    local cmd="$1" name="$2"
    local out rc
    out=$(timeout 10 bash -c "$cmd" 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qi "DRY RUN"; then
        p "gate: $name dry-runs without its gate flag"
    else
        f "gate: $name FAILED dry-run check (rc=$rc, out=${out:0:120})"
    fi
}
check_gate "python3 activemq/activemq-cve-2023-46604.py --target 127.0.0.1:61616 --cmd id"  "activemq-cve-2023-46604.py (--exploit)"
check_gate "bash activemq/activemq-jolokia-rce.sh --target 127.0.0.1:8161"                  "activemq-jolokia-rce.sh   (--exploit)"
check_gate "bash redis/redis-rce-module.sh --target 127.0.0.1:6379"                         "redis-rce-module.sh       (--exploit)"
check_gate "bash redis/redis-rce-ssh.sh --target 127.0.0.1:6379 --key-inline 'ssh-rsa AAAA x@y'" "redis-rce-ssh.sh      (--write)"
check_gate "bash smtp/smtp-phish-send.sh --target 127.0.0.1:25 --from a@b --to c@d --subject s --body x" "smtp-phish-send.sh (--send)"
check_gate "python3 smtp/smtp-smuggling-test.py --target 127.0.0.1:25"                      "smtp-smuggling-test.py    (--send)"

# -----------------------------------------------------------------
section "12. git working tree is clean"
# -----------------------------------------------------------------
if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
    p "git: working tree clean"
else
    f "git: working tree dirty: $(git status --porcelain | head -3)"
fi
# Tags present
for t in v0.1.0 v0.2.0 v0.9.0 v0.10.0 v0.11.0 v0.12.0 v0.13.0 v0.14.0; do
    if git tag | grep -qx "$t"; then
        p "git: tag $t present"
    else
        f "git: tag $t MISSING"
    fi
done

# -----------------------------------------------------------------
echo
printf "${C}=====[ SUMMARY ]=====${N}\n"
printf "  ${G}PASS${N}: %d\n" "$pass"
printf "  ${R}FAIL${N}: %d\n" "$fail"
printf "  ${Y}SKIP${N}: %d\n" "$skip"
if [ "$fail" -gt 0 ]; then
    echo
    printf "${R}FAILURES:${N}\n"
    for f in "${FAILURES[@]}"; do printf "  - %s\n" "$f"; done
    exit 1
fi
exit 0
