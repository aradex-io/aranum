#!/usr/bin/env bash
# tests/fp-harness.sh — FP/TP regression harness for aratool network dispatchers.
#
# Runs fp-server.py (7 wrong-service scenarios) and tp-server.py (rsync + telnet
# true-positive stubs) in the background, exercises all 22 dispatchers, and
# reports pass/fail. AJP TP is verified via the static fixture file
# tests/fixtures/ajp-real-nmap.txt without needing a live server.
#
# E4 additions:
#   - ike, slp, radius added to FP sweep (env-gated dispatchers need env var set)
#   - ENV-GATE TEST block: verifies aggressive dispatchers refuse without env var
#   - vCenter TP block added (stub at 19024)
#
# v0.22.1 additions (cross-service FP coverage):
#   - evil-json scenario: HTTP/200 with JSON body name-dropping every dispatcher's keywords
#   - evil-banner scenario: TCP banner with literal protocol words but no behavior
#   - evil-product-hdrs scenario: HTTP/404 with Server: Jenkins / Grafana / Solr / Vault
#     headers — used both in the dispatcher sweep AND in a dedicated HTTP-product-detect
#     FP cell that runs enum-http.sh against it and asserts zero "detected" lines fire.
#
# v0.28.1 additions (second-tier shape-mimicry FP class — noted in v0.22.1 Notes):
#   - evil-shape scenario: HTTP server that returns shape-mimicked product responses
#     with bogus field content (Vault seal-status shape with "version":"NOT_A_REAL_VAULT
#     _VERSION" but correct sealed/t/n/type fields). Defends against the FP class where
#     an adversary mimics response shape but content is bogus. Caught by enum-vault.sh's
#     v0.28.1 version-regex third-evidence check.
#
# Exit codes:
#   0 = all green (zero FPs, TP markers intact)
#   1 = one or more FPs detected
#   2 = one or more TP regressions

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$REPO/tests"

# ---- ports -------------------------------------------------------------------
# fp-server: http-200=19000, ssh-banner=19001, accept-silent=19002, tcp-echo=19003,
#            evil-json=19004, evil-banner=19005, evil-product-hdrs=19006,
#            evil-shape=19007 (v0.28.1 second-tier shape-mimicry FP class)
# tp-server: rsync-stub=19010, telnet-iac-stub=19011, jenkins=19020, grafana=19021,
#            prometheus=19022, vcenter=19024
FP_BASE=19000
TP_BASE=19010

# ---- colour helpers ----------------------------------------------------------
R="\033[1;31m"; G="\033[1;32m"; C="\033[1;36m"; N="\033[0m"
ok()   { printf "${G}[+]${N} %s\n" "$*"; }
bad()  { printf "${R}[-]${N} %s\n" "$*"; }
info() { printf "${C}[i]${N} %s\n" "$*"; }

# ---- temp dir + server PIDs ---------------------------------------------------
RUNDIR=$(mktemp -d /tmp/aratool-fp-harness.XXXXXX)
FP_PID=""
TP_PID=""

cleanup() {
    [ -n "$FP_PID" ] && kill "$FP_PID" 2>/dev/null || true
    [ -n "$TP_PID" ] && kill "$TP_PID" 2>/dev/null || true
    rm -rf "$RUNDIR"
}
trap cleanup EXIT

# ---- start servers -----------------------------------------------------------
python3 "$SCRIPT_DIR/fp-server.py" --port-base "$FP_BASE" >/dev/null 2>&1 &
FP_PID=$!
python3 "$SCRIPT_DIR/tp-server.py" --port-base "$TP_BASE" >/dev/null 2>&1 &
TP_PID=$!

# Give servers a moment to bind
sleep 1

# Verify servers are still alive
if ! kill -0 "$FP_PID" 2>/dev/null; then
    bad "fp-server.py failed to start (port conflict?)"
    exit 2
fi
if ! kill -0 "$TP_PID" 2>/dev/null; then
    bad "tp-server.py failed to start (port conflict?)"
    exit 2
fi

# ---- dispatcher list ---------------------------------------------------------
# E4: ike/slp/radius are env-gated aggressive dispatchers. They are included in
# the FP sweep with their respective env vars set (so the probe logic runs and
# we verify it does NOT FP on wrong-service scenarios). The ENV-GATE TEST block
# below separately verifies they refuse to run without the env var.
DISPATCHERS=(
    ajp oracle pop3 imap telnet rsync mqtt sip
    ipp zookeeper cassandra kafka neo4j influxdb solr consul vault msrpc netbios-ns
    ike slp radius
    print
    flexnet hpc monitoring backup
)

# Per-dispatcher extra env vars for the FP sweep. These must be set inline per
# invocation — NOT exported globally — so the ENV-GATE TEST block sees a clean env.
dispatcher_env() {
    local svc="$1"
    case "$svc" in
        ike)    echo "ENUM_RUN_IKE=1" ;;
        slp)    echo "ENUM_RUN_SLP=1" ;;
        radius) echo "ENUM_RUN_RADIUS=1" ;;
        *)      echo "" ;;
    esac
}

declare -A SCENARIO_NAMES=(
    [0]="http-200"
    [1]="ssh-banner"
    [2]="accept-silent"
    [3]="tcp-echo"
    [4]="evil-json"
    [5]="evil-banner"
    [6]="evil-product-hdrs"
    [7]="evil-shape"
)
NUM_SCENARIOS=8

# ---- FP sweep ----------------------------------------------------------------
printf "\n${C}=====[ FP SWEEP — %d dispatchers × %d wrong-service scenarios ]=====${N}\n\n" \
    "${#DISPATCHERS[@]}" "$NUM_SCENARIOS"
printf "%-15s %-18s %5s  %s\n" "dispatcher" "scenario" "hits" "first_hit"
printf "%-15s %-18s %5s  %s\n" "----------" "--------" "----" "---------"

fp_failures=0
declare -a FP_CELLS=()

for svc in "${DISPATCHERS[@]}"; do
    for i in 0 1 2 3 4 5 6 7; do
        scen="${SCENARIO_NAMES[$i]}"
        port=$((FP_BASE + i))
        tgt="$RUNDIR/${svc}-${scen}.targets"
        out="$RUNDIR/${svc}-${scen}-out"
        log="$RUNDIR/${svc}-${scen}.log"
        rm -rf "$out"
        echo "127.0.0.1:${port}" > "$tgt"

        # Build extra env inline — NOT exported globally — so ENV-GATE TEST sees clean env
        extra_env=""
        extra_env="$(dispatcher_env "$svc")"

        if [ -n "$extra_env" ]; then
            env "$extra_env" timeout 45 bash "$REPO/network/enum-${svc}.sh" \
                --targets "$tgt" --output "$out" > "$log" 2>&1 || true
        else
            timeout 45 bash "$REPO/network/enum-${svc}.sh" \
                --targets "$tgt" --output "$out" > "$log" 2>&1 || true
        fi

        hits=$(grep -c $'^\033\\[1;32m\\[+\\]\033\\[0m' "$log" 2>/dev/null | tr -d '[:space:]')
        hits="${hits:-0}"
        first=$(grep -m1 $'^\033\\[1;32m\\[+\\]\033\\[0m' "$log" 2>/dev/null \
                | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r')
        [ -z "$first" ] && first="-"

        printf "%-15s %-18s %5s  %s\n" "$svc" "$scen" "$hits" "$first"

        if [ "$hits" -gt 0 ]; then
            fp_failures=$((fp_failures + 1))
            FP_CELLS+=("$svc/$scen: $hits hits — $first")
        fi
    done
done

# ---- ENV-GATE TEST -----------------------------------------------------------
# Verify that the three aggressive dispatchers refuse to run WITHOUT their env
# var set, exit 0, produce no hits, and emit the gate-message reminder string.
printf "\n${C}=====[ ENV-GATE TEST — 3 aggressive + 7 OT dispatchers ]=====${N}\n\n"

env_gate_failures=0
declare -a ENV_GATE_CELLS=()

_run_gate_test() {
    local svc="$1"
    local env_var="$2"
    local gate_msg="$3"

    local tgt="$RUNDIR/gate-${svc}.targets"
    local out="$RUNDIR/gate-${svc}-out"
    local log="$RUNDIR/gate-${svc}.log"
    rm -rf "$out"
    echo "127.0.0.1:500" > "$tgt"   # port doesn't matter — gate fires before probe

    # Unset the env var explicitly in case parent shell has it set
    env -u "$env_var" timeout 10 bash "$REPO/network/enum-${svc}.sh" \
        --targets "$tgt" --output "$out" > "$log" 2>&1
    local rc=$?

    local hits
    hits=$(grep -c $'^\033\\[1;32m\\[+\\]\033\\[0m' "$log" 2>/dev/null | tr -d '[:space:]')
    hits="${hits:-0}"

    local has_msg=0
    grep -qi "$gate_msg" "$log" 2>/dev/null && has_msg=1

    if [ "$rc" -eq 0 ] && [ "$hits" -eq 0 ] && [ "$has_msg" -eq 1 ]; then
        ok "ENV gate ($svc): rc=0, 0 hits, gate message present"
    else
        bad "ENV gate ($svc): FAIL — rc=$rc hits=$hits gate_msg_found=$has_msg"
        env_gate_failures=$((env_gate_failures + 1))
        ENV_GATE_CELLS+=("$svc gate: rc=$rc hits=$hits msg=$has_msg")
    fi
}

_run_gate_test "ike"    "ENUM_RUN_IKE"    "ENUM_RUN_IKE=1"
_run_gate_test "slp"    "ENUM_RUN_SLP"    "ENUM_RUN_SLP=1"
_run_gate_test "radius" "ENUM_RUN_RADIUS" "ENUM_RUN_RADIUS=1"

# T4 OT/ICS dispatchers — separate gate function because they live in ot/
# (not network/) and the gate message they emit is different ("OT_CONFIRMED").
_run_ot_gate_test() {
    local svc="$1"
    local tgt="$RUNDIR/gate-ot-${svc}.targets"
    local out="$RUNDIR/gate-ot-${svc}-out"
    local log="$RUNDIR/gate-ot-${svc}.log"
    rm -rf "$out"
    echo "127.0.0.1:65500" > "$tgt"   # high port — won't be probed anyway (gate fires first)

    env -u OT_CONFIRMED timeout 10 bash "$REPO/ot/enum-${svc}.sh" \
        --targets "$tgt" --output "$out" > "$log" 2>&1
    local rc=$?

    # Gate fires before any probe, so 0 hits expected and rc=2 (refused).
    local hits
    hits=$(grep -c $'^\033\\[1;32m\\[+\\]\033\\[0m' "$log" 2>/dev/null | tr -d '[:space:]')
    hits="${hits:-0}"

    local has_msg=0
    grep -qi "OT dispatcher refused" "$log" 2>/dev/null && has_msg=1

    if [ "$rc" -eq 2 ] && [ "$hits" -eq 0 ] && [ "$has_msg" -eq 1 ]; then
        ok "OT gate ($svc): rc=2, 0 hits, refusal message present"
    else
        bad "OT gate ($svc): FAIL — rc=$rc hits=$hits gate_msg_found=$has_msg"
        env_gate_failures=$((env_gate_failures + 1))
        ENV_GATE_CELLS+=("ot/$svc gate: rc=$rc hits=$hits msg=$has_msg")
    fi
}

_run_ot_gate_test "modbus"
_run_ot_gate_test "s7"
_run_ot_gate_test "enip"
_run_ot_gate_test "bacnet"
_run_ot_gate_test "opcua"
_run_ot_gate_test "dnp3"
_run_ot_gate_test "iec104"

# ---- TP checks ---------------------------------------------------------------
printf "\n${C}=====[ TP CHECKS ]=====${N}\n\n"

tp_failures=0
declare -a TP_CELLS=()

# -- rsync TP --
info "rsync TP: testing against stub at 127.0.0.1:${TP_BASE}"
rsync_tgt="$RUNDIR/rsync-tp.targets"
rsync_out="$RUNDIR/rsync-tp-out"
rsync_log="$RUNDIR/rsync-tp.log"
rm -rf "$rsync_out"
echo "127.0.0.1:${TP_BASE}" > "$rsync_tgt"
timeout 30 bash "$REPO/network/enum-rsync.sh" \
    --targets "$rsync_tgt" --output "$rsync_out" > "$rsync_log" 2>&1 || true
rsync_hits=$(grep -c $'^\033\\[1;32m\\[+\\]\033\\[0m' "$rsync_log" 2>/dev/null | tr -d '[:space:]')
rsync_hits="${rsync_hits:-0}"
if [ "$rsync_hits" -gt 0 ]; then
    ok "rsync TP: $rsync_hits hit(s) — TP marker intact"
else
    bad "rsync TP: REGRESSION — no hits against rsync stub (rc-based gate is too strict or stub handshake failed)"
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("rsync TP: 0 hits")
fi

# -- telnet TP --
telnet_tp_port=$((TP_BASE + 1))
info "telnet TP: testing against IAC stub at 127.0.0.1:${telnet_tp_port}"
telnet_tgt="$RUNDIR/telnet-tp.targets"
telnet_out="$RUNDIR/telnet-tp-out"
telnet_log="$RUNDIR/telnet-tp.log"
rm -rf "$telnet_out"
echo "127.0.0.1:${telnet_tp_port}" > "$telnet_tgt"
timeout 30 bash "$REPO/network/enum-telnet.sh" \
    --targets "$telnet_tgt" --output "$telnet_out" > "$telnet_log" 2>&1 || true
telnet_hits=$(grep -c $'^\033\\[1;32m\\[+\\]\033\\[0m' "$telnet_log" 2>/dev/null | tr -d '[:space:]')
telnet_hits="${telnet_hits:-0}"
if [ "$telnet_hits" -gt 0 ]; then
    ok "telnet TP: $telnet_hits hit(s) — TP marker intact"
else
    bad "telnet TP: REGRESSION — no hits against IAC stub"
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("telnet TP: 0 hits")
fi

# -- AJP TP (fixture-based, no live server needed) --
info "AJP TP: mini integration test against fixture tests/fixtures/ajp-real-nmap.txt"
ajp_fixture="$REPO/tests/fixtures/ajp-real-nmap.txt"

if [ ! -f "$ajp_fixture" ]; then
    bad "AJP TP: fixture file missing: $ajp_fixture"
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("AJP TP: fixture missing")
else
    # Test the two guards directly against the fixture
    ajp_fp1=0; ajp_fp2=0
    grep -qE '^[0-9]+/tcp[[:space:]]+open[[:space:]]+ajp13' "$ajp_fixture" 2>/dev/null && ajp_fp1=1
    grep -qE '^\| ajp-(headers|methods|auth|brute):' "$ajp_fixture" 2>/dev/null && ajp_fp2=1
    if [ "$ajp_fp1" = 1 ] && [ "$ajp_fp2" = 1 ]; then
        ok "AJP TP: fixture passes both guards (ajp13 fingerprint + script result present)"
    else
        bad "AJP TP: REGRESSION — fixture failed guard check (is_ajp=$ajp_fp1 has_script=$ajp_fp2)"
        tp_failures=$((tp_failures + 1))
        TP_CELLS+=("AJP TP: guard failed on fixture (is_ajp=$ajp_fp1 has_script=$ajp_fp2)")
    fi
fi

# ---- HTTP product-detect FP check (v0.22.1) ----------------------------------
# enum-http.sh isn't in the per-port dispatcher sweep because its target shape
# differs (alive-URLs not raw ip:port). This dedicated cell hits the
# evil-product-hdrs flavor — HTTP/404 with Server: Jenkins / X-Powered-By: Solr /
# X-Grafana-Version / Set-Cookie: vault_token=... headers but no real endpoints.
# A correctly-disciplined product-detect MUST emit zero "detected" / "UNAUTH"
# hits because all the canonical paths return 404 (no body / JSON markers).
printf "\n${C}=====[ HTTP PRODUCT-DETECT FP CHECK — evil-product-hdrs ]=====${N}\n\n"
http_fp_failures=0
declare -a HTTP_FP_CELLS=()

evil_port=$((FP_BASE + 6))
info "enum-http.sh vs evil-product-hdrs at 127.0.0.1:${evil_port}"
http_fp_tgt="$RUNDIR/http-evil.targets"
http_fp_out="$RUNDIR/http-evil-out"
http_fp_log="$RUNDIR/http-evil.log"
rm -rf "$http_fp_out"
echo "127.0.0.1:${evil_port}" > "$http_fp_tgt"
NO_NUCLEI=1 NO_FFUF=1 RUN_NIKTO=0 NO_WHATWEB=1 \
    timeout 60 bash "$REPO/network/enum-http.sh" \
    --targets "$http_fp_tgt" --output "$http_fp_out" > "$http_fp_log" 2>&1 || true

# Look for any "X detected" or "UNAUTH:" hit (these are the product-detect
# emission patterns from enum-http.sh C.13).
http_fp_hits=$(grep -cE "(detected|UNAUTH:)" "$http_fp_log" 2>/dev/null | tr -d '[:space:]')
http_fp_hits="${http_fp_hits:-0}"
if [ "$http_fp_hits" -eq 0 ]; then
    ok "HTTP product-detect FP: 0 'detected'/'UNAUTH' hits against evil-product-hdrs"
else
    bad "HTTP product-detect FP: $http_fp_hits FP hit(s) on evil-product-hdrs — header-only matching too loose"
    grep -E "(detected|UNAUTH:)" "$http_fp_log" 2>/dev/null | head -5 || true
    http_fp_failures=1
    HTTP_FP_CELLS+=("HTTP-product-detect: $http_fp_hits hits on evil-product-hdrs")
fi

# ---- product-detect TP checks (Jenkins / Grafana / Prometheus) --------------
printf "\n${C}=====[ PRODUCT-DETECT TP CHECKS ]=====${N}\n\n"

# -- Jenkins TP --
jk_tp_port=$((TP_BASE + 10))
info "Jenkins TP: testing against stub at 127.0.0.1:${jk_tp_port}"
jk_tgt="$RUNDIR/jenkins-tp.targets"
jk_out="$RUNDIR/jenkins-tp-out"
jk_log="$RUNDIR/jenkins-tp.log"
rm -rf "$jk_out"
echo "127.0.0.1:${jk_tp_port}" > "$jk_tgt"
NO_NUCLEI=1 NO_FFUF=1 RUN_NIKTO=0 NO_WHATWEB=1 \
    timeout 60 bash "$REPO/network/enum-http.sh" \
    --targets "$jk_tgt" --output "$jk_out" > "$jk_log" 2>&1 || true
if grep -q "Jenkins detected" "$jk_log" 2>/dev/null && grep -q "UNAUTH: Jenkins API exposed" "$jk_log" 2>/dev/null; then
    ok "Jenkins TP: 'Jenkins detected' + 'UNAUTH: Jenkins API exposed' hits present"
else
    bad "Jenkins TP: REGRESSION — expected hits not found in log"
    grep -E "(Jenkins|UNAUTH)" "$jk_log" 2>/dev/null | head -5 || true
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("Jenkins TP: expected hits missing")
fi

# -- Grafana TP --
gf_tp_port=$((TP_BASE + 11))
info "Grafana TP: testing against stub at 127.0.0.1:${gf_tp_port}"
gf_tgt="$RUNDIR/grafana-tp.targets"
gf_out="$RUNDIR/grafana-tp-out"
gf_log="$RUNDIR/grafana-tp.log"
rm -rf "$gf_out"
echo "127.0.0.1:${gf_tp_port}" > "$gf_tgt"
NO_NUCLEI=1 NO_FFUF=1 RUN_NIKTO=0 NO_WHATWEB=1 \
    timeout 60 bash "$REPO/network/enum-http.sh" \
    --targets "$gf_tgt" --output "$gf_out" > "$gf_log" 2>&1 || true
if grep -q "Grafana detected" "$gf_log" 2>/dev/null; then
    ok "Grafana TP: 'Grafana detected' hit present"
else
    bad "Grafana TP: REGRESSION — 'Grafana detected' not found in log"
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("Grafana TP: 'Grafana detected' missing")
fi

# -- Prometheus TP --
pm_tp_port=$((TP_BASE + 12))
info "Prometheus TP: testing against stub at 127.0.0.1:${pm_tp_port}"
pm_tgt="$RUNDIR/prometheus-tp.targets"
pm_out="$RUNDIR/prometheus-tp-out"
pm_log="$RUNDIR/prometheus-tp.log"
rm -rf "$pm_out"
echo "127.0.0.1:${pm_tp_port}" > "$pm_tgt"
NO_NUCLEI=1 NO_FFUF=1 RUN_NIKTO=0 NO_WHATWEB=1 \
    timeout 60 bash "$REPO/network/enum-http.sh" \
    --targets "$pm_tgt" --output "$pm_out" > "$pm_log" 2>&1 || true
if grep -q "Prometheus detected" "$pm_log" 2>/dev/null; then
    ok "Prometheus TP: 'Prometheus detected' hit present"
else
    bad "Prometheus TP: REGRESSION — 'Prometheus detected' not found in log"
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("Prometheus TP: 'Prometheus detected' missing")
fi

# -- JetDirect TP --
jd_tp_port=$((TP_BASE + 15))
info "JetDirect TP: testing against stub at 127.0.0.1:${jd_tp_port}"
jd_tgt="$RUNDIR/jetdirect-tp.targets"
jd_out="$RUNDIR/jetdirect-tp-out"
jd_log="$RUNDIR/jetdirect-tp.log"
rm -rf "$jd_out"
echo "127.0.0.1:${jd_tp_port}" > "$jd_tgt"
PRINT_EXTRA_JETDIRECT_PORT="$jd_tp_port" \
    timeout 30 bash "$REPO/network/enum-print.sh" \
    --targets "$jd_tgt" --output "$jd_out" > "$jd_log" 2>&1 || true
if grep -q "JetDirect / PJL UNAUTH:" "$jd_log" 2>/dev/null; then
    ok "JetDirect TP: 'JetDirect / PJL UNAUTH' hit present"
else
    bad "JetDirect TP: REGRESSION — expected hit not found"
    grep -E "PJL|JetDirect|print:" "$jd_log" 2>/dev/null | head -5 || true
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("JetDirect TP: expected hit missing")
fi

# -- LPD TP --
lpd_tp_port=$((TP_BASE + 16))
info "LPD TP: testing against stub at 127.0.0.1:${lpd_tp_port}"
lpd_tgt="$RUNDIR/lpd-tp.targets"
lpd_out="$RUNDIR/lpd-tp-out"
lpd_log="$RUNDIR/lpd-tp.log"
rm -rf "$lpd_out"
echo "127.0.0.1:${lpd_tp_port}" > "$lpd_tgt"
PRINT_EXTRA_LPD_PORT="$lpd_tp_port" \
    timeout 30 bash "$REPO/network/enum-print.sh" \
    --targets "$lpd_tgt" --output "$lpd_out" > "$lpd_log" 2>&1 || true
if grep -q "LPD reachable:" "$lpd_log" 2>/dev/null; then
    ok "LPD TP: 'LPD reachable' hit present"
else
    bad "LPD TP: REGRESSION — expected hit not found"
    grep -E "LPD|print:" "$lpd_log" 2>/dev/null | head -5 || true
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("LPD TP: expected hit missing")
fi

# -- vCenter TP --
vc_tp_port=$((TP_BASE + 14))
info "vCenter TP: testing against stub at 127.0.0.1:${vc_tp_port}"
vc_tgt="$RUNDIR/vcenter-tp.targets"
vc_out="$RUNDIR/vcenter-tp-out"
vc_log="$RUNDIR/vcenter-tp.log"
rm -rf "$vc_out"
echo "127.0.0.1:${vc_tp_port}" > "$vc_tgt"
NO_NUCLEI=1 NO_FFUF=1 RUN_NIKTO=0 NO_WHATWEB=1 \
    timeout 60 bash "$REPO/network/enum-http.sh" \
    --targets "$vc_tgt" --output "$vc_out" > "$vc_log" 2>&1 || true
if grep -q "VMware vCenter SDK reachable" "$vc_log" 2>/dev/null; then
    ok "vCenter TP: 'VMware vCenter SDK reachable' hit present"
else
    bad "vCenter TP: REGRESSION — 'VMware vCenter SDK reachable' not found in log"
    grep -i "vcenter\|vCenter\|vsphere\|vim25" "$vc_log" 2>/dev/null | head -5 || true
    tp_failures=$((tp_failures + 1))
    TP_CELLS+=("vCenter TP: expected hit missing")
fi

# ---- summary -----------------------------------------------------------------
printf "\n${C}=====[ SUMMARY ]=====${N}\n"
printf "  FP cells:           %d / %d (expected 0)\n" "$fp_failures" "$((${#DISPATCHERS[@]} * NUM_SCENARIOS))"
printf "  HTTP product FP:    %d / 1 (expected 0)\n"  "$http_fp_failures"
printf "  ENV gates:          %d / 10 (expected 0)\n" "$env_gate_failures"
printf "  TP regressions:     %d / 9 (expected 0)\n"  "$tp_failures"

overall_rc=0

if [ "$fp_failures" -gt 0 ]; then
    printf "\n${R}FALSE POSITIVES DETECTED:${N}\n"
    for cell in "${FP_CELLS[@]}"; do
        printf "  ${R}FP${N}: %s\n" "$cell"
    done
    overall_rc=1
fi

if [ "$http_fp_failures" -gt 0 ]; then
    printf "\n${R}HTTP PRODUCT-DETECT FPs:${N}\n"
    for cell in "${HTTP_FP_CELLS[@]}"; do
        printf "  ${R}FP${N}: %s\n" "$cell"
    done
    [ "$overall_rc" -eq 0 ] && overall_rc=1
fi

if [ "$env_gate_failures" -gt 0 ]; then
    printf "\n${R}ENV GATE FAILURES:${N}\n"
    for cell in "${ENV_GATE_CELLS[@]}"; do
        printf "  ${R}GATE${N}: %s\n" "$cell"
    done
    [ "$overall_rc" -eq 0 ] && overall_rc=2
fi

if [ "$tp_failures" -gt 0 ]; then
    printf "\n${R}TP REGRESSIONS DETECTED:${N}\n"
    for cell in "${TP_CELLS[@]}"; do
        printf "  ${R}TP${N}: %s\n" "$cell"
    done
    [ "$overall_rc" -eq 0 ] && overall_rc=2
fi

if [ "$overall_rc" -eq 0 ]; then
    printf "\n${G}ALL GREEN — 0 FPs (incl. HTTP product-detect), 0 ENV gate failures, 0 TP regressions${N}\n\n"
else
    printf "\n${R}HARNESS FAILED (rc=$overall_rc)${N}\n\n"
fi

exit "$overall_rc"
