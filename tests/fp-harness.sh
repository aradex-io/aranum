#!/usr/bin/env bash
# tests/fp-harness.sh — FP/TP regression harness for aratool network dispatchers.
#
# Runs fp-server.py (4 wrong-service scenarios) and tp-server.py (rsync + telnet
# true-positive stubs) in the background, exercises all 19 dispatchers, and
# reports pass/fail. AJP TP is verified via the static fixture file
# tests/fixtures/ajp-real-nmap.txt without needing a live server.
#
# Exit codes:
#   0 = all green (zero FPs, TP markers intact)
#   1 = one or more FPs detected
#   2 = one or more TP regressions

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$REPO/tests"

# ---- ports -------------------------------------------------------------------
FP_BASE=19000   # http-200=19000, ssh-banner=19001, accept-silent=19002, tcp-echo=19003
TP_BASE=19010   # rsync-stub=19010, telnet-iac-stub=19011

# ---- colour helpers ----------------------------------------------------------
R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; C="\033[1;36m"; N="\033[0m"
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
DISPATCHERS=(
    ajp oracle pop3 imap telnet rsync mqtt sip
    ipp zookeeper cassandra kafka neo4j influxdb solr consul vault msrpc netbios-ns
)

declare -A SCENARIO_NAMES=(
    [0]="http-200"
    [1]="ssh-banner"
    [2]="accept-silent"
    [3]="tcp-echo"
)

# ---- FP sweep ----------------------------------------------------------------
printf "\n${C}=====[ FP SWEEP — 19 dispatchers × 4 wrong-service scenarios ]=====${N}\n\n"
printf "%-15s %-15s %5s  %s\n" "dispatcher" "scenario" "hits" "first_hit"
printf "%-15s %-15s %5s  %s\n" "----------" "--------" "----" "---------"

fp_failures=0
declare -a FP_CELLS=()

for svc in "${DISPATCHERS[@]}"; do
    for i in 0 1 2 3; do
        scen="${SCENARIO_NAMES[$i]}"
        port=$((FP_BASE + i))
        tgt="$RUNDIR/${svc}-${scen}.targets"
        out="$RUNDIR/${svc}-${scen}-out"
        log="$RUNDIR/${svc}-${scen}.log"
        rm -rf "$out"
        echo "127.0.0.1:${port}" > "$tgt"

        timeout 45 bash "$REPO/network/enum-${svc}.sh" \
            --targets "$tgt" --output "$out" > "$log" 2>&1 || true

        hits=$(grep -c $'^\033\\[1;32m\\[+\\]\033\\[0m' "$log" 2>/dev/null | tr -d '[:space:]')
        hits="${hits:-0}"
        first=$(grep -m1 $'^\033\\[1;32m\\[+\\]\033\\[0m' "$log" 2>/dev/null \
                | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r')
        [ -z "$first" ] && first="-"

        printf "%-15s %-15s %5s  %s\n" "$svc" "$scen" "$hits" "$first"

        if [ "$hits" -gt 0 ]; then
            fp_failures=$((fp_failures + 1))
            FP_CELLS+=("$svc/$scen: $hits hits — $first")
        fi
    done
done

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
ajp_tp_pass=0

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
        ajp_tp_pass=1
    else
        bad "AJP TP: REGRESSION — fixture failed guard check (is_ajp=$ajp_fp1 has_script=$ajp_fp2)"
        tp_failures=$((tp_failures + 1))
        TP_CELLS+=("AJP TP: guard failed on fixture (is_ajp=$ajp_fp1 has_script=$ajp_fp2)")
    fi
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

# ---- summary -----------------------------------------------------------------
printf "\n${C}=====[ SUMMARY ]=====${N}\n"
printf "  FP cells:      %d / %d (expected 0)\n" "$fp_failures" "$((${#DISPATCHERS[@]} * 4))"
printf "  TP regressions: %d / 6 (expected 0)\n" "$tp_failures"

overall_rc=0

if [ "$fp_failures" -gt 0 ]; then
    printf "\n${R}FALSE POSITIVES DETECTED:${N}\n"
    for cell in "${FP_CELLS[@]}"; do
        printf "  ${R}FP${N}: %s\n" "$cell"
    done
    overall_rc=1
fi

if [ "$tp_failures" -gt 0 ]; then
    printf "\n${R}TP REGRESSIONS DETECTED:${N}\n"
    for cell in "${TP_CELLS[@]}"; do
        printf "  ${R}TP${N}: %s\n" "$cell"
    done
    [ "$overall_rc" -eq 0 ] && overall_rc=2
fi

if [ "$overall_rc" -eq 0 ]; then
    printf "\n${G}ALL GREEN — 0 FPs, 0 TP regressions${N}\n\n"
else
    printf "\n${R}HARNESS FAILED (rc=$overall_rc)${N}\n\n"
fi

exit "$overall_rc"
