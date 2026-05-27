#!/usr/bin/env bash
# iterative-enum.sh — second-pass enumeration from an nmap inventory/auto-enum run.
#
# Correlates hostnames, HTTP source fingerprints, SMB shares, usernames,
# default credentials, and credentialed filesystem scraping into one follow-up
# output tree. All network/file operations are read-only.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARSER="$SCRIPT_DIR/nmap-parse.py"
DEFAULT_CREDS="$REPO_ROOT/creds/default-creds-sweep.py"
JUICY_SCRIPT="$REPO_ROOT/linux/juicy-files-hunt.sh"

INPUT=""
ENUM_OUT=""
OUTDIR="./iterative-results"
USER_NAME="${ENUM_USER:-}"
PASS="${ENUM_PASS:-}"
NTLM_HASH="${ENUM_HASH:-}"
DOMAIN="${ENUM_DOMAIN:-}"
DC_IP="${ENUM_DC_IP:-}"
SSH_USER=""
SSH_KEY=""
SSH_PASS=""
SSH_PORT="22"
PARALLEL="${ENUM_PARALLEL:-4}"
DRY_RUN=0
RUN_DEFAULT_CREDS=1
RUN_MOUNTS=0
RUN_FS_SCRAPE=1
CONNECT_TIMEOUT="${ENUM_CONNECT_TIMEOUT:-8}"

usage() {
    cat <<EOF
Usage: $0 [-i nmap.xml] [--enum-output DIR] [-o DIR] [options]

Inputs:
  -i, --input FILE        nmap output (.xml/.gnmap/.nmap). If omitted, reads
                          --enum-output/inventory.json.
  --enum-output DIR       existing auto-enum output tree to mine for URLs,
                          SMB output, SANs, and prior usernames.

Auth:
  -u, --user USER         SMB/AD username
  -p, --password PASS     SMB/AD password
  -H, --hash HASH         NTLM hash
  -d, --domain DOMAIN     AD/Windows domain
  --dc-ip IP              domain controller IP
  --ssh-user USER         SSH username for filesystem scraping
  --ssh-key FILE          SSH key for filesystem scraping
  --ssh-pass PASS         SSH password via sshpass for filesystem scraping
  --ssh-port N            default SSH port (default: $SSH_PORT)

Tuning:
  -P, --parallel N        parallelism for per-host phases (default: $PARALLEL)
  --mount-shares          mount readable SMB shares read-only under /mnt/aranum_*
                          and run grep/filename searches. Requires root/sudo.
  --no-default-creds      skip creds/default-creds-sweep.py
  --no-fs-scrape          skip SSH stdin-piped juicy filesystem scraping
  --dry-run               print commands/targets without connecting or mounting
  -h, --help              show this help

Outputs:
  <outdir>/hostnames.tsv          ip, hostname, source
  <outdir>/etc-hosts.add          /etc/hosts-ready entries
  <outdir>/http/source_products.tsv
  <outdir>/default-creds.json
  <outdir>/smb/{shares,spider,users}.*
  <outdir>/mounts/* and <outdir>/filesystem/*
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -i|--input) INPUT="$2"; shift 2 ;;
        --enum-output) ENUM_OUT="$2"; shift 2 ;;
        -o|--output) OUTDIR="$2"; shift 2 ;;
        -u|--user) USER_NAME="$2"; shift 2 ;;
        -p|--password) PASS="$2"; shift 2 ;;
        -H|--hash) NTLM_HASH="$2"; shift 2 ;;
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        --dc-ip) DC_IP="$2"; shift 2 ;;
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-pass) SSH_PASS="$2"; shift 2 ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        -P|--parallel) PARALLEL="$2"; shift 2 ;;
        --mount-shares) RUN_MOUNTS=1; shift ;;
        --no-default-creds) RUN_DEFAULT_CREDS=0; shift ;;
        --no-fs-scrape) RUN_FS_SCRAPE=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

[ -z "$INPUT" ] && [ -z "$ENUM_OUT" ] && { usage; exit 1; }
[ -n "$INPUT" ] && [ ! -f "$INPUT" ] && { echo "input not found: $INPUT" >&2; exit 2; }
[ -n "$ENUM_OUT" ] && [ ! -d "$ENUM_OUT" ] && { echo "enum output not found: $ENUM_OUT" >&2; exit 2; }
[ -n "$SSH_KEY" ] && [ ! -r "$SSH_KEY" ] && { echo "ssh key not readable: $SSH_KEY" >&2; exit 2; }
[ -n "$SSH_PASS" ] && ! command -v sshpass >/dev/null 2>&1 && {
    echo "--ssh-pass requires sshpass" >&2; exit 2;
}

mkdir -p "$OUTDIR"/{http,smb,mounts,filesystem}
RUN_LOG="$OUTDIR/run.log"
run_log() { printf "%s  %s\n" "$(date -Iseconds)" "$*" >> "$RUN_LOG"; }
log() { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
miss() { printf "\033[1;33m[-]\033[0m %s\n" "$*"; }
hit() { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }

run_log "=== iterative-enum run started ==="
run_log "input=${INPUT:-<none>} enum_out=${ENUM_OUT:-<none>} outdir=$OUTDIR"
run_log "user=${USER_NAME:-<none>} domain=${DOMAIN:-<none>} dc_ip=${DC_IP:-<none>} mounts=$RUN_MOUNTS default_creds=$RUN_DEFAULT_CREDS fs_scrape=$RUN_FS_SCRAPE"

INVENTORY="$OUTDIR/inventory.json"
if [ -n "$INPUT" ]; then
    log "parse inventory: $INPUT"
    python3 "$PARSER" "$INPUT" --json > "$INVENTORY" || exit 3
elif [ -f "$ENUM_OUT/inventory.json" ]; then
    cp "$ENUM_OUT/inventory.json" "$INVENTORY"
else
    echo "no input and $ENUM_OUT/inventory.json missing" >&2
    exit 2
fi

inventory_query() {
    python3 - "$INVENTORY" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
mode = sys.argv[2]
entries = d.get("entries", [])
def hp(e):
    ip = str(e.get("ip", ""))
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{e.get('port')}"
if mode == "ips":
    for ip in sorted({str(e.get("ip", "")) for e in entries if e.get("ip")}):
        print(ip)
elif mode == "hostnames":
    seen = set()
    for e in entries:
        ip = str(e.get("ip", ""))
        name = str(e.get("hostname", "")).strip().strip("()")
        if ip and name and name != "unknown" and (ip, name) not in seen:
            seen.add((ip, name))
            print(f"{ip}\t{name}\tnmap")
elif mode == "http":
    for e in entries:
        cats = set(e.get("categories", []))
        port = int(e.get("port", 0))
        if "http" in cats or "https" in cats or port in {80,81,443,4443,7001,7002,8000,8008,8080,8081,8443,8888,9000,9090,9443,10443}:
            ip = str(e.get("ip", ""))
            host = f"[{ip}]" if ":" in ip else ip
            scheme = "https" if "https" in cats or port in {443,4443,8443,9443,10443} or e.get("tunnel") == "ssl" else "http"
            print(f"{scheme}://{host}:{port}")
elif mode == "smb":
    for e in entries:
        if "smb" in set(e.get("categories", [])) or int(e.get("port", 0)) in {139, 445}:
            print(hp(e))
elif mode == "ssh":
    for e in entries:
        if "ssh" in set(e.get("categories", [])) or int(e.get("port", 0)) in {22, 2222}:
            print(hp(e))
PY
}

phase_hostnames() {
    log "hostname harvest -> hostnames.tsv / etc-hosts.add"
    : > "$OUTDIR/hostnames.tsv"
    inventory_query hostnames >> "$OUTDIR/hostnames.tsv"

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        if [ "$DRY_RUN" = 1 ]; then
            continue
        fi
        if command -v dig >/dev/null 2>&1; then
            name=$(timeout 3 dig +time=1 +tries=1 +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -1)
            [ -n "$name" ] && printf '%s\t%s\treverse-dns\n' "$ip" "$name" >> "$OUTDIR/hostnames.tsv"
        fi
        if command -v nmblookup >/dev/null 2>&1; then
            timeout 3 nmblookup -A "$ip" 2>/dev/null \
                | awk -v ip="$ip" '/<00>/ && /UNIQUE/ {print ip "\t" $1 "\tnetbios"}' \
                >> "$OUTDIR/hostnames.tsv" || true
        fi
    done < <(inventory_query ips)

    if [ -n "$ENUM_OUT" ]; then
        find "$ENUM_OUT" -path '*/http/_all_sans.txt' -type f -print 2>/dev/null \
            | while IFS= read -r f; do
                sed 's/^/# SAN unmapped: /' "$f" >> "$OUTDIR/hostnames.tsv"
            done
    fi

    sort -u "$OUTDIR/hostnames.tsv" -o "$OUTDIR/hostnames.tsv"
    python3 - "$OUTDIR/hostnames.tsv" > "$OUTDIR/etc-hosts.add" <<'PY'
import collections, re, sys
names = collections.defaultdict(list)
valid = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
for line in open(sys.argv[1], errors="replace"):
    if not line.strip() or line.startswith("#"):
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        continue
    ip, name = parts[0], parts[1].strip().lower()
    if valid.match(name) and name not in names[ip]:
        names[ip].append(name)
for ip in sorted(names):
    print(f"{ip}\t{' '.join(sorted(names[ip]))}")
PY
    hit "hostname entries: $(wc -l < "$OUTDIR/etc-hosts.add")"
}

phase_http_source() {
    log "HTTP source-code product fingerprints"
    HTTP_URLS="$OUTDIR/http/urls.txt"
    if [ -n "$ENUM_OUT" ] && [ -s "$ENUM_OUT/http/_alive_urls.txt" ]; then
        cp "$ENUM_OUT/http/_alive_urls.txt" "$HTTP_URLS"
    elif [ -n "$ENUM_OUT" ] && [ -s "$ENUM_OUT/http/httpx.txt" ]; then
        awk '{print $1}' "$ENUM_OUT/http/httpx.txt" | sort -u > "$HTTP_URLS"
    else
        inventory_query http | sort -u > "$HTTP_URLS"
    fi
    : > "$OUTDIR/http/source_products.tsv"
    [ ! -s "$HTTP_URLS" ] && { miss "no HTTP URLs for source fingerprinting"; return 0; }
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        safe=$(printf '%s' "$url" | sed 's|[:/]|_|g')
        src="$OUTDIR/http/source_${safe}.html"
        hdr="$OUTDIR/http/source_${safe}.headers"
        if [ "$DRY_RUN" = 1 ]; then
            echo "[DRY] curl $url/"
            continue
        fi
        curl -ksL -D "$hdr" --connect-timeout "$CONNECT_TIMEOUT" --max-time 15 "$url/" \
            | head -c 524288 > "$src" || true
        python3 - "$url" "$src" "$hdr" >> "$OUTDIR/http/source_products.tsv" <<'PY'
import re, sys
url, src, hdr = sys.argv[1], sys.argv[2], sys.argv[3]
hay = ""
for p in (src, hdr):
    try:
        hay += open(p, errors="replace").read(524288) + "\n"
    except OSError:
        pass
rules = [
    ("Jenkins", r"X-Jenkins:|jenkins\.model|adjuncts/|Jenkins ver\.|jenkins-logo"),
    ("Grafana", r"grafanaBootData|public/build/grafana|<title>Grafana</title>"),
    ("GitLab", r"gon\.gitlab_url|assets/gitlab|GitLab Community Edition|GitLab Enterprise Edition"),
    ("Confluence", r"ajs-version-number|confluence-context-path|Atlassian Confluence"),
    ("Jira", r"jira\.webresources|Atlassian Jira|data-aui-version"),
    ("Bamboo", r"Atlassian Bamboo|bamboo\.webresources|Bamboo</title>"),
    ("Keycloak", r"kc-form|keycloak\.js|Keycloak Administration Console"),
    ("Nexus Repository", r"Nexus Repository|Nexus Repository Manager|NX\.Bootstrap"),
    ("Artifactory", r"JFrog|Artifactory|artifactory-ui"),
    ("Harbor", r"Harbor</title>|harbor-icon|harbor-ui"),
    ("MinIO", r"MinIO Console|__MINIO|minio_browser"),
    ("Portainer", r"Portainer</title>|portainer\.|portainer-"),
    ("Rancher", r"Rancher</title>|rancher-ui|ember-rancher"),
    ("Argo CD", r"Argo CD|argocd|argo-cd"),
    ("Proxmox VE", r"PVE\.Utils|Proxmox Virtual Environment|proxmox"),
    ("VMware vSphere/ESXi", r"vSphere Client|VMware Host Client|/ui/assets/"),
    ("Tomcat", r"Apache Tomcat|Tomcat Manager|/manager/html"),
    ("Kibana", r"kbn-injected-metadata|Kibana</title>|elastic"),
    ("Prometheus", r"Prometheus Time Series Collection|prometheus-ui|Prometheus</title>"),
    ("Vault", r"HashiCorp Vault|vault-ui|Vault</title>"),
]
for name, pat in rules:
    if re.search(pat, hay, re.I):
        print(f"{url}\t{name}\tsource-regex:{pat}")
PY
    done < "$HTTP_URLS"
    sort -u "$OUTDIR/http/source_products.tsv" -o "$OUTDIR/http/source_products.tsv"
    [ -s "$OUTDIR/http/source_products.tsv" ] && hit "source products: $(wc -l < "$OUTDIR/http/source_products.tsv")"
}

phase_default_creds() {
    [ "$RUN_DEFAULT_CREDS" = 1 ] || { log "default creds skipped"; return 0; }
    [ -x "$DEFAULT_CREDS" ] || { miss "default-creds-sweep.py missing/not executable"; return 0; }
    [ -s "$OUTDIR/http/urls.txt" ] || { miss "no HTTP targets for default creds"; return 0; }
    log "default credential sweep (low-rate)"
    if [ "$DRY_RUN" = 1 ]; then
        echo "[DRY] $DEFAULT_CREDS --targets $OUTDIR/http/urls.txt --output $OUTDIR/default-creds.json"
        return 0
    fi
    python3 "$DEFAULT_CREDS" --targets "$OUTDIR/http/urls.txt" \
        --threads "${ENUM_DEFAULT_CREDS_THREADS:-4}" \
        --delay "${ENUM_DEFAULT_CREDS_DELAY:-0.5}" \
        --output "$OUTDIR/default-creds.json" \
        > "$OUTDIR/default-creds.log" 2>&1 || true
}

smb_auth_args() {
    if [ -n "$USER_NAME" ]; then
        printf '%s\n' -U "${DOMAIN:+$DOMAIN\\}$USER_NAME%$PASS"
    else
        printf '%s\n' -N
    fi
}

phase_smb() {
    SMB_TARGETS="$OUTDIR/smb/targets.txt"
    inventory_query smb | sort -u > "$SMB_TARGETS"
    [ ! -s "$SMB_TARGETS" ] && { miss "no SMB targets"; return 0; }
    awk '{gsub(/:[0-9]+$/, "", $1); gsub(/^\[/, "", $1); gsub(/\]$/, "", $1); print $1}' "$SMB_TARGETS" \
        | sort -u > "$OUTDIR/smb/ips.txt"
    log "SMB shares/users/spider"

    if command -v nxc >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
        NXC=$(command -v nxc || command -v netexec)
        nxc_args=()
        if [ -n "$USER_NAME" ]; then
            nxc_args=(-u "$USER_NAME")
            [ -n "$PASS" ] && nxc_args+=(-p "$PASS")
            [ -n "$NTLM_HASH" ] && nxc_args+=(-H "$NTLM_HASH")
            [ -n "$DOMAIN" ] && nxc_args+=(-d "$DOMAIN")
        fi
        if [ "$DRY_RUN" = 1 ]; then
            echo "[DRY] $NXC smb <ips> --shares --users --groups --rid-brute"
        else
            "$NXC" smb "$OUTDIR/smb/ips.txt" "${nxc_args[@]}" --shares --users --groups \
                > "$OUTDIR/smb/nxc_shares_users.txt" 2>&1 || true
            "$NXC" smb "$OUTDIR/smb/ips.txt" "${nxc_args[@]}" --rid-brute "${ENUM_RID_BRUTE_MAX:-10000}" \
                > "$OUTDIR/smb/nxc_rid_brute.txt" 2>&1 || true
            "$NXC" smb "$OUTDIR/smb/ips.txt" "${nxc_args[@]}" --spider_plus \
                > "$OUTDIR/smb/nxc_spider_plus.txt" 2>&1 || true
        fi
    fi

    if command -v smbclient >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            out="$OUTDIR/smb/${ip}_smbclient_shares.txt"
            if [ "$DRY_RUN" = 1 ]; then
                echo "[DRY] smbclient -L //$ip"
                continue
            fi
            mapfile -t auth < <(smb_auth_args)
            smbclient -L "//$ip" -g "${auth[@]}" > "$out" 2>&1 || true
            awk -F'|' -v ip="$ip" '$1 == "Disk" && $2 !~ /\$$/ {print ip "\t" $2}' "$out"
        done < "$OUTDIR/smb/ips.txt" | sort -u > "$OUTDIR/smb/readable_share_candidates.tsv"

        while IFS=$'\t' read -r ip share; do
            [ -z "$ip" ] || [ -z "$share" ] && continue
            listing="$OUTDIR/smb/${ip}_${share}_recursive_ls.txt"
            if [ "$DRY_RUN" = 1 ]; then
                echo "[DRY] smbclient //$ip/$share -c 'recurse; ls'"
                continue
            fi
            mapfile -t auth < <(smb_auth_args)
            smbclient "//$ip/$share" "${auth[@]}" -c 'recurse; ls' > "$listing" 2>&1 || true
        done < "$OUTDIR/smb/readable_share_candidates.tsv"
    fi

    {
        grep -hEio '[A-Za-z0-9._-]+\$?\)?[[:space:]]+\(SidTypeUser\)|user:[[:space:]]*[A-Za-z0-9._$-]+' \
            "$OUTDIR"/smb/nxc_*.txt 2>/dev/null || true
        grep -hEio 'user:\[[^]]+\]|user rid:\[[^]]+\]' "$OUTDIR"/smb/*.txt 2>/dev/null || true
        grep -hEio 'user:[[:space:]]*[A-Za-z0-9._$-]+' "$OUTDIR"/../smb/*.txt 2>/dev/null || true
    } | sed -E 's/.*[Uu]ser:?[[:space:]\[]*//;s/[])]*$//;s/.*\\//;s/\$//' \
        | grep -E '^[A-Za-z0-9._-]{2,64}$' | sort -u > "$OUTDIR/smb/users.txt"

    grep -HniE 'pass(word|wd)?|secret|token|api[_-]?key|backup|config|\.kdbx|\.pem|id_rsa|qwerty|asdf|1qaz|2wsx|unattend|sysprep|groups\.xml|\.service' \
        "$OUTDIR"/smb/*_recursive_ls.txt "$OUTDIR"/smb/nxc_spider_plus.txt 2>/dev/null \
        > "$OUTDIR/smb/juicy_share_names.txt" || true
}

phase_mounts() {
    [ "$RUN_MOUNTS" = 1 ] || { log "share mounting skipped (use --mount-shares)"; return 0; }
    [ -s "$OUTDIR/smb/readable_share_candidates.tsv" ] || { miss "no share candidates to mount"; return 0; }
    command -v mount >/dev/null 2>&1 || { miss "mount not installed"; return 0; }
    [ "$(id -u)" -eq 0 ] || { miss "--mount-shares requires root/sudo for CIFS mounts"; return 0; }
    credfile=""
    if [ -n "$USER_NAME" ]; then
        credfile="$OUTDIR/smb/.cifs-creds"
        umask 077
        {
            printf 'username=%s\n' "$USER_NAME"
            printf 'password=%s\n' "$PASS"
            [ -n "$DOMAIN" ] && printf 'domain=%s\n' "$DOMAIN"
        } > "$credfile"
        umask 022
    fi
    while IFS=$'\t' read -r ip share; do
        [ -z "$ip" ] || [ -z "$share" ] && continue
        mnt="/mnt/aranum_${ip//[^A-Za-z0-9_.-]/_}_${share//[^A-Za-z0-9_.-]/_}"
        out="$OUTDIR/mounts/${ip}_${share}.txt"
        mkdir -p "$mnt"
        opts="ro,vers=3.0,nounix,noserverino,dir_mode=0555,file_mode=0444"
        if [ -n "$credfile" ]; then opts="$opts,credentials=$credfile"; else opts="$opts,guest"; fi
        log "mount //$ip/$share -> $mnt"
        if mount -t cifs "//$ip/$share" "$mnt" -o "$opts" > "$out" 2>&1; then
            JUICY_MAX_HITS="${JUICY_MAX_HITS:-200}" bash "$JUICY_SCRIPT" --paths "$mnt" \
                > "$OUTDIR/mounts/${ip}_${share}_juicy.txt" 2>&1 || true
            umount "$mnt" >> "$out" 2>&1 || true
        else
            miss "mount failed: //$ip/$share (see $out)"
        fi
    done < "$OUTDIR/smb/readable_share_candidates.tsv"
}

phase_fs_scrape() {
    [ "$RUN_FS_SCRAPE" = 1 ] || { log "filesystem scrape skipped"; return 0; }
    [ -n "$SSH_USER" ] || { miss "filesystem scrape needs --ssh-user"; return 0; }
    [ -r "$JUICY_SCRIPT" ] || { miss "juicy script missing: $JUICY_SCRIPT"; return 0; }
    SSH_TARGETS="$OUTDIR/filesystem/ssh_targets.txt"
    inventory_query ssh | sort -u > "$SSH_TARGETS"
    [ ! -s "$SSH_TARGETS" ] && { miss "no SSH targets"; return 0; }
    KNOWN_HOSTS="$OUTDIR/filesystem/known_hosts"
    : > "$KNOWN_HOSTS"
    while IFS= read -r target; do
        ip=""
        port=""
        if [[ "$target" == \[*\]:* ]]; then
            ip="${target#[}"
            ip="${ip%%]:*}"
            port="${target##*]:}"
        else
            ip="${target%:*}"
            port="${target##*:}"
        fi
        [ -z "$ip" ] && continue
        [ -z "${port:-}" ] && port="$SSH_PORT"
        dest="$ip"; [[ "$ip" == *:* ]] && dest="[$ip]"
        hdir="$OUTDIR/filesystem/$ip"
        mkdir -p "$hdir"
        ssh_args=(-o BatchMode=yes -o "ConnectTimeout=$CONNECT_TIMEOUT" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$KNOWN_HOSTS" -o LogLevel=ERROR)
        [ -n "$SSH_KEY" ] && ssh_args+=(-i "$SSH_KEY")
        ssh_args+=(-p "$port" "$SSH_USER@$dest")
        if [ "$DRY_RUN" = 1 ]; then
            echo "[DRY] ssh ${SSH_USER}@${dest}:${port} 'bash -s' < $JUICY_SCRIPT"
            continue
        fi
        if [ -n "$SSH_PASS" ]; then
            SSHPASS="$SSH_PASS" sshpass -e ssh "${ssh_args[@]}" 'bash -s' \
                < "$JUICY_SCRIPT" > "$hdir/juicy-files.txt" 2> "$hdir/juicy-files.err" || true
        else
            ssh "${ssh_args[@]}" 'bash -s' \
                < "$JUICY_SCRIPT" > "$hdir/juicy-files.txt" 2> "$hdir/juicy-files.err" || true
        fi
    done < "$SSH_TARGETS"
}

phase_ideas() {
    cat > "$OUTDIR/next-ideas.txt" <<'EOF'
Additional iterative enumeration ideas:
- Cert/SAN to vhost expansion: add SANs and discovered hostnames to /etc/hosts, then re-run HTTP source/product/default-creds phases per vhost.
- ADCS and LDAP control-plane checks: Certipy ESC paths, LDAP signing/channel-binding state, password policy, delegation, local admin edges, SCCM NAA credentials.
- IPv6/LLMNR/NBNS poisonability: detect IPv6 RA/DHCPv6 and name-resolution fallback exposure before running responder-style tooling.
- Authenticated web inventory: with supplied creds/cookies, crawl admin portals for users, tokens, integrations, webhooks, runners, package repos, and backup configs.
- Secret material expansion: feed harvested usernames into kerbrute/AS-REP/SPN checks; feed harvested hostnames into DNS reverse/forward sweeps.
- Cloud and platform pivots: search file shares and hosts for kubeconfigs, cloud CLI profiles, Terraform state, CI runner configs, and package registry tokens.
- Backup/admin tier focus: prioritize backup consoles, artifact registries, monitoring, hypervisors, BMCs, and CI/CD because compromise there often crosses many hosts.
EOF
}

phase_hostnames
phase_http_source
phase_default_creds
phase_smb
phase_mounts
phase_fs_scrape
phase_ideas

log "iterative enumeration complete: $OUTDIR"
run_log "=== iterative-enum run complete ==="
