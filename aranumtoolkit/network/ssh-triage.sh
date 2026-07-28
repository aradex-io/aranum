#!/usr/bin/env bash
# ssh-triage.sh — OS-aware SSH sweep dispatcher. ADR-006 Workstream 1b.
#
# Operator has a list of open-22(ish) hosts, or the stdout of an `nxc ssh`
# sweep, and wants Linux vs Windows decided per host so the right bulk-enum
# tool runs against each. This script classifies, THEN shells out to the two
# existing bulk tools — it never reimplements their SSH/WinRM logic.
#
# Input (accept exactly one, or pipe nxc output on stdin):
#   --targets FILE   one host per line: 'host', 'user@host', 'host:port',
#                    or 'user@host:port'. '#' comments / blank lines skipped.
#   --nmap FILE      .xml/.gnmap/.nmap — hosts with an ssh-category port open
#                    (port 22/2222 or nmap-detected ssh service) are extracted
#                    via nmap-parse.py --service ssh.
#   --nxc FILE       stdout of `nxc ssh` / `netexec ssh`, or '-' for stdin.
#                    nxc already prints an OS label in parens — trusted as-is.
#   (no input flag + stdin not a tty -> treated as `--nxc -`)
#
# Classification, cheapest signal first:
#   (a) nxc-printed OS label, when parsing --nxc (trusted, no further probing)
#   (b) SSH pre-auth banner via classify_ssh_os_from_banner (enum-ssh.sh)
#   (c) if still ambiguous AND creds are available (--user/--key/--pass or
#       ENUM_USER/ENUM_PASS), one authenticated probe:
#       `uname -s 2>/dev/null || ver`
#   otherwise: "other" — reported, never dispatched (no guessing).
#
# Output (under --output DIR):
#   classification.tsv         host  os  signal  confidence
#   linux-targets.txt          spec list dispatched to bulk-enum-linux.sh
#   windows-targets.txt        spec list dispatched to bulk-enum-windows.py
#   unknown-hosts.txt          "other" hosts — NOT dispatched
#   linux/                     bulk-enum-linux.sh's own output tree
#   windows/                   bulk-enum-windows.py's own output tree
#
# Dispatch (skipped entirely under --dry-run, which only prints the plan):
#   linux   -> bulk-enum-linux.sh   --targets linux-targets.txt   --output <out>/linux
#   windows -> bulk-enum-windows.py --targets windows-targets.txt --output <out>/windows --transport ssh
#   Pass-through: --user/--key/--pass/--parallel forwarded verbatim to both.
#
# The authenticated classification probe follows the SAME three-mode SSH
# option spec ADR-006 mandates for every new SSH argv builder in this repo
# (KEY / PASS / KEY_THEN_PASS) so this script cannot reintroduce the 1a
# BatchMode+sshpass bug (see ssh_probe_args below). tests/test_ssh_triage.py
# asserts the built argv per mode.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=_lib.sh
. "$SCRIPT_DIR/_lib.sh"
# shellcheck source=enum-ssh.sh
# Sourced, not executed: enum-ssh.sh guards its main body behind a
# BASH_SOURCE==$0 check, so this pulls in only classify_ssh_os_from_banner.
. "$SCRIPT_DIR/enum-ssh.sh"

NMAP_PARSE="$SCRIPT_DIR/nmap-parse.py"

# Bulk tools are resolved via PATH first (so tests can shim
# `bulk-enum-linux.sh` / `bulk-enum-windows.py` ahead of the real ones),
# falling back to the sibling copy that ships in this repo. Never edited by
# this script — always shelled out to.
_resolve_tool() {
    local name="$1" fallback="$2"
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
    else
        printf '%s' "$fallback"
    fi
}
BULK_LINUX="$(_resolve_tool bulk-enum-linux.sh "$SCRIPT_DIR/bulk-enum-linux.sh")"
BULK_WINDOWS="$(_resolve_tool bulk-enum-windows.py "$SCRIPT_DIR/bulk-enum-windows.py")"

usage() {
    cat <<EOF
Usage: $0 (--targets FILE | --nmap FILE | --nxc FILE|-) --output DIR [options]

Input (exactly one; --nxc - or a bare pipe reads stdin):
  --targets FILE     host / user@host / host:port / user@host:port per line
  --nmap FILE        .xml/.gnmap/.nmap — ssh-category open ports extracted
  --nxc FILE|-       \`nxc ssh\` / \`netexec ssh\` stdout (OS label trusted)

Output:
  -o, --output DIR   results dir (classification.tsv + dispatch tree)

Creds (forwarded verbatim to bulk-enum-linux.sh / bulk-enum-windows.py, and
used for this script's own ambiguous-banner auth probe):
  -u, --user USER
  -k, --key FILE
  --pass PASSWORD    WARNING: visible in 'ps'; prefer --key or ssh-agent
  -P, --parallel N

  --dry-run          classify + print the dispatch plan; don't run the
                     bulk tools or touch --output beyond classification.tsv
  -h, --help

Examples:
  $0 --targets hosts.txt -o ./triage -u jay -k ~/.ssh/id_ed25519
  $0 --nmap scan.xml -o ./triage --dry-run
  nxc ssh targets.txt -u a -p b | $0 -o ./triage -u a --pass b
EOF
}

# ---------- option state ----------
TARGETS_FILE=""
NMAP_FILE=""
NXC_FILE=""
OUT=""
DRY_RUN=0
ARG_USER=""
ARG_KEY=""
ARG_PASS=""
ARG_PARALLEL=""

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --targets)     [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           TARGETS_FILE="$2"; shift 2 ;;
            --nmap)        [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           NMAP_FILE="$2"; shift 2 ;;
            --nxc)         [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           NXC_FILE="$2"; shift 2 ;;
            -o|--output)   [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           OUT="$2"; shift 2 ;;
            -u|--user)     [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           ARG_USER="$2"; shift 2 ;;
            -k|--key)      [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           ARG_KEY="$2"; shift 2 ;;
            --pass)        [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           ARG_PASS="$2"; shift 2 ;;
            -P|--parallel) [ $# -ge 2 ] || { err "missing value for $1"; return 1; }
                           ARG_PARALLEL="$2"; shift 2 ;;
            --dry-run)     DRY_RUN=1; shift ;;
            -h|--help)     usage; exit 0 ;;
            *) err "unknown arg: $1"; usage; return 1 ;;
        esac
    done

    local modes=0
    [ -n "$TARGETS_FILE" ] && modes=$((modes + 1))
    [ -n "$NMAP_FILE" ]    && modes=$((modes + 1))
    [ -n "$NXC_FILE" ]     && modes=$((modes + 1))
    if [ "$modes" -eq 0 ] && [ ! -t 0 ]; then
        NXC_FILE="-"
        modes=1
    fi
    if [ "$modes" -ne 1 ]; then
        err "specify exactly one of --targets / --nmap / --nxc (or pipe nxc output on stdin)"
        usage; return 1
    fi
    if [ -n "$TARGETS_FILE" ] && [ ! -f "$TARGETS_FILE" ]; then
        err "--targets file not found: $TARGETS_FILE"; return 1
    fi
    if [ -n "$NMAP_FILE" ] && [ ! -f "$NMAP_FILE" ]; then
        err "--nmap file not found: $NMAP_FILE"; return 1
    fi
    if [ -n "$NXC_FILE" ] && [ "$NXC_FILE" != "-" ] && [ ! -f "$NXC_FILE" ]; then
        err "--nxc file not found: $NXC_FILE"; return 1
    fi
    if [ -z "$OUT" ]; then
        err "missing --output DIR"; usage; return 1
    fi
    return 0
}

# ---------- host inventory ----------
# Keyed by "host|port" (pipe, not colon — colons are legal in bracket-free
# IPv6 host text stored here). Parallel associative arrays instead of a
# single delimited value keep lookups O(1) and avoid re-splitting.
declare -A HOST_RAW HOST_SOURCE HOST_KNOWN_OS HOST_KNOWN_SIGNAL
HOST_ORDER=()

# add_host host port raw [known_os] [known_signal] [source]
# `source` distinguishes a --targets line (whose `raw` is already the exact
# spec bulk-enum-linux.sh/bulk-enum-windows.py expect, incl. any user@ /
# :port) from an nmap/nxc-derived host (no user context — dispatch specs are
# rebuilt from host/port alone). Defaults to "targets" for callers that don't
# pass it explicitly.
add_host() {
    local host="$1" port="$2" raw="$3" known_os="${4:-}" known_signal="${5:-}" source="${6:-targets}"
    local key="${host}|${port}"
    if [ -z "${HOST_RAW[$key]+x}" ]; then
        HOST_ORDER+=("$key")
    fi
    HOST_RAW["$key"]="$raw"
    HOST_SOURCE["$key"]="$source"
    if [ -n "$known_os" ]; then
        HOST_KNOWN_OS["$key"]="$known_os"
        HOST_KNOWN_SIGNAL["$key"]="$known_signal"
    fi
}

# Parse one --targets line: '[user@]host[:port]' (host may be [bracketed]v6).
parse_target_spec() {
    local spec="$1" user host port rest
    spec="${spec%%#*}"
    spec="${spec#"${spec%%[![:space:]]*}"}"
    spec="${spec%"${spec##*[![:space:]]}"}"
    [ -z "$spec" ] && return 0
    if [[ "$spec" == *"@"* ]]; then
        user="${spec%@*}"; rest="${spec#*@}"
    else
        user=""; rest="$spec"
    fi
    if [[ "$rest" == \[*\]:* ]]; then
        host="${rest#[}"; host="${host%%]:*}"; port="${rest##*]:}"
    elif [[ "$rest" == \[*\] ]]; then
        host="${rest#[}"; host="${host%]}"; port="22"
    elif [[ "$rest" == *:* && "$rest" != *::* ]]; then
        host="${rest%:*}"; port="${rest##*:}"
    else
        host="$rest"; port="22"
    fi
    add_host "$host" "$port" "$spec" "" "" "targets"
}

read_targets_file() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        parse_target_spec "$line"
    done < "$TARGETS_FILE"
}

read_nmap_file() {
    local line ip port
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        read -r ip port <<< "$(split_ipport "$line")"
        add_host "$ip" "$port" "$line" "" "" "nmap"
    done < <(python3 "$NMAP_PARSE" "$NMAP_FILE" --service ssh)
}

# One nxc/netexec `ssh` module line looks like:
#   SSH   10.0.0.5   22   10.0.0.5   [*] SSH-2.0-OpenSSH_8.9p1 ... (Linux; protocol 2.0)
# Columns are whitespace-separated; the OS label — when present — is inside
# the trailing parenthetical. Per ADR-006 D1b-1/D1b-2, nxc's label is trusted
# outright; lines with no parenthetical OS fall through to banner/probe
# classification like any other host.
read_nxc_stream() {
    local line ip port os
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [[ "$line" =~ ^SSH[[:space:]]+([^[:space:]]+)[[:space:]]+([0-9]+)[[:space:]] ]]; then
            ip="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
            os=""
            if [[ "$line" =~ \([^\)]*[Ww][Ii][Nn][Dd][Oo][Ww][Ss][^\)]*\) ]]; then
                os="windows"
            elif [[ "$line" =~ \([^\)]*([Ll][Ii][Nn][Uu][Xx]|[Uu][Nn][Ii][Xx])[^\)]*\) ]]; then
                os="linux"
            fi
            if [ -n "$os" ]; then
                add_host "$ip" "$port" "$line" "$os" "nxc" "nxc"
            else
                add_host "$ip" "$port" "$line" "" "" "nxc"
            fi
        fi
    done
}

# ---------- canonical SSH option spec (ADR-006 post-review BLOCKER 1/3) ----------
# Explicit mode, never inferred from "$SSH_PASS is set": KEY / PASS /
# KEY_THEN_PASS / agent-default. Mirrors bulk-enum-linux.sh's (fixed) table
# exactly so this new bash SSH invocation can't re-ship the 1a
# BatchMode+sshpass bug. tests/test_ssh_triage.py asserts the built argv.
#
# Globals consumed: TRIAGE_KEY, TRIAGE_PASS, TRIAGE_KNOWN_HOSTS,
# TRIAGE_CONNECT_TIMEOUT. Emits one arg per line (no -p/-i destination —
# caller appends -p PORT and user@host).
ssh_probe_args() {
    local args=(
        -o "ConnectTimeout=${TRIAGE_CONNECT_TIMEOUT:-5}"
        -o "StrictHostKeyChecking=accept-new"
        -o "UserKnownHostsFile=${TRIAGE_KNOWN_HOSTS:-/dev/null}"
        -o "LogLevel=ERROR"
    )
    if [ -n "${TRIAGE_KEY:-}" ] && [ -n "${TRIAGE_PASS:-}" ]; then
        # KEY_THEN_PASS — try the key first, password is the fallback.
        # Deliberately do NOT set PubkeyAuthentication=no here.
        args+=(-i "$TRIAGE_KEY" -o "IdentitiesOnly=yes")
        args+=(-o "BatchMode=no")
        args+=(-o "PreferredAuthentications=publickey,keyboard-interactive,password")
        args+=(-o "NumberOfPasswordPrompts=1")
    elif [ -n "${TRIAGE_PASS:-}" ]; then
        # PASS only — no BatchMode=yes (would suppress the prompt sshpass answers).
        args+=(-o "PubkeyAuthentication=no")
        args+=(-o "BatchMode=no")
        args+=(-o "PreferredAuthentications=keyboard-interactive,password")
        args+=(-o "NumberOfPasswordPrompts=1")
    elif [ -n "${TRIAGE_KEY:-}" ]; then
        # KEY only.
        args+=(-i "$TRIAGE_KEY" -o "IdentitiesOnly=yes")
        args+=(-o "BatchMode=yes")
        args+=(-o "PreferredAuthentications=publickey")
    else
        # agent-default — rely on ssh-agent, never prompt.
        args+=(-o "BatchMode=yes")
        args+=(-o "PreferredAuthentications=publickey")
    fi
    printf '%s\n' "${args[@]}"
}

_SSHPASS_WARNED=0

# auth_probe_os <host> <port> -> echoes "linux" | "windows" | "other"
# The one authenticated probe ADR-006 D1b-1(b) allows for ambiguous banners:
# `uname -s 2>/dev/null || ver`. Never invoked unless creds are present
# (gated by the caller, classify_host).
auth_probe_os() {
    local host="$1" port="$2"
    local user="${TRIAGE_USER:-${USER:-root}}"
    local dest_host="$host"
    [[ "$host" == *:* ]] && dest_host="[$host]"

    if [ -n "${TRIAGE_PASS:-}" ] && ! have sshpass; then
        if [ "$_SSHPASS_WARNED" = 0 ]; then
            err "--pass given but sshpass not installed — skipping authenticated OS probe"
            _SSHPASS_WARNED=1
        fi
        echo "other"; return 0
    fi

    local ssh_args=()
    while IFS= read -r a; do ssh_args+=("$a"); done < <(ssh_probe_args)
    ssh_args+=(-p "$port" "$user@$dest_host")

    local out
    if [ -n "${TRIAGE_PASS:-}" ]; then
        out=$(SSHPASS="$TRIAGE_PASS" sshpass -e ssh "${ssh_args[@]}" 'uname -s 2>/dev/null || ver' 2>/dev/null) || true
    else
        out=$(ssh "${ssh_args[@]}" 'uname -s 2>/dev/null || ver' 2>/dev/null) || true
    fi

    case "$out" in
        *"Microsoft Windows"*) echo "windows" ;;
        *Linux*|*Darwin*|*FreeBSD*|*OpenBSD*|*SunOS*) echo "linux" ;;
        *) echo "other" ;;
    esac
}

# grab_banner <host> <port> -> echoes the raw "SSH-..." line, or nothing.
# `nc` is already an enum-ssh.sh dependency (its own banner grab uses it) —
# not a new one for this repo.
grab_banner() {
    local host="$1" port="$2"
    have nc || return 0
    nc -w "${TRIAGE_CONNECT_TIMEOUT:-5}" "$host" "$port" </dev/null 2>/dev/null | grep -am1 '^SSH-'
}

# classify_host <host> <port> [known_os] [known_signal]
# Echoes "os\tsignal\tconfidence". known_os/known_signal (set only for
# nxc-sourced hosts whose line carried a trusted OS label) short-circuits
# everything else.
classify_host() {
    local host="$1" port="$2" known_os="${3:-}" known_signal="${4:-}"
    if [ -n "$known_os" ]; then
        printf '%s\t%s\t%s\n' "$known_os" "$known_signal" "high"
        return 0
    fi

    local banner banner_os
    banner="$(grab_banner "$host" "$port")"
    banner_os="$(classify_ssh_os_from_banner "$banner")"
    if [ "$banner_os" != "other" ]; then
        printf '%s\t%s\t%s\n' "$banner_os" "banner" "high"
        return 0
    fi

    if [ "$CREDS_PRESENT" = 1 ]; then
        local probe_os
        probe_os="$(auth_probe_os "$host" "$port")"
        if [ "$probe_os" != "other" ]; then
            printf '%s\t%s\t%s\n' "$probe_os" "auth-probe" "high"
            return 0
        fi
    fi

    printf '%s\t%s\t%s\n' "other" "banner" "low"
}

# ---------- dispatch ----------
build_dispatch_cmd() {
    # $1 = "linux" | "windows"; $2 = targets file; $3 = outdir. Prints one
    # argv element per line (readarray-friendly).
    local bucket="$1" targets_file="$2" outdir="$3"
    local -a cmd
    if [ "$bucket" = "linux" ]; then
        cmd=("$BULK_LINUX" --targets "$targets_file" --output "$outdir")
    else
        cmd=("$BULK_WINDOWS" --targets "$targets_file" --output "$outdir" --transport ssh)
    fi
    [ -n "$ARG_USER" ]     && cmd+=(--user "$ARG_USER")
    [ -n "$ARG_KEY" ]      && cmd+=(--key "$ARG_KEY")
    [ -n "$ARG_PASS" ]     && cmd+=(--pass "$ARG_PASS")
    [ -n "$ARG_PARALLEL" ] && cmd+=(--parallel "$ARG_PARALLEL")
    printf '%s\n' "${cmd[@]}"
}

run_dispatch() {
    local bucket="$1" targets_file="$2" outdir="$3"
    local -a cmd
    while IFS= read -r a; do cmd+=("$a"); done < <(build_dispatch_cmd "$bucket" "$targets_file" "$outdir")

    if [ "$DRY_RUN" = 1 ]; then
        printf '[DRY] %s\n' "${cmd[*]}"
        return 0
    fi
    log "dispatching $bucket -> $outdir"
    mkdir -p "$outdir"
    "${cmd[@]}"
}

main() {
    parse_args "$@" || return 1
    mkdir -p "$OUT"

    CREDS_PRESENT=0
    [ -n "$ARG_USER" ] && CREDS_PRESENT=1
    [ -n "$ARG_KEY" ]  && CREDS_PRESENT=1
    [ -n "$ARG_PASS" ] && CREDS_PRESENT=1
    [ -n "${ENUM_USER:-}" ] && CREDS_PRESENT=1
    [ -n "${ENUM_PASS:-}" ] && CREDS_PRESENT=1

    TRIAGE_USER="${ARG_USER:-${ENUM_USER:-${USER:-root}}}"
    TRIAGE_KEY="$ARG_KEY"
    TRIAGE_PASS="${ARG_PASS:-${ENUM_PASS:-}}"
    TRIAGE_KNOWN_HOSTS="$OUT/known_hosts"
    TRIAGE_CONNECT_TIMEOUT=5
    : > "$TRIAGE_KNOWN_HOSTS"

    if [ -n "$TARGETS_FILE" ]; then
        read_targets_file
    elif [ -n "$NMAP_FILE" ]; then
        read_nmap_file
    elif [ "$NXC_FILE" = "-" ]; then
        read_nxc_stream <&0
    else
        read_nxc_stream < "$NXC_FILE"
    fi

    if [ "${#HOST_ORDER[@]}" -eq 0 ]; then
        err "no hosts extracted from input — nothing to triage"
        return 1
    fi

    local class_file="$OUT/classification.tsv"
    printf 'host\tos\tsignal\tconfidence\n' > "$class_file"

    local -a linux_specs=() windows_specs=() unknown_rows=()
    local key host port raw source known_os known_signal os signal confidence spec display_host

    for key in "${HOST_ORDER[@]}"; do
        host="${key%|*}"
        port="${key##*|}"
        raw="${HOST_RAW[$key]:-}"
        source="${HOST_SOURCE[$key]:-targets}"
        known_os="${HOST_KNOWN_OS[$key]:-}"
        known_signal="${HOST_KNOWN_SIGNAL[$key]:-}"

        IFS=$'\t' read -r os signal confidence <<< "$(classify_host "$host" "$port" "$known_os" "$known_signal")"

        display_host="$host"
        [ "$port" != "22" ] && display_host="$host:$port"
        printf '%s\t%s\t%s\t%s\n' "$display_host" "$os" "$signal" "$confidence" >> "$class_file"

        # A --targets line's `raw` IS the exact spec (incl. any inline user@)
        # bulk-enum-linux.sh/bulk-enum-windows.py expect — reuse verbatim.
        # nmap/nxc-derived hosts carry no user context, so rebuild a bare
        # host[:port] spec instead of the source line (e.g. an nxc log line).
        if [ "$source" = "targets" ]; then
            spec="$raw"
        else
            spec="$host"; [ "$port" != "22" ] && spec="$spec:$port"
        fi

        case "$os" in
            linux)   linux_specs+=("$spec") ;;
            windows) windows_specs+=("$spec") ;;
            *)       unknown_rows+=("$display_host	$os	$signal	$confidence") ;;
        esac
    done

    local n_linux=${#linux_specs[@]} n_windows=${#windows_specs[@]} n_unknown=${#unknown_rows[@]}
    echo "=== ssh-triage classification: $class_file ==="
    echo "  linux:   $n_linux"
    echo "  windows: $n_windows"
    echo "  other:   $n_unknown (not dispatched)"

    if [ "$n_unknown" -gt 0 ]; then
        {
            printf '# hosts ssh-triage could NOT classify — dispatch manually or re-run with creds\n'
            printf 'host\tos\tsignal\tconfidence\n'
            printf '%s\n' "${unknown_rows[@]}"
        } > "$OUT/unknown-hosts.txt"
        echo "  see: $OUT/unknown-hosts.txt"
    fi

    local rc=0
    if [ "$n_linux" -gt 0 ]; then
        printf '%s\n' "${linux_specs[@]}" > "$OUT/linux-targets.txt"
        run_dispatch linux "$OUT/linux-targets.txt" "$OUT/linux" || rc=$?
    fi
    if [ "$n_windows" -gt 0 ]; then
        printf '%s\n' "${windows_specs[@]}" > "$OUT/windows-targets.txt"
        run_dispatch windows "$OUT/windows-targets.txt" "$OUT/windows" || rc=$?
    fi

    return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    exit $?
fi
