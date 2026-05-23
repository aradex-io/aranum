#!/usr/bin/env bash
# enum-print.sh — Network print service enumeration.
#
# Covers two protocols that the IPP (631) dispatcher does not:
#   - HP JetDirect / raw print on 9100 (PJL info commands)
#   - LPD / line-printer daemon on 515 (RFC 1179 banner + show-queue probe)
#
# Both are unauthenticated by default and historically disclose:
#   - Firmware revision (JetDirect PJL @PJL INFO ID / @PJL INFO PRODINFO)
#   - Installed RAM / page count / device serial / model (JetDirect)
#   - Per-queue job inventory (LPD short-format queue probe)
# Print servers also frequently leak captured creds in stored job names
# and PJL filesystem (PJL FSDIRLIST) — out of scope for the default probe;
# operator follows the _hints.txt for that.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "print: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nc; then
    miss "nc not installed — print dispatcher cannot probe"
    exit 0
fi

# Port routing — production defaults are 9100 (JetDirect/PJL) and 515 (LPD).
# Test seam: PRINT_EXTRA_JETDIRECT_PORT / PRINT_EXTRA_LPD_PORT add a single
# extra port to either list (used by tests/fp-harness.sh to point at stubs
# that cannot bind on privileged ports).
declare -a JETDIRECT_PORTS=(9100)
declare -a LPD_PORTS=(515)
[ -n "${PRINT_EXTRA_JETDIRECT_PORT:-}" ] && JETDIRECT_PORTS+=("$PRINT_EXTRA_JETDIRECT_PORT")
[ -n "${PRINT_EXTRA_LPD_PORT:-}" ]       && LPD_PORTS+=("$PRINT_EXTRA_LPD_PORT")

_port_matches() {
    local needle="$1"; shift
    local n
    for n in "$@"; do [ "$n" = "$needle" ] && return 0; done
    return 1
}

# Two-evidence discipline:
#   - JetDirect 9100: a PJL response begins with the framing bytes
#     `\x1b%-12345X@PJL` (UEL + @PJL). Match on this AND on at least one
#     of @PJL INFO ID / PRODINFO / STATUS / VARIABLES — not just "PJL"
#     anywhere in the response.
#   - LPD 515: RFC 1179 short-form response to a `\x04<queue>\n` command
#     starts with either ASCII queue listing OR ACK byte 0x00 followed by
#     queue dump. A bare `accept-then-close` does not match.

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    if _port_matches "$port" "${JETDIRECT_PORTS[@]}"; then
        proto="jetdirect"
    elif _port_matches "$port" "${LPD_PORTS[@]}"; then
        proto="lpd"
    else
        proto="unsupported"
    fi

    case "$proto" in
        jetdirect)
            # ---------- JetDirect / PJL ----------
            pjl_file="$OUT/$ip/jetdirect_${port}.txt"
            # Send UEL + PJL INFO ID + PJL INFO PRODINFO + UEL exit.
            # Sequence: \x1b%-12345X opens, \x1b%-12345X closes.
            # Note: real printers respond within 1-2s; bump timeout for
            # slow embedded firmware.
            printf '\x1b%%-12345X@PJL INFO ID\r\n@PJL INFO PRODINFO\r\n@PJL INFO STATUS\r\n\x1b%%-12345X\r\n' \
                | timeout 8 nc -nv -w 5 "$ip" "$port" \
                > "$pjl_file" 2>&1 || true

            # Two-evidence guard
            if grep -q $'\x1b%-12345X' "$pjl_file" 2>/dev/null \
               && grep -qE '@PJL (INFO ID|INFO PRODINFO|INFO STATUS|INFO VARIABLES)' "$pjl_file" 2>/dev/null; then
                # Extract device model (PJL INFO ID's first quoted token)
                model=$(grep -oE '"[^"]+"' "$pjl_file" | head -1 | tr -d '"' || true)
                [ -z "$model" ] && model="unknown"
                hit "JetDirect / PJL UNAUTH: $ip:$port — model=${model}"

                # Page count is a useful "this printer is in production"
                # signal — search PJL output for it but only emit as INFO.
                pages=$(grep -oE 'PAGE COUNT[[:space:]]*[=:]?[[:space:]]*[0-9]+' "$pjl_file" \
                    | head -1 | grep -oE '[0-9]+' || true)
                [ -n "$pages" ] && log "JetDirect page count: $ip:$port — pages=${pages}"
            fi
            ;;

        lpd)
            # ---------- LPD ----------
            lpd_file="$OUT/$ip/lpd_${port}.txt"
            # RFC 1179 short-form "show queue state": `\x04<qname>\n`.
            # Many devices accept `\x04PASSTHRU\n` or queue name `lp`.
            # We try `lp` first (universal default), capture banner.
            printf '\x04lp\n' \
                | timeout 6 nc -nv -w 5 "$ip" "$port" \
                > "$lpd_file" 2>&1 || true

            # Two-evidence: response must be non-empty AND contain either
            # a queue-status keyword (Rank/Owner/Job/Files/Size are RFC 1179
            # short-format column headers) OR an LPD error message ("queue
            # does not exist" / "Permission denied").
            if [ -s "$lpd_file" ]; then
                if grep -qE '(Rank|Owner|Job|Files|Total size|no entries|Permission denied|queue (does not exist|is disabled))' \
                    "$lpd_file" 2>/dev/null; then
                    # Reachable LPD daemon — pull a one-line signature.
                    first_line=$(head -1 "$lpd_file" | tr -d '\r' | cut -c1-80)
                    hit "LPD reachable: $ip:$port — banner: ${first_line:-<empty>}"

                    # If we got a queue dump (Rank/Owner header), record it
                    # as MEDIUM-grade evidence — operator may find creds in
                    # historical job names.
                    if grep -qE '^(Rank|active|no entries)' "$lpd_file" 2>/dev/null; then
                        log "LPD queue state captured: $ip:$port — see $lpd_file"
                    fi
                fi
            fi
            ;;

        unsupported|*)
            # Unknown port for this dispatcher — log and skip, do not probe
            log "print: unsupported port $ip:$port (expected 9100 or 515)"
            ;;
    esac

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
Network print service follow-ups:

  JetDirect (9100):
    * Dump PJL filesystem (firmware/configs/captured-job-spool):
        printf '\x1b%-12345X@PJL FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=999\r\n\x1b%-12345X\r\n' \
          | nc -nv <ip> 9100
    * PRET (Printer Exploitation Toolkit) for full PJL/PostScript/PCL inspect:
        pret <ip> pjl
    * Watch for stored captured-job-spool entries that contain credentials
      in job names — historical hardcopy of SSL certificate enrollments.

  LPD (515):
    * RFC 1179 commands: \x01 (Print job), \x02 (Receive job), \x03 (Get queue
      long), \x04 (Get queue short), \x05 (Remove job).
    * Some daemons accept \x02 with no auth — recipe for unauthenticated
      print floods. Do NOT exercise without explicit operator authorization.
    * Vendor web admin consoles on 80/443 frequently have default creds
      (admin/admin, admin/0000, admin/password) — see enum-http.sh.

  Defensive note:
    * 9100 raw print and 515 LPD have NO authentication by design. The
      mitigations are network ACLs and disabling unused protocols (IPP
      with auth is the modern path).
EOF

log "print dispatcher done."
