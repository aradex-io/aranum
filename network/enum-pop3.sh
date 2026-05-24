#!/usr/bin/env bash
# enum-pop3.sh — POP3 enumeration (ports 110, 995).
#
# POP3 on port 110 frequently allows plaintext authentication (USER/PASS commands)
# without STLS. Port 995 is POP3S (TLS). Detecting plaintext auth on 110 without
# a STLS upgrade is a credential-exposure risk.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "pop3: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nc; then
    miss "nc not installed — pop3 dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- banner + CAPA ----------
    if [ "$port" = "995" ]; then
        # POP3S — TLS probe
        if have openssl; then
            printf 'CAPA\r\nQUIT\r\n' | \
                timeout 8 openssl s_client -quiet -connect "$ip:$port" \
                    -servername "$ip" < /dev/null \
                    > "$OUT/$ip/banner_${port}.txt" 2>&1 || true
        else
            miss "openssl not installed — skipping TLS banner for $ip:$port"
        fi
    else
        # Plain POP3
        printf 'CAPA\r\nQUIT\r\n' | \
            timeout 5 nc -nv -w 3 "$ip" "$port" \
            > "$OUT/$ip/banner_${port}.txt" 2>&1 || true
    fi

    # ---------- check reachability ----------
    if grep -q '+OK' "$OUT/$ip/banner_${port}.txt" 2>/dev/null; then
        hit "POP3 reachable: $ip:$port"

        # ---------- plaintext-auth check (port 110 only) ----------
        if [ "$port" = "110" ]; then
            has_user=$(grep -qi 'USER' "$OUT/$ip/banner_${port}.txt" 2>/dev/null && echo yes || echo no)
            has_stls=$(grep -qi 'STLS' "$OUT/$ip/banner_${port}.txt" 2>/dev/null && echo yes || echo no)
            if [ "$has_user" = "yes" ] && [ "$has_stls" = "no" ]; then
                hit "POP3 plaintext-auth allowed (no STLS): $ip:$port"
            fi
        fi
    fi

    # ---------- nmap POP3 scripts ----------
    if have nmap; then
        nmap -sT -p "$port" \
            --script pop3-capabilities,pop3-brute \
            --script-timeout 60 \
            "${THROTTLE_NMAP_ARGS[@]}" \
            "$ip" -oN "$OUT/$ip/pop3_${port}.txt" 2>/dev/null || true
    fi

    # ---------- optional cred check ----------
    if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && [ "$port" != "995" ]; then
        printf 'USER %s\r\nPASS %s\r\nSTAT\r\nQUIT\r\n' \
            "$ENUM_USER" "$ENUM_PASS" | \
            timeout 8 nc -nv -w 5 "$ip" "$port" \
            > "$OUT/$ip/authtry_${port}.txt" 2>&1 || true
        if grep -q '+OK' "$OUT/$ip/authtry_${port}.txt" 2>/dev/null; then
            # Must see +OK after PASS (second +OK line)
            ok_count=$(grep -c '+OK' "$OUT/$ip/authtry_${port}.txt" 2>/dev/null || echo 0)
            if [ "$ok_count" -ge 2 ]; then
                hit "POP3 AUTH SUCCESS: $ip:$port"
            fi
        fi
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
POP3 follow-ups:
  * List messages after auth: LIST (returns <msg-num> <size> pairs)
  * Get unique IDs: UIDL
  * Retrieve message N: RETR <n>
  * Delete message N: DELE <n> (requires QUIT to commit)
  * If STLS is advertised on 110: try STARTTLS upgrade before USER/PASS
  * Dovecot / Courier expose usernames via APOP timing on older versions.
  * Plaintext POP3 over port 110 (no STLS) exposes credentials to any
    on-path observer — flag as credential-exposure risk in the report.
EOF

log "pop3 dispatcher done."
