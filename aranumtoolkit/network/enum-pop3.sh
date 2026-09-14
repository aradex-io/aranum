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

pop3_exchange() {
    local ip="$1" port="$2" connect="$1:$2"
    [[ "$ip" == *:* ]] && connect="[$ip]:$port"
    if [ "$port" = "995" ]; then
        have openssl || return 127
        timeout 8 openssl s_client -quiet -connect "$connect" -servername "$ip"
    else
        have nc || return 127
        timeout 8 nc -nv -w 5 "$ip" "$port"
    fi
}

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- banner + CAPA ----------
    if [ "$port" = "995" ]; then
        # POP3S — TLS probe
        if have openssl; then
            printf 'CAPA\r\nQUIT\r\n' | \
                pop3_exchange "$ip" "$port" \
                    > "$OUT/$ip/banner_${port}.txt" 2>&1 || true
        else
            miss "openssl not installed — skipping TLS banner for $ip:$port"
        fi
    else
        # Plain POP3
        printf 'CAPA\r\nQUIT\r\n' | \
            pop3_exchange "$ip" "$port" \
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
    if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ]; then
        printf 'USER %s\r\nPASS %s\r\nSTAT\r\nQUIT\r\n' \
            "$ENUM_USER" "$ENUM_PASS" | \
            pop3_exchange "$ip" "$port" \
            > "$OUT/$ip/authtry_${port}.txt" 2>&1 || true
        # With USER/PASS/STAT/QUIT there is one greeting followed by one reply
        # per command. The third status line is therefore the PASS result; an
        # accepted USER or QUIT can never substitute for it.
        pass_reply=$(grep -E '^\+OK([[:space:]]|$)|^-ERR([[:space:]]|$)' \
            "$OUT/$ip/authtry_${port}.txt" 2>/dev/null | sed -n '3p')
        if [[ "$pass_reply" == +OK* ]]; then
            hit "POP3 AUTH SUCCESS: $ip:$port"
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
