#!/usr/bin/env bash
# enum-imap.sh — IMAP enumeration (ports 143, 993).
#
# IMAP on port 143 may allow plaintext LOGIN without STARTTLS negotiation.
# Port 993 is IMAPS (TLS). Detecting LOGIN capability without STARTTLS on 143
# is a credential-exposure risk. IMAP's richer protocol surface (folder listing,
# FETCH) makes it useful for post-auth mail collection as well.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "imap: $(wc -l < "$TARGETS") targets -> $OUT"

if ! have nc; then
    miss "nc not installed — imap dispatcher cannot probe"
    exit 0
fi

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    mkdir -p "$OUT/$ip"

    # ---------- banner + CAPABILITY ----------
    if [ "$port" = "993" ]; then
        # IMAPS — TLS probe
        if have openssl; then
            printf 'a1 CAPABILITY\r\na2 LOGOUT\r\n' | \
                timeout 8 openssl s_client -quiet -connect "$ip:$port" \
                    -servername "$ip" < /dev/null \
                    > "$OUT/$ip/banner_${port}.txt" 2>&1 || true
        else
            miss "openssl not installed — skipping TLS banner for $ip:$port"
        fi
    else
        # Plain IMAP
        printf 'a1 CAPABILITY\r\na2 LOGOUT\r\n' | \
            timeout 5 nc -nv -w 3 "$ip" "$port" \
            > "$OUT/$ip/banner_${port}.txt" 2>&1 || true
    fi

    # ---------- check reachability ----------
    if grep -q '\* OK' "$OUT/$ip/banner_${port}.txt" 2>/dev/null; then
        hit "IMAP reachable: $ip:$port"

        # ---------- plaintext-auth check (port 143 only) ----------
        if [ "$port" = "143" ]; then
            has_login=$(grep -qi 'LOGIN' "$OUT/$ip/banner_${port}.txt" 2>/dev/null && echo yes || echo no)
            has_starttls=$(grep -qi 'STARTTLS' "$OUT/$ip/banner_${port}.txt" 2>/dev/null && echo yes || echo no)
            if [ "$has_login" = "yes" ] && [ "$has_starttls" = "no" ]; then
                hit "IMAP plaintext-auth allowed (no STARTTLS): $ip:$port"
            fi
        fi
    fi

    # ---------- nmap IMAP scripts ----------
    if have nmap; then
        nmap -sT -p "$port" \
            --script imap-capabilities,imap-brute \
            --script-timeout 60 \
            $(throttle_nmap_args) \
            "$ip" -oN "$OUT/$ip/imap_${port}.txt" 2>/dev/null || true
    fi

    # ---------- optional cred check ----------
    if [ -n "${ENUM_USER:-}" ] && [ -n "${ENUM_PASS:-}" ] && [ "$port" != "993" ]; then
        printf 'a1 LOGIN %s %s\r\na2 LOGOUT\r\n' \
            "$ENUM_USER" "$ENUM_PASS" | \
            timeout 8 nc -nv -w 5 "$ip" "$port" \
            > "$OUT/$ip/authtry_${port}.txt" 2>&1 || true
        if grep -q 'a1 OK' "$OUT/$ip/authtry_${port}.txt" 2>/dev/null; then
            hit "IMAP AUTH SUCCESS: $ip:$port"
        fi
    fi

    throttle_sleep
done < "$TARGETS"

cat > "$OUT/_hints.txt" <<'EOF'
IMAP follow-ups:
  * List folders after auth: a1 LIST "" "*"
  * Select INBOX: a1 SELECT INBOX
  * Fetch first 5 messages (headers): a1 FETCH 1:5 (BODY[HEADER.FIELDS (FROM TO SUBJECT)])
  * Fetch full body: a1 FETCH <n> BODY[]
  * If STARTTLS is advertised on 143: negotiate TLS before LOGIN
  * Dovecot: check /var/mail/<user> and ~/.Maildir/ on the server if
    you gain shell access — mail spools often contain token reset emails.
  * Plaintext IMAP over port 143 (no STARTTLS) exposes credentials to
    any on-path observer — flag as credential-exposure risk.
EOF

log "imap dispatcher done."
