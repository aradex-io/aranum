#!/usr/bin/env bash
# enum-jabber.sh — XMPP/Jabber server enumeration dispatcher.
#
# Phases (each one is best-effort and survives if a tool is missing):
#   1. Raw TCP banner (nc)
#   2. STARTTLS feature probe + cert / SANs collection (openssl s_client)
#   3. Advertised SASL mechanisms (parsed from the stream-features element)
#   4. XEP-0077 in-band-registration probe (advertised? — no actual register)
#   5. Server `disco#info` + `disco#items` (anon stream — many servers expose this)
#   6. MUC discovery on `conference.<derived-domain>`
#   7. BOSH / WebSocket endpoint detection on 5280 / 5281
#
# All probes are READ-ONLY. No state changes on the target.
# Domain is derived from the cert's CN/SAN if --domain not passed via env.
#
# Output: $OUT/<ip>_<port>/<phase>.{txt,xml,pem}

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"
parse_common_args "$@" || exit 1
log "jabber: $(wc -l < "$TARGETS") targets -> $OUT"

# Optional override: explicit XMPP domain (the to= attribute on the stream open
# matters — some servers refuse the stream if the JID domain doesn't match).
# Otherwise we extract it from the server cert's SAN/CN per host.
ENUM_XMPP_DOMAIN="${ENUM_XMPP_DOMAIN:-}"

# ---------------------------------------------------------------- helpers

# Send an XMPP stream-open and read the first chunk back. Used for SASL-mech
# discovery and IBR-advertised check on cleartext / STARTTLS-negotiable ports.
# Args: ip port domain
# Echoes the raw bytes received (best-effort, with a 5s read window).
xmpp_stream_open() {
    local ip="$1" port="$2" domain="$3"
    local req="<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='${domain}' version='1.0'>"
    # Some servers buffer; allow nc to drain for ~3s after we send the open.
    printf '%s' "$req" | timeout 5 nc -nv -w 3 "$ip" "$port" 2>/dev/null
}

# Try to extract a usable XMPP domain for a host. Order:
#   1. ENUM_XMPP_DOMAIN env (operator-supplied — wins)
#   2. SAN/CN from a passive openssl s_client probe
#   3. The IP itself (last resort — many servers refuse this)
derive_domain() {
    local ip="$1" port="$2"
    if [ -n "$ENUM_XMPP_DOMAIN" ]; then
        echo "$ENUM_XMPP_DOMAIN"; return
    fi
    # Try a STARTTLS-negotiated cert pull. -starttls xmpp is supported by
    # openssl 1.0.2+ for the c2s 5222 port; for 5223 (implicit TLS) we use
    # plain s_client without -starttls.
    local cert
    case "$port" in
        5223|9091) cert=$(timeout 5 openssl s_client -connect "$ip:$port" -servername "$ip" </dev/null 2>/dev/null) ;;
        *)         cert=$(timeout 5 openssl s_client -connect "$ip:$port" -starttls xmpp -xmpphost "$ip" </dev/null 2>/dev/null) ;;
    esac
    # Parse SAN first, then CN
    local san cn
    san=$(printf '%s' "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null | \
          grep -oE 'DNS:[^,[:space:]]+' | head -1 | sed 's/^DNS://')
    if [ -n "$san" ]; then echo "$san"; return; fi
    cn=$(printf '%s' "$cert" | openssl x509 -noout -subject 2>/dev/null | \
         sed -n 's/.*CN ?= ?\([^,/]*\).*/\1/p' | head -1 | tr -d '[:space:]')
    if [ -n "$cn" ]; then echo "$cn"; return; fi
    echo "$ip"
}

# Extract advertised SASL mechs from a stream-features blob.
parse_sasl_mechs() {
    grep -oE '<mechanism>[^<]+</mechanism>' | sed 's/<[^>]*>//g' | sort -u
}

# Does the stream-features blob advertise XEP-0077 in-band registration?
ibr_advertised() {
    grep -q '<register xmlns="http://jabber.org/features/iq-register"' \
      || grep -q "<register xmlns='http://jabber.org/features/iq-register'"
}

# ---------------------------------------------------------------- main loop
have_nc=0; have nc       && have_nc=1
have_ssl=0; have openssl && have_ssl=1
have_curl=0; have curl   && have_curl=1
[ "$have_nc"  = 0 ] && miss "nc not installed — phases 1/3/4 will be skipped"
[ "$have_ssl" = 0 ] && miss "openssl not installed — phase 2 and STARTTLS-needing parts of phase 3 will be skipped"

while read -r target; do
    [ -z "$target" ] && continue
    read -r ip port <<< "$(split_ipport "$target")"
    out_dir="$OUT/${ip}_${port}"
    mkdir -p "$out_dir"
    log "  $ip:$port"

    domain=$(derive_domain "$ip" "$port")
    echo "$domain" > "$out_dir/derived_domain.txt"
    log "    derived domain: $domain"

    # --- 1. raw banner ---
    if [ "$have_nc" = 1 ]; then
        timeout 5 nc -nv -w 3 "$ip" "$port" </dev/null > "$out_dir/banner.txt" 2>&1 || true
    fi

    # --- 2. cert + SANs ---
    if [ "$have_ssl" = 1 ]; then
        case "$port" in
            5223|9091)
                timeout 8 openssl s_client -connect "$ip:$port" -servername "$domain" \
                    -showcerts </dev/null > "$out_dir/cert_raw.txt" 2>&1 || true ;;
            5222|5269)
                timeout 8 openssl s_client -connect "$ip:$port" -starttls xmpp \
                    -xmpphost "$domain" -showcerts </dev/null > "$out_dir/cert_raw.txt" 2>&1 || true ;;
            5280|5281|7777)
                # HTTP-fronted endpoints — TLS only on 5281 / sometimes 7777
                timeout 8 openssl s_client -connect "$ip:$port" -servername "$domain" \
                    -showcerts </dev/null > "$out_dir/cert_raw.txt" 2>&1 || true ;;
        esac
        # Extract a single PEM + SANs for downstream use
        if [ -s "$out_dir/cert_raw.txt" ]; then
            awk '/-----BEGIN CERT/{f=1} f{print} /-----END CERT/{f=0; exit}' \
                "$out_dir/cert_raw.txt" > "$out_dir/cert.pem"
            if [ -s "$out_dir/cert.pem" ]; then
                openssl x509 -in "$out_dir/cert.pem" -noout -text 2>/dev/null \
                    | grep -E 'Subject:|DNS:' > "$out_dir/cert_sans.txt" || true
            fi
        fi
    fi

    # --- 3. stream features (SASL mechs, IBR, STARTTLS advertised?) ---
    if [ "$have_nc" = 1 ]; then
        features=$(xmpp_stream_open "$ip" "$port" "$domain")
        echo "$features" > "$out_dir/stream_features.xml"
        echo "$features" | parse_sasl_mechs > "$out_dir/sasl_mechs.txt"
        if echo "$features" | ibr_advertised; then
            echo "ADVERTISED — XEP-0077 in-band registration is offered. Probe further with jabber-user-enum.py." \
                 > "$out_dir/ibr_probe.txt"
        else
            echo "NOT_ADVERTISED — server does not offer XEP-0077 IBR (or stream open failed)." \
                 > "$out_dir/ibr_probe.txt"
        fi
        if echo "$features" | grep -q 'starttls xmlns'; then
            echo "ADVERTISED" > "$out_dir/starttls.txt"
        else
            echo "NOT_ADVERTISED — server may speak plaintext-only, or this port is implicit-TLS already." \
                 > "$out_dir/starttls.txt"
        fi
    fi

    # --- 4. disco#info + disco#items (anonymous attempt) ---
    # Servers that allow anon-bind disclose hosted services here; even servers
    # that don't accept anon often leak component lists in response to a
    # well-formed but un-auth'd IQ. We send it on the same stream-open.
    if [ "$have_nc" = 1 ] && [ "$port" = "5222" ]; then
        {
            printf "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>" "$domain"
            sleep 1
            printf "<iq type='get' id='disco1' to='%s'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>" "$domain"
            printf "<iq type='get' id='disco2' to='%s'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>" "$domain"
            sleep 2
        } | timeout 8 nc -nv -w 5 "$ip" "$port" 2>/dev/null > "$out_dir/disco.xml" || true
    fi

    # --- 5. MUC discovery on conference.<domain> ---
    # Just disco#items on the conventional MUC subdomain — many servers
    # respond even without auth, especially if anon-bind is enabled.
    muc_domain="conference.${domain}"
    if [ "$have_nc" = 1 ] && [ "$port" = "5222" ]; then
        {
            printf "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>" "$domain"
            sleep 1
            printf "<iq type='get' id='muc1' to='%s'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>" "$muc_domain"
            sleep 2
        } | timeout 8 nc -nv -w 5 "$ip" "$port" 2>/dev/null > "$out_dir/muc_items.xml" || true
    fi

    # --- 6. BOSH / WebSocket endpoint detection on 5280 / 5281 ---
    if [ "$have_curl" = 1 ] && { [ "$port" = "5280" ] || [ "$port" = "5281" ]; }; then
        local_scheme="http"
        [ "$port" = "5281" ] && local_scheme="https"
        for path in "/http-bind/" "/http-bind" "/bosh" "/xmpp-websocket" "/ws-xmpp"; do
            safe=$(echo "$path" | tr -d '/')
            [ -z "$safe" ] && safe="root"
            curl -ksI --connect-timeout 5 --max-time 10 \
                 "${local_scheme}://${ip}:${port}${path}" \
                 > "$out_dir/bosh_${safe}.txt" 2>&1 || true
        done
    fi

    # --- 7. admin-API exposure probe (Ejabberd /api/, Prosody mod_admin_*) ---
    # One per HOST (not per port — the probe targets fixed admin ports of its own)
    # so we de-dupe by tracking IPs we've already probed in this run.
    probe_marker="$OUT/_admin_probed_${ip}.done"
    if [ ! -e "$probe_marker" ]; then
        admin_probe="$SCRIPT_DIR/../../standalones/jabber/jabber-admin-api-probe.sh"
        if [ -x "$admin_probe" ]; then
            bash "$admin_probe" --host "$ip" --out "$out_dir" >> "$out_dir/_admin_probe.log" 2>&1 || true
            touch "$probe_marker"
        fi
    fi

done < "$TARGETS"

# Final hint with workflow pointers
cat > "$OUT/_hints.txt" <<'EOF'
Next steps once the dispatcher has populated $OUT:

  * If sasl_mechs.txt advertises PLAIN over a plaintext socket — flag immediately.
  * If ibr_probe.txt says ADVERTISED — run jabber-user-enum.py for username harvest.
  * If you have a candidate credential — run jabber-validate.py against it.
  * If openfire-admin was also enumerated (ports 9090/9091) — run the
    openfire-cve-2023-32315 helper in detection mode against those hosts.
  * The admin-API probe runs automatically (jabber-admin-api-probe.sh) and
    surfaces any EXPOSED ejabberd-api / prosody-mod_admin_telnet / mod_admin_web
    findings inline in this dispatcher's log.
EOF

# Clean up per-host probe markers
rm -f "$OUT"/_admin_probed_*.done

log "jabber dispatcher done."
