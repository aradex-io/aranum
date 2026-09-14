#!/usr/bin/env bash
# spf-dmarc-check.sh — analyze a domain's SPF + DKIM + DMARC posture.
# Tells you whether external spoofing of the domain is feasible.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_smtp_lib.sh"

DOMAIN="${1:-}"
[ -z "$DOMAIN" ] && { echo "Usage: $0 <domain>"; exit 1; }
DNS_LOOKUP_FAILED=0

dig_txt() {
    local name="$1" raw
    if ! raw=$(dig +short TXT "$name" 2>&1); then
        err "DNS TXT lookup failed for $name: ${raw:-no diagnostic}" >&2
        return 1
    fi
    printf '%s\n' "$raw"
}

echo "================ MX ================"
if ! MX_RAW=$(dig +short MX "$DOMAIN" 2>&1); then
    err "DNS MX lookup failed for $DOMAIN: ${MX_RAW:-no diagnostic}"
    DNS_LOOKUP_FAILED=1
else
    printf '%s\n' "$MX_RAW" | sort
fi

echo
echo "================ SPF ================"
SPF=""; SPF_LOOKUP_OK=0
if SPF_RAW=$(dig_txt "$DOMAIN"); then
    SPF_LOOKUP_OK=1
    SPF=$(printf '%s\n' "$SPF_RAW" | awk 'BEGIN{IGNORECASE=1} /v=spf1/{gsub(/"/, ""); print; exit}')
else
    DNS_LOOKUP_FAILED=1
fi
if [ "$SPF_LOOKUP_OK" = 0 ]; then
    miss "SPF posture indeterminate because the DNS lookup failed"
elif [ -z "$SPF" ]; then
    crit "No SPF record — external spoofing of $DOMAIN is unrestricted by SPF"
else
    echo "$SPF"
    if echo "$SPF" | grep -q -- '~all'; then
        miss "SPF ends with ~all (SoftFail) — receivers may still deliver as spam, not reject"
    elif echo "$SPF" | grep -q -- '-all'; then
        hit "SPF ends with -all (HardFail) — receivers will reject mismatched senders"
    elif echo "$SPF" | grep -q -- '?all'; then
        miss "SPF ends with ?all (Neutral) — no enforcement"
    elif echo "$SPF" | grep -q -- '+all'; then
        crit "SPF ends with +all — ANYONE can pass SPF for $DOMAIN. Spoofing trivial."
    fi
    # Count DNS lookups (SPF limit is 10)
    lookups=$(echo "$SPF" | grep -oE '\b(include:|a:|mx:|exists:|redirect=)' | wc -l)
    if [ "$lookups" -gt 10 ]; then
        miss "SPF has $lookups DNS lookups — exceeds RFC 7208 limit of 10 (causes PermError, breaks SPF)"
    fi
fi

echo
echo "================ DMARC ================"
policy=""; sub_policy=""; pct=""; rua=""; DMARC=""; DMARC_LOOKUP_OK=0
if DMARC_RAW=$(dig_txt "_dmarc.$DOMAIN"); then
    DMARC_LOOKUP_OK=1
    DMARC=$(printf '%s\n' "$DMARC_RAW" | awk 'BEGIN{IGNORECASE=1} /v=DMARC1/{gsub(/"/, ""); print; exit}')
else
    DNS_LOOKUP_FAILED=1
fi
if [ "$DMARC_LOOKUP_OK" = 0 ]; then
    miss "DMARC posture indeterminate because the DNS lookup failed"
elif [ -z "$DMARC" ]; then
    crit "No DMARC record — even with SPF, receivers have no policy guidance. Spoofing feasible."
else
    echo "$DMARC"
    policy=$(echo "$DMARC" | grep -oE 'p=[a-z]+' | head -1 | cut -d= -f2)
    sub_policy=$(echo "$DMARC" | grep -oE 'sp=[a-z]+' | head -1 | cut -d= -f2)
    pct=$(echo "$DMARC" | grep -oE 'pct=[0-9]+' | head -1 | cut -d= -f2)
    case "$policy" in
        reject)     hit "DMARC policy: reject — external spoofing blocked by DMARC-honoring receivers" ;;
        quarantine) miss "DMARC policy: quarantine — spoofed mail goes to junk (still delivers)" ;;
        none)       crit "DMARC policy: none — monitoring only, no enforcement. Spoofing feasible." ;;
        *)          err  "DMARC policy unrecognized: $policy" ;;
    esac
    [ -n "$pct" ] && [ "$pct" -lt 100 ] && miss "DMARC pct=$pct — policy applies to only $pct% of mail"
    [ -n "$sub_policy" ] && [ "$sub_policy" != "$policy" ] && \
        miss "DMARC sub-policy ($sub_policy) differs from main ($policy) — subdomain spoofing may be easier"

    # Check RUA destination — often a third-party reporting tool
    rua=$(echo "$DMARC" | grep -oE 'rua=mailto:[^;]+')
    [ -n "$rua" ] && echo "  $rua"
fi

echo
echo "================ DKIM (common selectors) ================"
FOUND_DKIM=0
for sel in default selector1 selector2 google k1 dkim mail s1 s2 mta sm sib mxv mailo; do
    if ! rec=$(dig +short TXT "${sel}._domainkey.${DOMAIN}" 2>&1); then
        err "DNS TXT lookup failed for ${sel}._domainkey.${DOMAIN}: ${rec:-no diagnostic}"
        DNS_LOOKUP_FAILED=1
        continue
    fi
    rec=$(printf '%s\n' "$rec" | head -1)
    if [ -n "$rec" ]; then
        echo "  selector '$sel': $(echo "$rec" | head -c 80)..."
        FOUND_DKIM=1
    fi
done
[ "$FOUND_DKIM" = 0 ] && miss "No DKIM keys found at common selectors (try dkimscanner for full sweep)"

echo
echo "================ MTA-STS / TLSRPT ================"
if ! MTASTS_RAW=$(dig +short TXT "_mta-sts.$DOMAIN" 2>&1); then
    err "DNS TXT lookup failed for _mta-sts.$DOMAIN: ${MTASTS_RAW:-no diagnostic}"
    DNS_LOOKUP_FAILED=1; MTASTS_RAW=""
fi
MTASTS=$(printf '%s\n' "$MTASTS_RAW" | grep 'v=STSv1' | head -1)
[ -n "$MTASTS" ] && hit "MTA-STS published: $MTASTS" || miss "No MTA-STS — TLS downgrade is undetected"
if ! TLSRPT_RAW=$(dig +short TXT "_smtp._tls.$DOMAIN" 2>&1); then
    err "DNS TXT lookup failed for _smtp._tls.$DOMAIN: ${TLSRPT_RAW:-no diagnostic}"
    DNS_LOOKUP_FAILED=1; TLSRPT_RAW=""
fi
TLSRPT=$(printf '%s\n' "$TLSRPT_RAW" | grep 'v=TLSRPTv1' | head -1)
[ -n "$TLSRPT" ] && hit "TLSRPT published: $TLSRPT" || miss "No TLSRPT — TLS failures invisible"

echo
echo "================ Verdict ================"
if [ "$DNS_LOOKUP_FAILED" != 0 ]; then
    err "INDETERMINATE — one or more DNS lookups failed; no spoofing posture verdict is safe"
    exit 2
elif [ -z "$SPF" ] && [ -z "$DMARC" ]; then
    crit "DOMAIN IS WIDE OPEN — neither SPF nor DMARC. Spoofing externally is trivial."
elif [ "$policy" = "reject" ] && echo "$SPF" | grep -q -- '-all'; then
    hit  "Well-defended. External spoofing requires bypassing both SPF-hardfail and DMARC-reject."
elif [ "$policy" = "none" ] || echo "$SPF" | grep -q -- '?all'; then
    crit "Weakly defended. External spoofing achievable; DMARC reports may be sent but no rejection."
else
    miss "Mixed posture — see individual lines above."
fi
