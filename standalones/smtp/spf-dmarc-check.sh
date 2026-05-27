#!/usr/bin/env bash
# spf-dmarc-check.sh — analyze a domain's SPF + DKIM + DMARC posture.
# Tells you whether external spoofing of the domain is feasible.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_smtp_lib.sh"

DOMAIN="$1"
[ -z "$DOMAIN" ] && { echo "Usage: $0 <domain>"; exit 1; }

echo "================ MX ================"
dig +short MX "$DOMAIN" | sort

echo
echo "================ SPF ================"
SPF=$(dig +short TXT "$DOMAIN" | grep -i 'v=spf1' | head -1 | tr -d '"')
if [ -z "$SPF" ]; then
    crit "No SPF record — external spoofing of $DOMAIN is unrestricted by SPF"
else
    echo "$SPF"
    if echo "$SPF" | grep -q '~all'; then
        miss "SPF ends with ~all (SoftFail) — receivers may still deliver as spam, not reject"
    elif echo "$SPF" | grep -q '-all'; then
        hit "SPF ends with -all (HardFail) — receivers will reject mismatched senders"
    elif echo "$SPF" | grep -q '?all'; then
        miss "SPF ends with ?all (Neutral) — no enforcement"
    elif echo "$SPF" | grep -q '+all'; then
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
DMARC=$(dig +short TXT "_dmarc.$DOMAIN" | grep -i 'v=DMARC1' | head -1 | tr -d '"')
if [ -z "$DMARC" ]; then
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
    rec=$(dig +short TXT "${sel}._domainkey.${DOMAIN}" | head -1)
    if [ -n "$rec" ]; then
        echo "  selector '$sel': $(echo "$rec" | head -c 80)..."
        FOUND_DKIM=1
    fi
done
[ "$FOUND_DKIM" = 0 ] && miss "No DKIM keys found at common selectors (try dkimscanner for full sweep)"

echo
echo "================ MTA-STS / TLSRPT ================"
MTASTS=$(dig +short TXT "_mta-sts.$DOMAIN" | grep 'v=STSv1' | head -1)
[ -n "$MTASTS" ] && hit "MTA-STS published: $MTASTS" || miss "No MTA-STS — TLS downgrade is undetected"
TLSRPT=$(dig +short TXT "_smtp._tls.$DOMAIN" | grep 'v=TLSRPTv1' | head -1)
[ -n "$TLSRPT" ] && hit "TLSRPT published: $TLSRPT" || miss "No TLSRPT — TLS failures invisible"

echo
echo "================ Verdict ================"
if [ -z "$SPF" ] && [ -z "$DMARC" ]; then
    crit "DOMAIN IS WIDE OPEN — neither SPF nor DMARC. Spoofing externally is trivial."
elif [ "$policy" = "reject" ] && echo "$SPF" | grep -q '\-all'; then
    hit  "Well-defended. External spoofing requires bypassing both SPF-hardfail and DMARC-reject."
elif [ "$policy" = "none" ] || echo "$SPF" | grep -q '?all'; then
    crit "Weakly defended. External spoofing achievable; DMARC reports may be sent but no rejection."
else
    miss "Mixed posture — see individual lines above."
fi
