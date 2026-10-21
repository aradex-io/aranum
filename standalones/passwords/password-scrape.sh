#!/usr/bin/env bash
# password-scrape.sh — compliance scanner: find passwords & secrets typed into
#                      shell history and logs.
#
# Authorized testing / internal compliance only. READ-ONLY: this script never writes
# to a target, never modifies the files it scans, and never phones home. It reads the
# paths (or stdin) you hand it — or the standard shell-history/log locations with
# --history — and reports every token that looks like a credential someone typed.
#
# PRIMARY USE CASE
#   Shell history hygiene. Operators and admins routinely paste or type passwords
#   straight into a command line, where they are persisted forever in:
#       ~/.bash_history  ~/.zsh_history  ~/.*_history
#       PSReadLine ConsoleHost_history.txt   (PowerShell, see Get-WeakPassword.ps1)
#       /var/log/*  (sudo, auth, app logs that echoed a secret)
#   This scanner flags those so they can be scrubbed and the credential rotated.
#
# TWO BANKS (both scanned by default):
#   1. WEAK-PASSWORD shapes — "Password1!", keyboard walks (qwerty / 1qaz2wsx /
#      zxcvbn / qazwsx), seasons+year, sequences, repeats, leet "p@ssw0rd",
#      common base words.
#   2. SECRET / CREDENTIAL EXPOSURE "key terms" — command-line password flags
#      (--password, mysql -p, sshpass -p, net user), secret env vars (PGPASSWORD,
#      AWS_SECRET_ACCESS_KEY, ...), provider API keys/tokens (AWS AKIA, GitHub ghp_,
#      Slack xox*, Google AIza, Stripe, JWT, OpenAI sk-), private-key headers,
#      DB/URL connection strings with embedded creds, and Authorization headers.
#
# Output path (if any) is the one YOU pass via --out; there are no global loot dirs.
# Style: CLAUDE.md §8 (set -uo pipefail, [[ ]], quoted vars, no eval).
set -uo pipefail

PROG="${0##*/}"

# ---- defaults -------------------------------------------------------------
MINLEN=6              # ignore matched tokens shorter than this
MAXLEN=512           # ignore absurdly long tokens
RECURSE=1            # grep -r handles dirs; --no-recurse to only read named files
LOOSE=0              # --loose: also match word+digits with NO trailing special
NO_COMPOSED=0        # --no-composed: drop the broad word+digits+special class
IGNORECASE="-i"      # recall-oriented by default; --case for case-sensitive
CONTEXT=0            # emit the whole source line as a trailing column
OUT=""               # operator-chosen output file (default: stdout)
SUMMARY=1            # print per-category counts at the end
MODE="both"          # both | weak | secrets
HISTORY=0            # --history: also scan standard shell-history/log locations
declare -a INPUTS=()

usage() {
    cat >&2 <<EOF
$PROG — compliance scanner for passwords & secrets in shell history and logs (read-only).

USAGE:
    $PROG [options] <file|dir> [<file|dir> ...]
    $PROG --history [options]              # scan standard history/log locations
    some-cmd | $PROG [options] -           # read stdin

OPTIONS:
    --history       also scan standard *nix shell-history + /var/log locations
    --weak-only     scan only the weak-password bank
    --secrets-only  scan only the secret/credential-exposure bank
    --min-len N     ignore tokens shorter than N chars        (default $MINLEN)
    --max-len N     ignore tokens longer than N chars         (default $MAXLEN)
    --no-recurse    do not descend into directories
    --loose         also flag word+digits with no special char (higher recall)
    --no-composed   drop the broad "word+digits+special" class (highest precision)
    --case          case-sensitive matching (default: case-insensitive)
    --context       append the full matching source line as an extra TAB column
    --out FILE      write results to FILE instead of stdout (operator path only)
    --no-summary    suppress the per-category count summary
    -h, --help      this help

OUTPUT (TAB-separated):
    <category>\t<file>:<line>\t<token>[\t<full line>]

EXIT: 0 = clean, 1 = findings, 2 = usage/error  (scriptable gate for CI compliance jobs)

EXAMPLES:
    # Audit every shell history + log on this host
    sudo $PROG --history --context --out /tmp/compliance-$(hostname).tsv

    # One user's bash history only
    $PROG ~/.bash_history

    # Just secret/API-key exposure across an exported log bundle
    $PROG --secrets-only /mnt/logs

    # CI gate: fail the build if a secret landed in committed logs
    $PROG --secrets-only ./logs || echo "SECRET FOUND — rotate + scrub"
EOF
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }

# ---- arg parse ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --history)     HISTORY=1; shift ;;
        --weak-only)   MODE="weak"; shift ;;
        --secrets-only) MODE="secrets"; shift ;;
        --min-len)     MINLEN="${2:?--min-len needs a value}"; shift 2 ;;
        --max-len)     MAXLEN="${2:?--max-len needs a value}"; shift 2 ;;
        --no-recurse)  RECURSE=0; shift ;;
        --loose)       LOOSE=1; shift ;;
        --no-composed) NO_COMPOSED=1; shift ;;
        --case)        IGNORECASE=""; shift ;;
        --context)     CONTEXT=1; shift ;;
        --out)         OUT="${2:?--out needs a path}"; shift 2 ;;
        --no-summary)  SUMMARY=0; shift ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; while [[ $# -gt 0 ]]; do INPUTS+=("$1"); shift; done ;;
        -)             INPUTS+=("-"); shift ;;
        -*)            die "unknown option: $1 (see --help)" ;;
        *)             INPUTS+=("$1"); shift ;;
    esac
done

command -v grep >/dev/null 2>&1 || die "grep not found"
[[ "$MINLEN" =~ ^[0-9]+$ ]] || die "--min-len must be numeric"
[[ "$MAXLEN" =~ ^[0-9]+$ ]] || die "--max-len must be numeric"

# ---- history/log convenience ---------------------------------------------
if [[ "$HISTORY" -eq 1 ]]; then
    # Curated list of flat text files only. We deliberately do NOT recurse the whole
    # /var/log tree: it holds huge rotated and binary logs (journald, btmp/wtmp,
    # compressed .gz) that make a blind walk crawl. grep -I still skips any binary
    # that sneaks in. For a full tree, pass the directory explicitly as an argument.
    shopt -s nullglob
    declare -a hist=(
        # shell histories (interactive secret-typing lives here)
        /root/.bash_history /root/.zsh_history /root/.sh_history /root/.ash_history
        /root/.*_history
        /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history /home/*/.ash_history
        /home/*/.*_history
        # PowerShell (pwsh on *nix) history
        /root/.local/share/powershell/PSReadLine/ConsoleHost_history.txt
        /home/*/.local/share/powershell/PSReadLine/ConsoleHost_history.txt
        # common flat text logs that frequently echo a typed secret
        /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages
        /var/log/cloud-init-output.log /var/log/cloud-init.log /var/log/*.log
        /var/log/apache2/*.log /var/log/httpd/*.log /var/log/nginx/*.log
    )
    shopt -u nullglob
    for f in "${hist[@]}"; do [[ -f "$f" && -r "$f" ]] && INPUTS+=("$f"); done
    [[ ${#INPUTS[@]} -gt 0 ]] || die "--history: no readable history/log files found (try sudo)"
fi

[[ ${#INPUTS[@]} -gt 0 ]] || { usage; exit 2; }

# If reading stdin, spool it to a temp file so grep can report a stable label.
TMP=""
cleanup() { [[ -n "$TMP" ]] && rm -f "$TMP"; }
trap cleanup EXIT
for i in "${!INPUTS[@]}"; do
    if [[ "${INPUTS[$i]}" == "-" ]]; then
        TMP="$(mktemp "${TMPDIR:-/tmp}/pwscrape.XXXXXX")" || die "mktemp failed"
        cat > "$TMP"
        INPUTS[$i]="$TMP"
    fi
done

# ===========================================================================
# PATTERN BANKS.  Each entry: "CATEGORY|ERE".  ERE = grep -E, token-shaped so
# -o extracts the credential itself.  Literal patterns are single-quoted so the
# shell never touches $, `, etc.
# ===========================================================================

# Repeated-run alternation (aaaa, 1111, 0000 …) built without backrefs for portability.
repeat_alt=""
for c in {a..z} {0..9}; do repeat_alt+="${c}${c}${c}${c}+|"; done
repeat_alt="${repeat_alt%|}"

declare -a WEAK=()
WEAK+=('keyboard-walk|(qwertyuiop|qwertz|qwerty|azerty|asdfghjkl|asdfgh|asdfg|asdf|zxcvbnm|zxcvbn|zxcvb|qazwsxedc|qazwsx|zaq12wsx|zaq1xsw2|1qaz2wsx3edc|1qaz2wsx|1q2w3e4r5t|1q2w3e4r|1q2w3e|qweasdzxc|qweasd|poiuytrewq|mnbvcxz|0okm9ijn|qscwdv)[0-9[:punct:]]{0,4}')
WEAK+=('keyboard-walk-shift|(!qaz@wsx#edc|!qaz@wsx|!q@w#e$r%t|!q@w#e$r|@wsx#edc)')
WEAK+=('sequence|(1234567890|0123456789|123456789|12345678|1234567|123456|234567|0987654321|987654321|87654321|654321|123123|121212|112233|123321|101010|abcdefgh|abcdefg|abcdef|abcde|abc123|abcd1234|qwe123|asd123|pass123|password123|admin123|test123|letmein123)')
WEAK+=("repeat|(${repeat_alt})")
WEAK+=('season-year|(spring|summer|autumn|winter|fall)(19|20)?[0-9]{2}[[:punct:]]?')
WEAK+=('month-year|(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sept|sep|oct|nov|dec)(19|20)?[0-9]{2}[[:punct:]]?')
WEAK+=('leet-password|p[a@4]ss?w[o0]rd[0-9[:punct:]]{0,4}|p[a@4]55w[o0]rd[0-9[:punct:]]{0,4}|l[e3]tm[e3]in[0-9[:punct:]]{0,4}|[a@4]dm[i1]n[0-9[:punct:]]{0,4}')
WEAK+=('baseword|(password|passw0rd|passwd|pass|pwd|admin|administrator|welcome|letmein|changeme|change123|secret|login|logon|root|toor|monkey|dragon|master|shadow|superman|batman|trustno1|iloveyou|princess|sunshine|football|baseball|hello|freedom|whatever|ninja|mustang|starwars|hunter2|default|guest|temp|demo|oracle|cisco|access|money|love|god|liverpool|arsenal|chelsea|hockey|killer|soccer|computer|internet)[0-9[:punct:]]{0,4}')
WEAK+=('word-year|[a-z]{3,20}(19[0-9]{2}|20[0-9]{2})[[:punct:]]?')
if [[ "$NO_COMPOSED" -eq 0 ]]; then
    if [[ "$LOOSE" -eq 1 ]]; then
        WEAK+=('composed|[a-z]{3,20}[0-9]{1,4}[[:punct:]]{0,3}')
    else
        WEAK+=('composed|[a-z]{3,20}[0-9]{1,4}[[:punct:]]{1,3}')
    fi
fi

declare -a SECRETS=()
# Passwords typed as command-line arguments (the #1 history-hygiene violation).
SECRETS+=('cmdline-pass-flag|(--password|--passwd|--pass-?word|--pwd|--secret|--token|--api-?key|--auth-?token|-pwd|/p:|/pass:|/password:)[ =:]+[^ '"'"'"]{3,}')
SECRETS+=('cmdline-mysql-p|(^|[[:space:]])-p[^ ='"'"'"-][^ '"'"'"]{2,}')
SECRETS+=('cmdline-sshpass|sshpass[ ]+-p[ ]?[^ '"'"'"]{2,}')
SECRETS+=('cmdline-net-user|net[ ]+user[ ]+[^ ]+[ ]+[^ /]{3,}')
SECRETS+=('cmdline-curl-userpass|(curl|wget)[ ].*(-u|--user)[ =][^ '"'"'"]+:[^ '"'"'"]+')
SECRETS+=('cmdline-ps-plaintext|(ConvertTo-SecureString[^\n]*-AsPlainText|-AsPlainText[ ]+-Force|New-Object[^\n]*PSCredential)')
# Secrets set via environment variables.
SECRETS+=('env-secret|(^|[[:space:]]|export[ ]+)(PGPASSWORD|MYSQL_PWD|MYSQL_PASSWORD|MARIADB_PASSWORD|REDIS_PASSWORD|MONGO_?PASSWORD|RABBITMQ_PASSWORD|POSTGRES_PASSWORD|DB_PASSWORD|FTP_PASSWORD|SMTP_PASSWORD|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_API_KEY|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|DOCKER_PASSWORD|DOCKERHUB_TOKEN|TWILIO_AUTH_TOKEN|SLACK_TOKEN|SLACK_WEBHOOK|NPM_TOKEN|PYPI_TOKEN|HF_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY|SENDGRID_API_KEY|DATABASE_URL|SECRET_KEY|SECRET_TOKEN|API_?KEY|ACCESS_?KEY|AUTH_?TOKEN|PRIVATE_?KEY|PASSWORD|PASSWD|PASSPHRASE|TOKEN)[ ]*=[ ]*['"'"'"]?[^ '"'"'";]{3,}')
# High-confidence provider key/token formats.
SECRETS+=('aws-access-key|(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}')
SECRETS+=('github-token|gh[pousr]_[A-Za-z0-9]{30,}')
SECRETS+=('slack-token|xox[baprs]-[0-9A-Za-z-]{10,}')
SECRETS+=('google-api-key|AIza[0-9A-Za-z_-]{35}')
SECRETS+=('gcp-oauth|ya29\.[0-9A-Za-z_-]{20,}')
SECRETS+=('stripe-key|[sr]k_(live|test)_[0-9A-Za-z]{10,}')
SECRETS+=('twilio-sid|(SK|AC)[0-9a-fA-F]{32}')
SECRETS+=('sendgrid-key|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}')
SECRETS+=('openai-key|sk-(proj-)?[A-Za-z0-9_-]{20,}')
SECRETS+=('npm-token|npm_[A-Za-z0-9]{36}')
SECRETS+=('jwt|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
SECRETS+=('private-key-header|-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----')
SECRETS+=('putty-key|PuTTY-User-Key-File-?[0-9]?:')
# Connection strings / URLs with embedded creds.
SECRETS+=('url-with-creds|(https?|ftp|ssh|mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|amqp|rediss)://[^ :@/]+:[^ @/]+@[^ ]+')
SECRETS+=('conn-string-pw|(server|data[ ]?source|host|initial[ ]?catalog|database)=[^;]+;[^\n]*(password|pwd)=[^;[:space:]]{1,}')
# HTTP auth headers.
SECRETS+=('auth-header|[Aa]uthorization:?[ ]*(Basic|Bearer)[ ]+[A-Za-z0-9+/=._-]{8,}')
SECRETS+=('proxy-auth-header|[Pp]roxy-[Aa]uthorization:?[ ]*(Basic|Bearer)[ ]+[A-Za-z0-9+/=._-]{8,}')
# Generic key:value / key=value secret assignments (broad catch-all).
SECRETS+=('generic-secret-assign|(password|passwd|pwd|passphrase|secret|secret_key|client_secret|token|access_token|refresh_token|auth_token|api_?key|access_?key|private_?key|credential)["'"'"' ]*[:=][ ]*['"'"'"]?[^ '"'"'";,)]{3,}')

# Select active banks.
declare -a BANK=()
case "$MODE" in
    weak)    BANK=("${WEAK[@]}") ;;
    secrets) BANK=("${SECRETS[@]}") ;;
    both)    BANK=("${WEAK[@]}" "${SECRETS[@]}") ;;
esac

# ---- scan -----------------------------------------------------------------
GREP_R=""; [[ "$RECURSE" -eq 1 ]] && GREP_R="-r"
[[ -n "$OUT" ]] && : > "$OUT"   # truncate operator output file up front

declare -A COUNTS=()
declare -a CATORDER=()

scan_one() {
    local regex="$1"
    # -H force filename (so single-file input still yields file:line:token),
    # -r recurse, -n line#, -o only-match, -E ERE, -I skip binary, -i (opt).
    # Only file and line are split off by the first two ':'; the token keeps any
    # remaining ':' intact (JWTs, URLs and connection strings contain them).
    # shellcheck disable=SC2086
    grep -H $GREP_R -noEI $IGNORECASE -e "$regex" -- "${INPUTS[@]}" 2>/dev/null \
    | while IFS= read -r hit; do
        local file line token
        file="${hit%%:*}"; hit="${hit#*:}"
        line="${hit%%:*}"; token="${hit#*:}"
        local len="${#token}"
        (( len >= MINLEN && len <= MAXLEN )) || continue
        if [[ "$CONTEXT" -eq 1 ]]; then
            local src
            src="$(sed -n "${line}p" "$file" 2>/dev/null | tr '\t\n' '  ')"
            printf '%s:%s\t%s\t%s\n' "$file" "$line" "$token" "$src"
        else
            printf '%s:%s\t%s\n' "$file" "$line" "$token"
        fi
    done
}

total=0
for entry in "${BANK[@]}"; do
    cat="${entry%%|*}"
    regex="${entry#*|}"
    CATORDER+=("$cat")
    n=0
    while IFS= read -r row; do
        # row is already "file:line<TAB>token[<TAB>src]"; just prefix the category.
        if [[ -n "$OUT" ]]; then printf '%s\t%s\n' "$cat" "$row" >> "$OUT"
        else printf '%s\t%s\n' "$cat" "$row"; fi
        n=$((n+1))
    done < <(scan_one "$regex")
    COUNTS["$cat"]=$(( ${COUNTS["$cat"]:-0} + n ))
    total=$((total+n))
done

# ---- summary --------------------------------------------------------------
if [[ "$SUMMARY" -eq 1 ]]; then
    {
        echo
        echo "=== password/secret compliance summary ==="
        printf 'scanned inputs : %d\n' "${#INPUTS[@]}"
        printf 'mode           : %s\n' "$MODE"
        echo "---"
        for cat in "${CATORDER[@]}"; do
            [[ -n "${COUNTS[$cat]+x}" ]] || continue
            [[ "${COUNTS[$cat]}" -gt 0 ]] && printf '%-24s %d\n' "$cat" "${COUNTS[$cat]}"
        done
        echo "---"
        printf '%-24s %d\n' "TOTAL FINDINGS" "$total"
        [[ -n "$OUT" ]] && echo "results written to: $OUT"
    } >&2
fi

[[ "$total" -gt 0 ]] && exit 1 || exit 0
