# Password & Secret Compliance Scanner

**Authorized testing / internal compliance only. Read-only.**

A cross-platform pair that scans files, directories, logs, and **shell history** for
credentials that someone typed where they shouldn't have persisted — then flags them so
they can be scrubbed and rotated. Neither script writes to a target, modifies the files it
scans, or phones home (CLAUDE.md §9).

```
standalones/passwords/
├── password-scrape.sh     # Bash  — *nix / macOS / WSL
├── Get-WeakPassword.ps1   # PowerShell — Windows / pwsh-on-*nix
└── README.md
```

## Why this exists

The single most common credential-hygiene failure is a human typing a password straight
onto a command line, where the shell persists it **forever**:

- `~/.bash_history`, `~/.zsh_history`, `~/.*_history`
- PowerShell PSReadLine `ConsoleHost_history.txt`
- logs that echoed a secret (`/var/log/auth.log`, app logs, CI logs)

`mysql -pSuperSecret123!`, `export PGPASSWORD=...`, `sshpass -p ...`,
`ConvertTo-SecureString -AsPlainText`, a pasted `Authorization: Bearer ...` — all of these
leave a durable copy of a live secret on disk. This scanner finds them during a compliance
pass so the secret can be rotated and the history line removed.

## Two detection banks (both run by default)

1. **Weak-password shapes** — predictable passwords that violate policy even before anyone
   leaks them:
   - `Password1!` family (word + digits + special)
   - **keyboard walks** — `qwerty`, `qwertyuiop`, `asdfgh`, `zxcvbn`, `qazwsx`,
     `1qaz2wsx`, `1q2w3e4r`, `zaq1xsw2`, and shifted walks (`!qaz@wsx`, `!q@w#e$r`)
   - **season / month + year** — `Spring2024!`, `Winter25`, `August2026`
   - **sequences** — `123456`, `abcdef`, `abc123`, `0987654321`
   - **repeats** — `aaaa`, `1111`, `0000`
   - **leet** — `P@ssw0rd`, `pa55word`, `l3tm3in`, `@dm1n`
   - **base words** — `password`, `welcome`, `letmein`, `changeme`, `monkey`, `dragon`, …

2. **Secret / credential-exposure "key terms"** — a live secret sitting in the input:
   | Category | Catches |
   |---|---|
   | `cmdline-pass-flag` | `--password`, `-Password`, `-AsPlainText`, `/password:` |
   | `cmdline-mysql-p` | `mysql -p<password>` |
   | `cmdline-sshpass` | `sshpass -p <password>` |
   | `cmdline-net-user` | `net user <user> <password> /add` |
   | `cmdline-curl-userpass` | `curl -u user:pass` |
   | `cmdline-ps-plaintext` | `ConvertTo-SecureString -AsPlainText`, `New-Object PSCredential` |
   | `env-secret` | `PGPASSWORD=`, `AWS_SECRET_ACCESS_KEY=`, `GITHUB_TOKEN=`, 40+ names |
   | `aws-access-key` | `AKIA… / ASIA…` |
   | `github-token` | `ghp_… ghs_… gho_…` |
   | `slack-token` | `xoxb-/xoxp-/xoxa-…` |
   | `google-api-key` / `gcp-oauth` | `AIza…`, `ya29.…` |
   | `stripe-key` / `twilio-sid` / `sendgrid-key` / `openai-key` / `npm-token` | provider formats |
   | `jwt` | `eyJ….eyJ….sig` |
   | `private-key-header` / `putty-key` | `-----BEGIN … PRIVATE KEY-----`, `PuTTY-User-Key-File` |
   | `url-with-creds` | `scheme://user:pass@host` |
   | `conn-string-pw` | `Server=…;Password=…` |
   | `auth-header` / `proxy-auth-header` | `Authorization: Basic/Bearer …` |
   | `generic-secret-assign` | `password=/secret=/token=/api_key=…` (broad catch-all) |

Use `--weak-only` / `-WeakOnly` or `--secrets-only` / `-SecretsOnly` to run just one bank.

## Bash — `password-scrape.sh`

```bash
# Audit every shell history + common log on this host (needs sudo to read others')
sudo ./password-scrape.sh --history --context --out /tmp/compliance-$(hostname).tsv

# One file
./password-scrape.sh ~/.bash_history

# Only secret/API-key exposure across an exported log bundle
./password-scrape.sh --secrets-only /mnt/logs

# From a pipe (e.g. a DB column dump)
mysql -N -e 'select pw from users' app | ./password-scrape.sh -

# CI compliance gate — non-zero exit if anything is found
./password-scrape.sh --secrets-only ./logs || echo 'SECRET FOUND — rotate + scrub'
```

Output is TAB-separated `category <TAB> file:line <TAB> token [<TAB> full-line]`, plus a
per-category summary on stderr. Key flags: `--history`, `--weak-only`, `--secrets-only`,
`--loose` (recall), `--no-composed` (precision), `--case`, `--context`, `--out FILE`,
`--min-len/--max-len`.

## PowerShell — `Get-WeakPassword.ps1`

```powershell
# Audit all users' PowerShell history + common logs, save a CSV compliance report
.\Get-WeakPassword.ps1 -History -OutFile C:\audit\pwhits.csv

# A directory tree, objects into the pipeline
.\Get-WeakPassword.ps1 -Path C:\inetpub\logs | Where-Object Category -eq 'auth-header'

# Pipe a log through the secret bank only
Get-Content .\app.log | .\Get-WeakPassword.ps1 -SecretsOnly
```

Findings are emitted as objects (`Category, File, Line, Token, Context`) so you can
`Format-Table`, `Export-Csv`, `Group-Object Category`, or filter them. `-OutFile` writes a
CSV. Switches mirror the bash flags (`-History`, `-WeakOnly`, `-SecretsOnly`, `-Loose`,
`-NoComposed`, `-CaseSensitive`, `-Context`, `-MinLen/-MaxLen`).

## Exit codes (both)

| Code | Meaning |
|---|---|
| `0` | clean — nothing matched |
| `1` | findings present (use as a CI/compliance gate) |
| `2` | usage error / nothing to scan |

## Tuning precision vs recall

The scanner is **recall-oriented** by default (case-insensitive, broad `composed` class) —
appropriate for a compliance sweep where a missed secret is worse than a false positive.
When auditing large, verbose logs and the `composed`/`word-year` noise is high:

- `--secrets-only` / `-SecretsOnly` — drop the weak-shape bank, keep only live-secret formats
- `--no-composed` / `-NoComposed` — drop the broadest weak class
- raise `--min-len`

## Scope / safety

Per CLAUDE.md §9 this tool is read-only: it never edits or removes the history lines it
finds — remediation (scrubbing the line, rotating the credential) is a deliberate operator
step. Output goes only to the path you pass with `--out` / `-OutFile`; there are no global
output locations. Treat any output file as sensitive — it contains the very secrets you are
trying to protect — and delete it once the findings are actioned.
