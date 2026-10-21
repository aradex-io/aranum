<#
.SYNOPSIS
    Compliance scanner: find passwords & secrets typed into PowerShell/shell history
    and logs. Read-only.

.DESCRIPTION
    The Windows/PowerShell counterpart to password-scrape.sh. READ-ONLY: never writes
    to a target, never modifies scanned files, never phones home. Reads the paths (or
    pipeline input) you give it - or the standard PSReadLine history + text logs with
    -History - and emits one object per token that looks like a credential someone typed.

    PRIMARY USE CASE: shell-history hygiene. Admins routinely type passwords straight
    onto a command line, where PSReadLine persists them forever in
    ConsoleHost_history.txt. This flags them so they can be scrubbed and rotated.

    TWO BANKS (both scanned by default):
      1. WEAK-PASSWORD shapes  - "Password1!", keyboard walks (qwerty / 1qaz2wsx /
         zxcvbn / qazwsx), seasons+year, sequences, repeats, leet "p@ssw0rd", base words.
      2. SECRET / CREDENTIAL exposure "key terms" - command-line password flags
         (-Password, --password, mysql -p, net user, ConvertTo-SecureString -AsPlainText),
         secret env vars (PGPASSWORD, AWS_SECRET_ACCESS_KEY, ...), provider API keys/
         tokens (AWS AKIA, GitHub ghp_, Slack xox*, Google AIza, Stripe, JWT, OpenAI sk-),
         private-key headers, DB/URL connection strings with embedded creds, Authorization headers.

.PARAMETER Path
    One or more files/directories to scan. Directories are recursed unless -NoRecurse.

.PARAMETER History
    Also scan standard PSReadLine history (all user profiles) and common text logs.

.PARAMETER WeakOnly
    Scan only the weak-password bank.

.PARAMETER SecretsOnly
    Scan only the secret/credential-exposure bank.

.PARAMETER OutFile
    Also write findings to this CSV (operator path only; no global loot dirs).

.EXAMPLE
    .\Get-WeakPassword.ps1 -History -OutFile C:\audit\pwhits.csv
    Audit every user's PowerShell history + common logs, save a CSV compliance report.

.EXAMPLE
    Get-Content .\app.log | .\Get-WeakPassword.ps1 -SecretsOnly
    Pipe a log through the secret/API-key bank only.

.NOTES
    Authorized testing / internal compliance only. Style: CLAUDE.md section 8.
    Objects go to the Output stream (pipe to Format-Table / Export-Csv / Where-Object).
    Exit code: 0 = clean, 1 = findings (scriptable CI gate).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Path,

    [Parameter(ValueFromPipeline = $true)]
    [string[]]$InputObject,

    [switch]$History,
    [switch]$WeakOnly,
    [switch]$SecretsOnly,
    [int]$MinLen = 6,
    [int]$MaxLen = 512,
    [switch]$NoRecurse,
    [switch]$Loose,
    [switch]$NoComposed,
    [switch]$CaseSensitive,
    [switch]$Context,
    [string]$OutFile,
    [switch]$NoSummary
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Are we on Windows? Detect WITHOUT the $IsWindows automatic variable: that
    # var only exists in PowerShell 6+, and under Set-StrictMode referencing it
    # on Windows PowerShell 5.1 throws. OSVersion.Platform works on both.
    $script:IsWindowsOS = ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

    # ---- pattern banks ----------------------------------------------------
    # .NET regex. [\p{P}\p{S}] is the POSIX [:punct:] analog (punctuation+symbols).
    # Value class [^\s'";,)] = "a credential value: no whitespace/quote/delimiter".
    $repeatChars = [char[]](97..122) + [char[]](48..57)   # a-z, 0-9
    $repeat = ($repeatChars | ForEach-Object { "$_$_$_$_+" }) -join '|'

    $weak = @(
        [pscustomobject]@{ Cat = 'keyboard-walk';       Pat = '(qwertyuiop|qwertz|qwerty|azerty|asdfghjkl|asdfgh|asdfg|asdf|zxcvbnm|zxcvbn|zxcvb|qazwsxedc|qazwsx|zaq12wsx|zaq1xsw2|1qaz2wsx3edc|1qaz2wsx|1q2w3e4r5t|1q2w3e4r|1q2w3e|qweasdzxc|qweasd|poiuytrewq|mnbvcxz|0okm9ijn|qscwdv)[0-9\p{P}\p{S}]{0,4}' }
        [pscustomobject]@{ Cat = 'keyboard-walk-shift'; Pat = '(!qaz@wsx#edc|!qaz@wsx|!q@w#e\$r%t|!q@w#e\$r|@wsx#edc)' }
        [pscustomobject]@{ Cat = 'sequence';            Pat = '(1234567890|0123456789|123456789|12345678|1234567|123456|234567|0987654321|987654321|87654321|654321|123123|121212|112233|123321|101010|abcdefgh|abcdefg|abcdef|abcde|abc123|abcd1234|qwe123|asd123|pass123|password123|admin123|test123|letmein123)' }
        [pscustomobject]@{ Cat = 'repeat';              Pat = "($repeat)" }
        [pscustomobject]@{ Cat = 'season-year';         Pat = '(spring|summer|autumn|winter|fall)(19|20)?[0-9]{2}[\p{P}\p{S}]?' }
        [pscustomobject]@{ Cat = 'month-year';          Pat = '(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sept|sep|oct|nov|dec)(19|20)?[0-9]{2}[\p{P}\p{S}]?' }
        [pscustomobject]@{ Cat = 'leet-password';       Pat = '(p[a@4]ss?w[o0]rd|p[a@4]55w[o0]rd|l[e3]tm[e3]in|[a@4]dm[i1]n)[0-9\p{P}\p{S}]{0,4}' }
        [pscustomobject]@{ Cat = 'baseword';            Pat = '(password|passw0rd|passwd|pass|pwd|admin|administrator|welcome|letmein|changeme|change123|secret|login|logon|root|toor|monkey|dragon|master|shadow|superman|batman|trustno1|iloveyou|princess|sunshine|football|baseball|hello|freedom|whatever|ninja|mustang|starwars|hunter2|default|guest|temp|demo|oracle|cisco|access|money|love|god|liverpool|arsenal|chelsea|hockey|killer|soccer|computer|internet)[0-9\p{P}\p{S}]{0,4}' }
        [pscustomobject]@{ Cat = 'word-year';           Pat = '[a-z]{3,20}(19[0-9]{2}|20[0-9]{2})[\p{P}\p{S}]?' }
    )
    if (-not $NoComposed) {
        if ($Loose) { $weak += [pscustomobject]@{ Cat = 'composed'; Pat = '[a-z]{3,20}[0-9]{1,4}[\p{P}\p{S}]{0,3}' } }
        else        { $weak += [pscustomobject]@{ Cat = 'composed'; Pat = '[a-z]{3,20}[0-9]{1,4}[\p{P}\p{S}]{1,3}' } }
    }

    $secrets = @(
        [pscustomobject]@{ Cat = 'cmdline-pass-flag';   Pat = '(-Password|-AsPlainText|--password|--passwd|--pass-?word|--pwd|--secret|--token|--api-?key|--auth-?token|-pwd|/p:|/pass:|/password:)[ =:]+[^\s'';"]{3,}' }
        [pscustomobject]@{ Cat = 'cmdline-mysql-p';     Pat = '(^|\s)-p[^\s=''";-][^\s'';"]{2,}' }
        [pscustomobject]@{ Cat = 'cmdline-sshpass';     Pat = 'sshpass\s+-p\s?[^\s'';"]{2,}' }
        [pscustomobject]@{ Cat = 'cmdline-net-user';    Pat = 'net\s+user\s+\S+\s+[^\s/]{3,}' }
        [pscustomobject]@{ Cat = 'cmdline-curl-userpass'; Pat = '(curl|wget)\s.*(-u|--user)[ =]\S+:\S+' }
        [pscustomobject]@{ Cat = 'cmdline-ps-plaintext'; Pat = '(ConvertTo-SecureString.*-AsPlainText|-AsPlainText\s+-Force|New-Object.*PSCredential)' }
        [pscustomobject]@{ Cat = 'env-secret';          Pat = '(PGPASSWORD|MYSQL_PWD|MYSQL_PASSWORD|MARIADB_PASSWORD|REDIS_PASSWORD|MONGO_?PASSWORD|RABBITMQ_PASSWORD|POSTGRES_PASSWORD|DB_PASSWORD|FTP_PASSWORD|SMTP_PASSWORD|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_API_KEY|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|DOCKER_PASSWORD|DOCKERHUB_TOKEN|TWILIO_AUTH_TOKEN|SLACK_TOKEN|SLACK_WEBHOOK|NPM_TOKEN|PYPI_TOKEN|HF_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY|SENDGRID_API_KEY|DATABASE_URL|SECRET_KEY|SECRET_TOKEN|API_?KEY|ACCESS_?KEY|AUTH_?TOKEN|PRIVATE_?KEY|PASSWORD|PASSWD|PASSPHRASE|TOKEN)\s*=\s*[''"]?[^\s'';]{3,}' }
        [pscustomobject]@{ Cat = 'aws-access-key';      Pat = '(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}' }
        [pscustomobject]@{ Cat = 'github-token';        Pat = 'gh[pousr]_[A-Za-z0-9]{30,}' }
        [pscustomobject]@{ Cat = 'slack-token';         Pat = 'xox[baprs]-[0-9A-Za-z-]{10,}' }
        [pscustomobject]@{ Cat = 'google-api-key';      Pat = 'AIza[0-9A-Za-z_-]{35}' }
        [pscustomobject]@{ Cat = 'gcp-oauth';           Pat = 'ya29\.[0-9A-Za-z_-]{20,}' }
        [pscustomobject]@{ Cat = 'stripe-key';          Pat = '[sr]k_(live|test)_[0-9A-Za-z]{10,}' }
        [pscustomobject]@{ Cat = 'twilio-sid';          Pat = '(SK|AC)[0-9a-fA-F]{32}' }
        [pscustomobject]@{ Cat = 'sendgrid-key';        Pat = 'SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}' }
        [pscustomobject]@{ Cat = 'openai-key';          Pat = 'sk-(proj-)?[A-Za-z0-9_-]{20,}' }
        [pscustomobject]@{ Cat = 'npm-token';           Pat = 'npm_[A-Za-z0-9]{36}' }
        [pscustomobject]@{ Cat = 'jwt';                 Pat = 'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' }
        [pscustomobject]@{ Cat = 'private-key-header';  Pat = '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' }
        [pscustomobject]@{ Cat = 'putty-key';           Pat = 'PuTTY-User-Key-File-?[0-9]?:' }
        [pscustomobject]@{ Cat = 'url-with-creds';      Pat = '(https?|ftp|ssh|mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|rediss|amqp)://[^\s:@/]+:[^\s@/]+@\S+' }
        [pscustomobject]@{ Cat = 'conn-string-pw';      Pat = '(server|data\s?source|host|initial\s?catalog|database)=[^;]+;.*(password|pwd)=[^;\s]{1,}' }
        [pscustomobject]@{ Cat = 'auth-header';         Pat = 'Authorization:?\s*(Basic|Bearer)\s+[A-Za-z0-9+/=._-]{8,}' }
        [pscustomobject]@{ Cat = 'proxy-auth-header';   Pat = 'Proxy-Authorization:?\s*(Basic|Bearer)\s+[A-Za-z0-9+/=._-]{8,}' }
        [pscustomobject]@{ Cat = 'generic-secret-assign'; Pat = '(password|passwd|pwd|passphrase|secret|secret_key|client_secret|token|access_token|refresh_token|auth_token|api_?key|access_?key|private_?key|credential)[''" ]*[:=]\s*[''"]?[^\s'';,)]{3,}' }
    )

    if     ($WeakOnly)    { $bankDefs = $weak }
    elseif ($SecretsOnly) { $bankDefs = $secrets }
    else                  { $bankDefs = @($weak + $secrets) }

    $opts = [System.Text.RegularExpressions.RegexOptions]::Compiled
    if (-not $CaseSensitive) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    $bank = foreach ($d in $bankDefs) {
        [pscustomobject]@{ Cat = $d.Cat; Rx = [System.Text.RegularExpressions.Regex]::new($d.Pat, $opts) }
    }

    $counts  = @{}
    $total   = 0
    $results = [System.Collections.Generic.List[object]]::new()
    $pipeLines = [System.Collections.Generic.List[string]]::new()

    # Per-run accounting so we can report WHY files were skipped instead of
    # flooding the console with one warning per unreadable file.
    $script:scannedCount = 0
    $script:skipBinary   = 0
    $script:skipErr      = 0
    $script:skipMsgs     = [System.Collections.Generic.List[string]]::new()

    # Make a raw filesystem path safe for the .NET file APIs on Windows.
    # Windows PowerShell 5.1 runs on .NET Framework, whose File/FileStream APIs
    # enforce the legacy MAX_PATH (260) limit and throw PathTooLongException on
    # longer paths - even though Get-ChildItem -Recurse happily HANDS us those
    # longer paths (so files in deep subdirectories fail to open). The \\?\
    # prefix tells Win32 to skip MAX_PATH normalization. Only valid for a fully
    # qualified, backslash-only path (which .FullName / Join-Path give us on
    # Windows); it is meaningless/ harmful elsewhere, so no-op off Windows.
    function ConvertTo-IOPath {
        param([string]$Path)
        if (-not $script:IsWindowsOS) { return $Path }
        if ($Path.StartsWith('\\?\')) { return $Path }
        if ($Path -match '^[A-Za-z]:\\')  { return '\\?\' + $Path }           # C:\...
        if ($Path.StartsWith('\\'))        { return '\\?\UNC\' + $Path.Substring(2) }  # \\server\share\...
        return $Path
    }

    # Open a file for reading with FileShare.ReadWrite so we can still scan a
    # file another process holds open for writing (active logs, a file open in
    # an editor, a running app's data) - the default OpenRead uses FileShare.Read
    # and fails those with "being used by another process". Caller disposes.
    function Open-ReadStream {
        param([string]$File)
        $p = ConvertTo-IOPath $File
        return New-Object System.IO.FileStream(
            $p,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    }

    function Test-IsBinary {
        # Returns $true ONLY for a file that opens but contains a NUL byte in its
        # first 8 KiB (a real binary). An open FAILURE is re-thrown so the caller
        # counts it as "unreadable", never silently mislabels it "binary".
        param([string]$File)
        $fs = Open-ReadStream -File $File
        try {
            $buf = New-Object byte[] 8192
            $n = $fs.Read($buf, 0, 8192)
            for ($i = 0; $i -lt $n; $i++) { if ($buf[$i] -eq 0) { return $true } }
        } finally { $fs.Dispose() }
        return $false
    }

    # Match one line against every bank and emit/record any hits.
    function Invoke-ScanLine {
        param([string]$Label, [string]$Line, [int]$LineNo)
        if ([string]::IsNullOrEmpty($Line)) { return }
        foreach ($b in $script:bank) {
            foreach ($m in $b.Rx.Matches($Line)) {
                $tok = $m.Value
                if ($tok.Length -lt $script:MinLen -or $tok.Length -gt $script:MaxLen) { continue }
                # NB: compute context first. An inline 'if' used as a hashtable
                # VALUE does not parse on Windows PowerShell 5.1 (works only in 7+);
                # a plain variable assignment from 'if' is fine on both.
                $ctx = $null
                if ($script:Context) { $ctx = $Line.Trim() }
                $obj = [pscustomobject]@{
                    Category = $b.Cat
                    File     = $Label
                    Line     = $LineNo
                    Token    = $tok
                    Context  = $ctx
                }
                $script:results.Add($obj)
                Write-Output $obj
                if (-not $script:counts.ContainsKey($b.Cat)) { $script:counts[$b.Cat] = 0 }
                $script:counts[$b.Cat]++
                $script:total++
            }
        }
    }

    # Scan an in-memory sequence of lines (pipeline input).
    function Invoke-Scan {
        param([string]$Label, [System.Collections.IEnumerable]$Lines)
        $ln = 0
        foreach ($line in $Lines) { $ln++; Invoke-ScanLine -Label $Label -Line $line -LineNo $ln }
    }

    # Scan a file on disk: robust open (shared + long-path aware), streamed line
    # by line so a huge file never has to fit in memory. Open/read failures are
    # accounted, not fatal and not flooded.
    function Invoke-ScanFile {
        param([string]$File)
        try {
            if (Test-IsBinary -File $File) { $script:skipBinary++; return }
            $fs = Open-ReadStream -File $File
            try {
                $sr = New-Object System.IO.StreamReader($fs, $true)  # detect BOM, default UTF-8
                try {
                    $ln = 0
                    while ($null -ne ($line = $sr.ReadLine())) { $ln++; Invoke-ScanLine -Label $File -Line $line -LineNo $ln }
                } finally { $sr.Dispose() }
            } finally { $fs.Dispose() }
            $script:scannedCount++
        } catch {
            $script:skipErr++
            if ($script:skipMsgs.Count -lt 10) { $script:skipMsgs.Add(("{0}: {1}" -f $File, $_.Exception.Message)) }
        }
    }
}

process {
    if ($InputObject) { foreach ($l in $InputObject) { $pipeLines.Add($l) } }
}

end {
    # Assemble the file list.
    $files = [System.Collections.Generic.List[string]]::new()

    if ($History) {
        # Curated, fixed-depth locations only - mirrors password-scrape.sh. We never
        # -Recurse a whole user tree or /var/log: those hold huge/rotated/binary files
        # that turn a blind walk into a crawl (and can hang on symlink loops). To scan a
        # full tree, pass that directory explicitly as a -Path argument instead.
        $hist = [System.Collections.Generic.List[string]]::new()

        # Enumerate user home directories ONE level deep (no -Recurse).
        $homeDirs = [System.Collections.Generic.List[string]]::new()
        $containers = @()
        if ($env:SystemDrive) { $containers += (Join-Path $env:SystemDrive 'Users') }  # Windows
        $containers += '/home', '/Users'                                               # *nix + macOS
        foreach ($c in $containers) {
            if (Test-Path -Path $c -PathType Container -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $c -Directory -Force -ErrorAction SilentlyContinue |
                    ForEach-Object { $homeDirs.Add($_.FullName) }
            }
        }
        foreach ($explicit in @('/root', $env:HOME, $env:USERPROFILE)) {
            if ($explicit -and (Test-Path -Path $explicit -PathType Container -ErrorAction SilentlyContinue)) { $homeDirs.Add($explicit) }
        }

        foreach ($h in ($homeDirs | Sort-Object -Unique)) {
            # every *_history dotfile (bash, zsh, sh, ash, python, mysql, psql, ...)
            Get-ChildItem -Path $h -Filter '.*_history' -File -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $hist.Add($_.FullName) }
            # PSReadLine history - fixed sub-paths (Windows layout + pwsh-on-*nix/macOS).
            foreach ($r in @(
                    'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
                    '.local/share/powershell/PSReadLine/ConsoleHost_history.txt')) {
                $candidate = Join-Path $h $r
                if (Test-Path -Path $candidate -PathType Leaf -ErrorAction SilentlyContinue) { $hist.Add($candidate) }
            }
        }

        # Common flat text logs (fixed paths - never a /var/log tree walk).
        foreach ($g in @('/var/log/auth.log','/var/log/secure','/var/log/syslog','/var/log/messages',
                         '/var/log/cloud-init-output.log','/var/log/cloud-init.log')) {
            if (Test-Path -Path $g -PathType Leaf -ErrorAction SilentlyContinue) { $hist.Add($g) }
        }

        foreach ($f in ($hist | Sort-Object -Unique)) { $files.Add($f) }
    }

    foreach ($p in ($Path | Where-Object { $_ })) {
        if (Test-Path -Path $p -PathType Container) {
            $gc = Get-ChildItem -Path $p -File -Recurse:(-not $NoRecurse) -ErrorAction SilentlyContinue
            foreach ($f in $gc) { $files.Add($f.FullName) }
        } elseif (Test-Path -Path $p) {
            $files.Add((Resolve-Path $p).Path)
        } else {
            Write-Warning "no such path: $p"
        }
    }

    if ($History -and $files.Count -eq 0) { Write-Warning 'Get-WeakPassword: -History found no readable history/log files (try an elevated prompt).' }

    # Scan files (robust: shared-mode open, long-path aware, per-file errors
    # accounted rather than fatal).
    foreach ($f in $files) { Invoke-ScanFile -File $f }
    # Scan pipeline input.
    if ($pipeLines.Count -gt 0) { Invoke-Scan -Label '(pipeline)' -Lines $pipeLines }

    if ($files.Count -eq 0 -and $pipeLines.Count -eq 0) {
        Write-Warning 'Get-WeakPassword: nothing to scan. Pass -Path, pipe input, or use -History.'
        exit 2
    }

    # Operator output file (CSV - handy for Excel compliance reports).
    if ($OutFile) {
        $results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    }

    # Summary (host stream, not the object stream - so pipelines stay clean).
    if (-not $NoSummary) {
        Write-Host ''
        Write-Host '=== password/secret compliance summary ===' -ForegroundColor Cyan
        Write-Host ("files found    : {0}" -f $files.Count)
        Write-Host ("scanned        : {0}" -f $script:scannedCount)
        if ($script:skipBinary -gt 0) { Write-Host ("skipped binary : {0}" -f $script:skipBinary) }
        if ($script:skipErr -gt 0) {
            Write-Host ("skipped unread : {0}" -f $script:skipErr) -ForegroundColor DarkYellow
            foreach ($m in $script:skipMsgs) { Write-Host ("  - {0}" -f $m) -ForegroundColor DarkYellow }
            if ($script:skipErr -gt $script:skipMsgs.Count) {
                Write-Host ("  - ... and {0} more (run from an elevated prompt to read protected files)" -f ($script:skipErr - $script:skipMsgs.Count)) -ForegroundColor DarkYellow
            }
        }
        $mode = if ($WeakOnly) { 'weak' } elseif ($SecretsOnly) { 'secrets' } else { 'both' }
        Write-Host ("mode           : {0}" -f $mode)
        Write-Host '---'
        foreach ($k in ($counts.Keys | Sort-Object { -$counts[$_] })) {
            Write-Host ("{0,-24} {1}" -f $k, $counts[$k])
        }
        Write-Host '---'
        Write-Host ("{0,-24} {1}" -f 'TOTAL FINDINGS', $total) -ForegroundColor Yellow
        if ($OutFile) { Write-Host ("results written to: {0}" -f $OutFile) }
    }

    if ($total -gt 0) { exit 1 } else { exit 0 }
}
