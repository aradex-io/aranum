<#
.SYNOPSIS
    Find unquoted service paths and check write access on intermediate dirs.
.DESCRIPTION
    A service path like  C:\Program Files\Foo Bar\app.exe  unquoted causes
    Windows to attempt  C:\Program.exe, then  C:\Program Files\Foo.exe,
    then the real binary. If any preceding directory is writable, planting
    an executable there gets it invoked under the service account.
#>
[CmdletBinding()]
param([switch]$LibraryOnly)

$ident = [Security.Principal.WindowsIdentity]::GetCurrent()

function Test-Writable($path) {
    if (-not (Test-Path $path)) { return $false }
    try {
        $f = Join-Path $path ([Guid]::NewGuid().ToString() + ".tmp")
        [IO.File]::WriteAllText($f, "x")
        Remove-Item $f -Force
        return $true
    } catch { return $false }
}

function Get-ServiceExecutablePath([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded -match '^"([^"]+)"') { return $Matches[1] }
    if ($expanded -match '^(.+?\.(?:exe|com|bat|cmd))(?=\s|$)') { return $Matches[1] }
    return ($expanded -split '\s+', 2)[0]
}

function Get-UnquotedLoaderCandidates([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine.TrimStart().StartsWith('"')) {
        return @()
    }
    $exe = Get-ServiceExecutablePath $CommandLine
    if (-not $exe) { return @() }
    $candidates = @()
    foreach ($match in [regex]::Matches($exe, ' ')) {
        $candidate = $exe.Substring(0, $match.Index) + '.exe'
        if ($candidate -ne $exe -and $candidates -notcontains $candidate) { $candidates += $candidate }
    }
    return $candidates
}

if ($LibraryOnly) { return }

Get-CimInstance Win32_Service | ForEach-Object {
    $p = $_.PathName
    if (-not $p) { return }
    if ($p -match '^"') { return }                                # already quoted
    if ($p -notmatch ' ') { return }                              # no spaces, no risk
    $exe = Get-ServiceExecutablePath $p
    if ($p -match '^[A-Za-z]:\\Windows\\System32\\') { return }   # ignore signed builtins

    Write-Host "[!] $($_.Name)" -ForegroundColor Yellow
    Write-Host "    Path : $p"
    Write-Host "    Start: $($_.StartMode)   State: $($_.State)   Account: $($_.StartName)"

    foreach ($candidate in Get-UnquotedLoaderCandidates $p) {
        $parent = Split-Path -Parent $candidate
        $writable = Test-Writable $parent
        Write-Host "    Candidate: $candidate"
        if ($writable) {
            Write-Host "    [+] WRITABLE CANDIDATE PARENT: $parent" -ForegroundColor Green
        }
    }
}
