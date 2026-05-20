<#
.SYNOPSIS
    Find unquoted service paths and check write access on intermediate dirs.
.DESCRIPTION
    A service path like  C:\Program Files\Foo Bar\app.exe  unquoted causes
    Windows to attempt  C:\Program.exe, then  C:\Program Files\Foo.exe,
    then the real binary. If any preceding directory is writable, planting
    an executable there gets it invoked under the service account.
#>
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

Get-WmiObject win32_service | ForEach-Object {
    $p = $_.PathName
    if (-not $p) { return }
    if ($p -match '^"') { return }                                # already quoted
    if ($p -notmatch ' ') { return }                              # no spaces, no risk
    $exe = ($p -split ' ')[0]
    if ($p -match '^[A-Za-z]:\\Windows\\System32\\') { return }   # ignore signed builtins

    Write-Host "[!] $($_.Name)" -ForegroundColor Yellow
    Write-Host "    Path : $p"
    Write-Host "    Start: $($_.StartMode)   State: $($_.State)   Account: $($_.StartName)"

    # Walk intermediate directories
    $parts = $exe -split '\\'
    $accum = ''
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        $accum = if ($i -eq 0) { $parts[0] + '\' } else { $accum + $parts[$i] + '\' }
        if (Test-Writable $accum) {
            Write-Host "    [+] WRITABLE: $accum" -ForegroundColor Green
        }
    }
}
