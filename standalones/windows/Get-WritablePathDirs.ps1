<#
.SYNOPSIS
    Identify directories in $env:Path that the current user can write to.
.DESCRIPTION
    Combined with a service or app that lacks an absolute path / loads DLLs
    by name, writable PATH dirs are a DLL planting / command hijack vector.
#>
[CmdletBinding()]
param()

foreach ($d in ($env:Path -split ';')) {
    if (-not $d) { continue }
    if (-not (Test-Path $d)) { continue }
    try {
        $tmp = Join-Path $d (".write_test_" + [Guid]::NewGuid().ToString())
        [IO.File]::WriteAllText($tmp, 'x')
        Remove-Item $tmp -Force
        Write-Host "[+] WRITABLE: $d" -ForegroundColor Green
    } catch {
        Write-Host "[-] $d" -ForegroundColor DarkGray
    }
}
