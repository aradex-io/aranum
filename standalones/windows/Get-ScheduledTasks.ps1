<#
.SYNOPSIS
    Enumerate all scheduled tasks with run-as, action, and trigger info.
    Flags tasks running as SYSTEM / Administrators / NETWORK SERVICE whose
    action invokes a writable script or executable.
#>
[CmdletBinding()]
param()

$ident = [Security.Principal.WindowsIdentity]::GetCurrent()

function Test-CanWriteFile($p) {
    if (-not $p -or -not (Test-Path $p)) { return $false }
    try { $acl = Get-Acl $p } catch { return $false }
    foreach ($a in $acl.Access) {
        if ($a.AccessControlType -ne 'Allow') { continue }
        if ($a.FileSystemRights -notmatch 'Modify|FullControl|Write') { continue }
        try {
            $sid = (New-Object Security.Principal.NTAccount($a.IdentityReference)).Translate([Security.Principal.SecurityIdentifier]).Value
        } catch { continue }
        if ($sid -eq $ident.User.Value) { return $true }
        if ($ident.Groups.Value -contains $sid) { return $true }
    }
    return $false
}

Get-ScheduledTask | ForEach-Object {
    $task = $_
    if ($task.State -eq 'Disabled') { return }
    $principal = $task.Principal.UserId
    $logon = $task.Principal.LogonType
    $highest = $task.Principal.RunLevel
    foreach ($act in $task.Actions) {
        $exe = $act.Execute
        $args = $act.Arguments
        $writable = $false
        if ($exe) {
            # Expand env vars
            $exeExp = [Environment]::ExpandEnvironmentVariables($exe.Trim('"'))
            $writable = Test-CanWriteFile $exeExp
        }
        $obj = [pscustomobject]@{
            Task     = $task.TaskPath + $task.TaskName
            RunAs    = $principal
            Logon    = $logon
            RunLevel = $highest
            Execute  = $exe
            Args     = $args
            Writable = $writable
        }
        if ($principal -match 'SYSTEM|Administrators|NETWORK SERVICE' -and $writable) {
            Write-Host "[+] WRITABLE+PRIVILEGED: $($obj | Out-String)" -ForegroundColor Green
        } elseif ($principal -match 'SYSTEM|Administrators|NETWORK SERVICE') {
            Write-Host "[*] PRIVILEGED: $($obj | Out-String)" -ForegroundColor Yellow
        } else {
            $obj | Format-List
        }
    }
}
