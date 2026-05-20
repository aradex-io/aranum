<#
.SYNOPSIS
    Interpret current token privileges and call out exploitable ones.
#>
$exploitable = @{
    'SeImpersonatePrivilege'        = 'Potato family: JuicyPotato/PrintSpoofer/RoguePotato/GodPotato -> SYSTEM'
    'SeAssignPrimaryTokenPrivilege' = 'Potato family (same as SeImpersonate)'
    'SeBackupPrivilege'             = 'Read SYSTEM/SAM/SECURITY hives -> offline secretsdump'
    'SeRestorePrivilege'            = 'Write to protected registry keys -> persistence / hive injection'
    'SeTakeOwnershipPrivilege'      = 'Take ownership of files, then grant rights -> overwrite EXEs'
    'SeDebugPrivilege'              = 'OpenProcess on any process -> dump LSASS / inject SYSTEM proc'
    'SeLoadDriverPrivilege'         = 'Load arbitrary kernel driver -> BYOVD (Capcom, RTCore64, dbutil)'
    'SeTcbPrivilege'                = 'Act as part of OS -> token forging'
    'SeManageVolumePrivilege'       = 'Set ACLs on root of any volume -> write to C:\ then DLL hijack'
    'SeShutdownPrivilege'           = 'Trigger reboot — useful for racing service-recovery / patch testing'
    'SeSecurityPrivilege'           = 'Read/clear Security event log'
    'SeCreateTokenPrivilege'        = 'Create primary tokens -> SYSTEM token forging (rare, very strong)'
    'SeChangeNotifyPrivilege'       = '(bypass traverse checking — every account has this; not a privesc)'
}

$out = whoami /priv
$out | ForEach-Object {
    foreach ($p in $exploitable.Keys) {
        if ($_ -match $p) {
            $state = if ($_ -match 'Enabled') { 'ENABLED' } else { 'disabled' }
            $color = if ($state -eq 'ENABLED') { 'Green' } else { 'Yellow' }
            Write-Host "[$state] $p" -ForegroundColor $color
            Write-Host "        $($exploitable[$p])"
        }
    }
}
