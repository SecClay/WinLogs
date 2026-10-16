<#
  End-to-end test for the Windows scripts. Needs an elevated, DISPOSABLE Windows machine
  (a CI runner or a VM snapshot) and internet access. It installs, asserts, re-runs, reverts, asserts.
#>
#Requires -Version 5.1
param([string]$Work = (Join-Path ([IO.Path]::GetTempPath()) 'winlogs-test'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo    = Split-Path $PSScriptRoot -Parent
$install = Join-Path $repo 'windows\Install-WinLogs.ps1'
$prep    = Join-Path $repo 'windows\Prepare-Offline.ps1'
$state   = Join-Path $env:ProgramData 'WinLogs\state.json'
$failed  = @()

# Surface problems as GitHub Actions annotations (readable without downloading the full log).
trap {
    $where = ($_.InvocationInfo.PositionMessage -replace '\r?\n', ' | ')
    Write-Host "::error::$($_.Exception.Message) $where"
    exit 1
}

function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { Write-Host "  PASS  $Name" -ForegroundColor Green }
    else     { Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red; Write-Host "::error::FAIL $Name $Detail"; $script:failed += $Name }
}
function Reg($p, $n) {
    # $null when the key or value is missing (strict mode throws on a bare .$n access).
    $item = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    if ($item -and $item.PSObject.Properties[$n]) { return $item.PSObject.Properties[$n].Value }
    return $null
}
function Audit($sub) { (& auditpol.exe /get /subcategory:"$sub" /r | Out-String) }

Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
$offline = Join-Path $Work 'offline'

Write-Host '== Prepare-Offline'
& $prep -OutPath $offline
Check 'Sysmon.zip downloaded'  (Test-Path (Join-Path $offline 'Sysmon.zip'))
Check 'manifest.json written'  (Test-Path (Join-Path $offline 'manifest.json'))

Write-Host '== Baseline'
$cmdKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$before  = Reg $cmdKey 'ProcessCreationIncludeCmdLine_Enabled'
$auditBefore = Audit 'Process Creation'

Write-Host '== -WhatIf changes nothing'
& $install -OfflinePath $offline -Force -WhatIf | Out-Null
Check 'WhatIf wrote no state file' (-not (Test-Path $state))
Check 'WhatIf left cmdline audit as it was' ((Reg $cmdKey 'ProcessCreationIncludeCmdLine_Enabled') -eq $before)

Write-Host '== Install (offline)'
& $install -OfflinePath $offline -Force
Check 'state.json exists' (Test-Path $state)
Check 'cmdline auditing on'         ((Reg $cmdKey 'ProcessCreationIncludeCmdLine_Enabled') -eq 1)
Check 'legacy audit override on'    ((Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy') -eq 1)
$psw = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Check 'Script Block logging policy' ((Reg "$psw\ScriptBlockLogging" 'EnableScriptBlockLogging') -eq 1)
Check 'Module logging policy'       ((Reg "$psw\ModuleLogging" 'EnableModuleLogging') -eq 1)
Check 'Transcription policy'        ((Reg "$psw\Transcription" 'EnableTranscripting') -eq 1)
Check 'PowerShell 7 policy mirrored' ((Reg 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)
Check 'Process Creation audited (Success)' ((Audit 'Process Creation') -match 'Success')
Check 'Security log >= 1 GB'        ((Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 1GB)
Check 'Task Scheduler log enabled'  ((Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational').IsEnabled)

Write-Host '== Sysmon'
$svc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
Check 'Sysmon service running' ($null -ne $svc -and $svc.Status -eq 'Running')

Write-Host '== Events actually appear'
$marker = 'winlogs-marker-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
& cmd.exe /c "echo $marker" | Out-Null
& powershell.exe -NoProfile -Command "Write-Output '$marker'" | Out-Null
Start-Sleep -Seconds 5
$ev4688 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $marker })
Check '4688 carries the command line' ($ev4688.Count -gt 0)
$ev4104 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $marker })
Check '4104 script block logged' ($ev4104.Count -gt 0)
if ($svc) {
    $sys1 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match $marker })
    Check 'Sysmon event 1 recorded' ($sys1.Count -gt 0)
}

Write-Host '== Re-run is idempotent'
& $install -OfflinePath $offline -Force
Check 'second run succeeded' $true

Write-Host '== Revert'
& $install -Revert -Force
Check 'state.json removed'        (-not (Test-Path $state))
Check 'cmdline auditing restored' ((Reg $cmdKey 'ProcessCreationIncludeCmdLine_Enabled') -eq $before)
Check 'PowerShell policy removed' ($null -eq (Reg "$psw\ScriptBlockLogging" 'EnableScriptBlockLogging'))
Check 'audit policy restored'     ((Audit 'Process Creation') -eq $auditBefore)
Check 'Sysmon service removed'    ($null -eq (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue))

if ($failed.Count) { Write-Host "`n$($failed.Count) failed: $($failed -join '; ')" -ForegroundColor Red; exit 1 }
Write-Host "`nAll checks passed." -ForegroundColor Green
