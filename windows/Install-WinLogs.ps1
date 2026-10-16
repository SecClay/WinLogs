<#
.SYNOPSIS
    Quickly turn on forensic-grade Windows logging for malware / detection labs.

.DESCRIPTION
    Supports Windows 10, Windows 11 and Windows Server 2022/2025 (Windows PowerShell 5.1 or PowerShell 7).
    Run from an elevated prompt. Intended for disposable lab machines only.

    What it does:
      * Advanced audit policy            (auditpol /restore from audit.csv)
      * Command line in process events   (4688)
      * PowerShell Script Block, Module and Transcription logging (Windows PowerShell + PowerShell 7)
      * Larger event logs, and enables useful channels that are off by default
        (Task Scheduler, DNS Client, ...)
      * Sysmon with the bundled sysmon-modular config (on by default)

    Everything it changes is recorded in C:\ProgramData\WinLogs\state.json so -Revert can undo it.

.PARAMETER OfflinePath
    Folder produced by Prepare-Offline.ps1 (contains Sysmon.zip and manifest.json). No network access is used.

.PARAMETER SkipSysmon
    Do not install or configure Sysmon.

.PARAMETER SysmonConfigPath
    Use this Sysmon config instead of the bundled one.

.PARAMETER SysmonSha256
    Optional SHA-256 the Sysmon.zip must match (downloaded or offline). The Authenticode signature of the
    extracted binary is always checked.

.PARAMETER LogSizeMB
    Maximum size for the big channels (Security, Sysmon, PowerShell). Default 1024.

.PARAMETER Revert
    Restore the settings captured by the last run and remove Sysmon (unless -KeepSysmon).

.PARAMETER Force
    Skip the "this is a lab machine" confirmation (for automation).

.EXAMPLE
    .\Install-WinLogs.ps1
.EXAMPLE
    .\Install-WinLogs.ps1 -OfflinePath D:\winlogs-offline -Force
.EXAMPLE
    .\Install-WinLogs.ps1 -WhatIf
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OfflinePath,
    [switch]$SkipSysmon,
    [string]$SysmonConfigPath,
    [string]$SysmonSha256,
    [ValidateRange(64, 65536)][int]$LogSizeMB = 1024,
    [switch]$Revert,
    [switch]$KeepSysmon,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root      = $PSScriptRoot
$DataDir   = Join-Path $env:ProgramData 'WinLogs'
$StateFile = Join-Path $DataDir 'state.json'
$TranscriptDir = Join-Path $DataDir 'transcripts'
$SysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'

# --- helpers ----------------------------------------------------------------------------------

function Write-Step([string]$Message) { Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Warn([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

function Get-State {
    if (Test-Path $StateFile) { return Get-Content $StateFile -Raw | ConvertFrom-Json }
    return $null
}

function New-State {
    [ordered]@{
        created        = (Get-Date).ToString('o')
        auditBackup    = $null
        registry       = @()   # {path,name,existed,type,value}
        registryKeys   = @()   # keys we created
        logs           = @()   # {name,enabled,maxBytes}
        sysmon         = $null # {installedByUs,mode}
    }
}

function Save-State($State) {
    if ($WhatIfPreference) { return }
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    $State | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8
}

# Sets a registry value and records the previous value (first write wins, so re-runs keep the original).
function Set-TrackedValue($State, [string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    $already = @($State.registry) | Where-Object { $_.path -eq $Path -and $_.name -eq $Name }
    if (-not $already) {
        $entry = [ordered]@{ path = $Path; name = $Name; existed = $false; type = $null; value = $null }
        if (-not (Test-Path $Path)) { $State.registryKeys += $Path }
        elseif ((Get-Item -Path $Path).GetValueNames() -contains $Name) {
            $key = Get-Item -Path $Path
            $entry.existed = $true
            $entry.type    = $key.GetValueKind($Name).ToString()
            $entry.value   = $key.GetValue($Name)
        }
        $State.registry += $entry
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

function Set-TrackedLog($State, [string]$Name, [int]$SizeMB, [bool]$Enable) {
    try { $log = Get-WinEvent -ListLog $Name -ErrorAction Stop } catch {
        Write-Verbose "Log '$Name' not present on this system, skipping."
        return
    }
    if (-not (@($State.logs) | Where-Object { $_.name -eq $Name })) {
        $State.logs += [ordered]@{ name = $Name; enabled = $log.IsEnabled; maxBytes = $log.MaximumSizeInBytes }
    }
    $target = [int64]$SizeMB * 1MB
    if ($PSCmdlet.ShouldProcess($Name, "Max size ${SizeMB}MB, enabled=$Enable")) {
        # Never shrink a log that is already larger than requested.
        if ($log.MaximumSizeInBytes -lt $target) { $log.MaximumSizeInBytes = $target }
        if ($Enable) { $log.IsEnabled = $true }
        # The Security log rejects SaveChanges(); wevtutil handles it. A channel that still fails
        # (odd build, analytic/debug log) should not abort the whole run.
        try { $log.SaveChanges() } catch {
            $size = [math]::Max($log.MaximumSizeInBytes, $target)
            $out = & { $ErrorActionPreference = 'Continue'; & wevtutil.exe sl "$Name" "/ms:$size" 2>&1 | Out-String }
            if ($LASTEXITCODE -ne 0) { Write-Warn "Could not configure log '$Name': $($out.Trim())" }
        }
    }
}

function Confirm-Lab {
    if ($Force -or $WhatIfPreference) { return }
    Write-Warn 'This turns on very verbose logging and (optionally) installs Sysmon.'
    Write-Warn 'Use it on disposable lab machines, not on production or work computers.'
    $answer = Read-Host 'Type YES to continue'
    if ($answer -cne 'YES') { throw 'Aborted.' }
}

# --- revert -----------------------------------------------------------------------------------

function Invoke-Revert {
    $state = Get-State
    if (-not $state) { throw "No state file at $StateFile, nothing to revert." }
    Confirm-Lab

    if ($state.auditBackup -and (Test-Path $state.auditBackup)) {
        Write-Step 'Restoring audit policy'
        if ($PSCmdlet.ShouldProcess('audit policy', 'auditpol /restore')) {
            & auditpol.exe /restore /file:"$($state.auditBackup)" | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warn 'auditpol /restore failed.' }
        }
    }

    Write-Step 'Restoring registry values'
    foreach ($e in @($state.registry)) {
        if (-not $PSCmdlet.ShouldProcess("$($e.path)\$($e.name)", 'Restore')) { continue }
        if ($e.existed) {
            New-ItemProperty -Path $e.path -Name $e.name -Value $e.value -PropertyType $e.type -Force | Out-Null
        } else {
            # .NET API on purpose: Remove-ItemProperty treats a value named '*' as a wildcard.
            $sub = Get-Item -Path $e.path -ErrorAction SilentlyContinue
            if ($sub) {
                $hklm = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($e.path -replace '^HKLM:\\', ''), $true)
                if ($hklm) { $hklm.DeleteValue($e.name, $false); $hklm.Close() }
            }
        }
    }
    # Remove keys we created, deepest first, only if empty.
    foreach ($k in @($state.registryKeys) | Sort-Object { $_.Length } -Descending) {
        if ((Test-Path $k) -and -not (Get-ChildItem $k -ErrorAction SilentlyContinue) -and
            -not (Get-Item $k).ValueCount) {
            if ($PSCmdlet.ShouldProcess($k, 'Remove empty key')) { Remove-Item $k -ErrorAction SilentlyContinue }
        }
    }

    Write-Step 'Restoring event log settings'
    foreach ($l in @($state.logs)) {
        if (-not $PSCmdlet.ShouldProcess($l.name, 'Restore')) { continue }
        try {
            $log = Get-WinEvent -ListLog $l.name -ErrorAction Stop
            $log.MaximumSizeInBytes = [int64]$l.maxBytes
            $log.IsEnabled = [bool]$l.enabled
            try { $log.SaveChanges() } catch {
                & { $ErrorActionPreference = 'Continue'; & wevtutil.exe sl "$($l.name)" "/ms:$([int64]$l.maxBytes)" 2>&1 | Out-Null }
                if ($LASTEXITCODE -ne 0) { throw }
            }
        } catch { Write-Warn "Could not restore log $($l.name): $_" }
    }

    if ($state.sysmon -and $state.sysmon.installedByUs -and -not $KeepSysmon) {
        Write-Step 'Removing Sysmon'
        $exe = $state.sysmon.exe
        if ($PSCmdlet.ShouldProcess('Sysmon', 'Uninstall')) {
            if ($exe -and (Test-Path $exe)) { & $exe -accepteula -u force | Out-Null }
            else { Write-Warn 'Sysmon binary not found; remove it manually.' }
        }
    }

    if ($PSCmdlet.ShouldProcess($StateFile, 'Delete')) { Remove-Item $StateFile -Force }
    Write-Host "Reverted. Transcripts (if any) were left in $TranscriptDir." -ForegroundColor Green
}

# --- sysmon -----------------------------------------------------------------------------------

function Get-SysmonBinaryName {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'Sysmon64.exe' }
        'ARM64' { 'Sysmon64a.exe' }
        default { 'Sysmon.exe' }
    }
}

function Get-SysmonZip {
    if ($OfflinePath) {
        $zip = Join-Path $OfflinePath 'Sysmon.zip'
        if (-not (Test-Path $zip)) { throw "Sysmon.zip not found in $OfflinePath. Run Prepare-Offline.ps1 first." }
        $manifestPath = Join-Path $OfflinePath 'manifest.json'
        if (Test-Path $manifestPath) {
            $expected = ((Get-Content $manifestPath -Raw | ConvertFrom-Json).files |
                Where-Object { $_.name -eq 'Sysmon.zip' }).sha256
            if ($expected -and (Get-FileHash $zip -Algorithm SHA256).Hash -ne $expected) {
                throw "Sysmon.zip does not match manifest.json. Refusing to use it."
            }
        } else { Write-Warn 'No manifest.json next to Sysmon.zip; only the signature check will apply.' }
        return $zip
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $zip = Join-Path ([IO.Path]::GetTempPath()) 'Sysmon.zip'
    Write-Step "Downloading Sysmon from $SysmonUrl"
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $zip -UseBasicParsing
    return $zip
}

function Assert-MicrosoftSigned([string]$Path) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "$Path is not validly signed by Microsoft Corporation (status: $($sig.Status))."
    }
}

function Install-WinLogsSysmon($State) {
    $config = $SysmonConfigPath
    if (-not $config) { $config = Join-Path $Root 'sysmon\sysmonconfig-15.21.xml' }
    if (-not (Test-Path $config)) { throw "Sysmon config not found: $config" }

    $installDir = Join-Path $DataDir 'sysmon'
    $binName    = Get-SysmonBinaryName
    $exe        = Join-Path $installDir $binName

    # Reuse an existing install (any source) instead of fighting it.
    $existing = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) {
        $raw  = (Get-CimInstance Win32_Service -Filter "Name='$($existing.Name)'").PathName
        $path = if ($raw -match '^"([^"]+)"') { $Matches[1] } else { ($raw -split '\s+')[0] }
        Write-Step "Sysmon already installed ($path); updating its configuration"
        if ($PSCmdlet.ShouldProcess($path, "Sysmon -c $config")) {
            & $path -accepteula -c $config | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Sysmon -c failed (exit $LASTEXITCODE)." }
        }
        # On a re-run the service is ours from the first run; keep that so -Revert still removes it.
        if (-not ($State.sysmon -and $State.sysmon.installedByUs)) {
            $State.sysmon = [ordered]@{ installedByUs = $false; exe = $path }
        }
        return
    }

    $zip = Get-SysmonZip
    if ($SysmonSha256 -and (Get-FileHash $zip -Algorithm SHA256).Hash -ne $SysmonSha256.ToUpperInvariant()) {
        throw "Sysmon.zip SHA-256 does not match -SysmonSha256."
    }

    if ($PSCmdlet.ShouldProcess($exe, 'Extract and install Sysmon')) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        Expand-Archive -Path $zip -DestinationPath $installDir -Force
        Assert-MicrosoftSigned $exe

        $ver = $null
        try { $ver = [version]((Get-Item $exe).VersionInfo.FileVersion -replace '[^\d\.].*$', '') } catch { }
        if ($ver -and $ver -lt [version]'15.21') {
            Write-Warn "Sysmon $ver is older than the config's target (15.21); it may reject the config."
        }

        Write-Step "Installing Sysmon $ver"
        & $exe -accepteula -i $config | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed (exit $LASTEXITCODE)." }
        $State.sysmon = [ordered]@{ installedByUs = $true; exe = $exe }
    }
}

# --- main -------------------------------------------------------------------------------------

if ($Revert) { Invoke-Revert; return }

$os = Get-CimInstance Win32_OperatingSystem
if ([version]$os.Version -lt [version]'10.0') { throw "Unsupported OS: $($os.Caption). Windows 10 or later is required." }
Write-Host "WinLogs on $($os.Caption) (build $($os.BuildNumber))"
Confirm-Lab

$state = $null
$prior = Get-State
if ($prior) {
    # Re-run: keep the original "before" snapshot so -Revert still returns the machine to its first state.
    $state = $prior
    $state.registry     = @($state.registry)
    $state.registryKeys = @($state.registryKeys)
    $state.logs         = @($state.logs)
} else { $state = New-State }

# 1. Advanced audit policy
Write-Step 'Applying advanced audit policy'
$auditCsv = Join-Path $Root 'audit.csv'
if ($PSCmdlet.ShouldProcess('audit policy', "auditpol /restore $auditCsv")) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    if (-not $state.auditBackup) {
        $backup = Join-Path $DataDir 'audit-before.csv'
        if (Test-Path $backup) { Remove-Item $backup -Force }
        & auditpol.exe /backup /file:"$backup" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'auditpol /backup failed.' }
        $state.auditBackup = $backup
    }
    & auditpol.exe /restore /file:"$auditCsv" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /restore failed.' }
}

# 2. Registry: command line auditing, legacy audit override, PowerShell logging
Write-Step 'Configuring command line auditing and PowerShell logging'
Set-TrackedValue $state 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Set-TrackedValue $state 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1

if ($PSCmdlet.ShouldProcess($TranscriptDir, 'Create transcript folder')) {
    New-Item -ItemType Directory -Path $TranscriptDir -Force | Out-Null
}
# Windows PowerShell and PowerShell 7 read the same value names under different policy roots.
foreach ($psRoot in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell', 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore') {
    Set-TrackedValue $state "$psRoot\ScriptBlockLogging" 'EnableScriptBlockLogging' 1
    Set-TrackedValue $state "$psRoot\ScriptBlockLogging" 'EnableScriptBlockInvocationLogging' 1
    Set-TrackedValue $state "$psRoot\ModuleLogging" 'EnableModuleLogging' 1
    Set-TrackedValue $state "$psRoot\ModuleLogging\ModuleNames" '*' '*' 'String'
    Set-TrackedValue $state "$psRoot\Transcription" 'EnableTranscripting' 1
    Set-TrackedValue $state "$psRoot\Transcription" 'EnableInvocationHeader' 1
    Set-TrackedValue $state "$psRoot\Transcription" 'OutputDirectory' $TranscriptDir 'String'
}

# 3. Sysmon (before log sizing, so its event log exists)
if ($SkipSysmon) {
    Write-Warn 'Skipping Sysmon (-SkipSysmon).'
} else {
    Write-Step 'Setting up Sysmon'
    Install-WinLogsSysmon $state
    Save-State $state
}

# 4. Event logs: sizes, and channels that are off by default
Write-Step 'Sizing and enabling event logs'
$big = 'Security', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell'
foreach ($n in $big) { Set-TrackedLog $state $n $LogSizeMB $true }
$medium = 'System', 'Application',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational'
foreach ($n in $medium) { Set-TrackedLog $state $n ([math]::Min(256, $LogSizeMB)) $true }
# Off by default on most builds; valuable for persistence and DNS visibility.
foreach ($n in 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-DNS-Client/Operational') {
    Set-TrackedLog $state $n ([math]::Min(256, $LogSizeMB)) $true
}

Save-State $state

Write-Host ''
Write-Host 'Done. Logs are collecting now; no reboot needed.' -ForegroundColor Green
Write-Host "  Undo:        .\Install-WinLogs.ps1 -Revert"
Write-Host "  Transcripts: $TranscriptDir"
Write-Host '  Tip: PowerShell sessions opened before this run are not covered, open a new one.'
