<#
.SYNOPSIS
    Download and verify everything WinLogs needs, so the lab machine never needs internet access.

.DESCRIPTION
    Run this on a machine WITH internet access, then copy the output folder to the lab and run
        .\Install-WinLogs.ps1 -OfflinePath <folder>

    Sysmon is Microsoft software under the Sysinternals license, which this repo does not redistribute.
    Each person downloads it from Microsoft with this script instead.

    Output folder:
        Sysmon.zip       straight from download.sysinternals.com
        manifest.json    SHA-256 of each file, source URL, Sysmon version, download date
        sysmonconfig.xml (only with -RefreshSysmonConfig) latest sysmon-modular config, checked against its SHA256SUMS

.PARAMETER OutPath
    Where to write the offline bundle. Default .\winlogs-offline

.PARAMETER RefreshSysmonConfig
    Also fetch the latest sysmon-modular balanced config (MIT) and verify it against the project's SHA256SUMS.
    The repo already bundles a pinned copy, so this is optional.

.EXAMPLE
    .\Prepare-Offline.ps1 -OutPath E:\winlogs-offline
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutPath = (Join-Path (Get-Location) 'winlogs-offline'),
    [switch]$RefreshSysmonConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$SysmonUrl  = 'https://download.sysinternals.com/files/Sysmon.zip'
$ConfigBase = 'https://github.com/olafhartong/sysmon-modular/releases/latest/download'

New-Item -ItemType Directory -Path $OutPath -Force | Out-Null
$OutPath = (Resolve-Path $OutPath).Path
$files = @()

function Add-File([string]$Name, [string]$Url) {
    $dest = Join-Path $OutPath $Name
    Write-Host "[*] Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing
    $script:files += [ordered]@{
        name   = $Name
        url    = $Url
        sha256 = (Get-FileHash $dest -Algorithm SHA256).Hash
    }
    return $dest
}

# --- Sysmon -----------------------------------------------------------------------------------
$zip = Add-File 'Sysmon.zip' $SysmonUrl

# Prove the zip holds Microsoft-signed binaries before it goes anywhere near the lab.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("winlogs-" + [guid]::NewGuid())
try {
    Expand-Archive -Path $zip -DestinationPath $tmp
    $sysmonVersion = $null
    foreach ($exe in 'Sysmon.exe', 'Sysmon64.exe', 'Sysmon64a.exe') {
        $p = Join-Path $tmp $exe
        if (-not (Test-Path $p)) { Write-Warning "$exe not found in Sysmon.zip"; continue }
        $sig = Get-AuthenticodeSignature -FilePath $p
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw "$exe is not validly signed by Microsoft Corporation (status: $($sig.Status))."
        }
        if (-not $sysmonVersion) { $sysmonVersion = (Get-Item $p).VersionInfo.FileVersion }
        Write-Host "[+] $exe signature OK"
    }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- optional: fresh sysmon-modular config ----------------------------------------------------
if ($RefreshSysmonConfig) {
    $sums = Join-Path $OutPath 'SHA256SUMS'
    Invoke-WebRequest -Uri "$ConfigBase/SHA256SUMS" -OutFile $sums -UseBasicParsing
    $cfg = Add-File 'sysmonconfig.xml' "$ConfigBase/sysmonconfig.xml"
    $line = Get-Content $sums | Where-Object { $_ -match '\ssysmonconfig\.xml\s*$' } | Select-Object -First 1
    if (-not $line) { throw 'sysmonconfig.xml is not listed in the published SHA256SUMS.' }
    $expected = ($line -split '\s+')[0]
    if ((Get-FileHash $cfg -Algorithm SHA256).Hash -ne $expected.ToUpperInvariant()) {
        throw 'sysmonconfig.xml does not match the published SHA256SUMS.'
    }
    Remove-Item $sums -Force
    Write-Host '[+] sysmonconfig.xml matches published SHA256SUMS'
}

[ordered]@{
    created        = (Get-Date).ToString('o')
    sysmonVersion  = $sysmonVersion
    files          = $files
} | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutPath 'manifest.json') -Encoding UTF8

Write-Host ''
Write-Host "Offline bundle ready: $OutPath" -ForegroundColor Green
Write-Host 'Copy it to the lab machine, then:  .\Install-WinLogs.ps1 -OfflinePath <folder>'
if ($RefreshSysmonConfig) { Write-Host 'Pass -SysmonConfigPath <folder>\sysmonconfig.xml to use the refreshed config.' }
