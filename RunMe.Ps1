#
# Really bad powershell code to get the job done 
#

# Dwonloading Windows 10 TH2 Security Baseline.zip from microsoft
# Article here https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1511-threshold-2-final/
# psst we just want LGPO.exe


$uri = "https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/4062/00/00/03/65/94/81/Windows%2010%20TH2%20Security%20Baseline.zip"
$file = "$pwd\Windows 10 TH2 Security Baseline.zip"

Invoke-WebRequest -Uri $uri -OutFile $file

#Extracting Zip

Add-Type -Assembly "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory($file, $pwd)

# Placing porfile.ps1 in proper place
# This sets powershell logging in all sessions

New-Item 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1' -type file
"$LogCommandHealthEvent = $true" > "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
"$LogCommandLifecycleEvent = $true" > "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"

# modifying Windows Powershell event logs

limit-eventlog -LogName 'Windows PowerShell' -MaximumSize 999936KB

# Doing the GPOBackup file to Local GPO magic
# Also setting all the CIS and Windows Logging cheet sheet settings that can be set in workstation GPO
# Not everything might be here, but most of it. 
# In addition to the Advance Logging settings, it will add two registery settings
# hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
# hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1

# See Also
# https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/56016bffe4b0a6f05d1832ab/1442933759511/Windows+Logging+Cheat+Sheet_Sept_2015.pdf

& $pwd'\Windows 10 TH2 Security Baselines\Local_Script\Tools\LGPO.exe' '/g' '{00AB999A-5370-4DB3-A10B-2C5C3FBA3993}\'


