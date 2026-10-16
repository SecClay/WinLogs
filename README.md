# WinLogs

Quick, disposable-lab logging setup for malware detonation and security-control validation.
Windows is done; Linux and macOS are planned on the same model.

> Use on throwaway lab machines only. It turns on very verbose logging.

## Supported
Windows 10, Windows 11, Windows Server 2022/2025. Windows PowerShell 5.1 or PowerShell 7, run as Administrator.
Older systems are no longer supported. The previous Windows 10 TH2 / LGPO script is in git history.

## Use
```powershell
.\windows\Install-WinLogs.ps1           # asks for confirmation, then applies everything
.\windows\Install-WinLogs.ps1 -WhatIf   # show what would change
.\windows\Install-WinLogs.ps1 -Revert   # undo
```
Options: `-SkipSysmon`, `-SysmonConfigPath`, `-SysmonSha256`, `-LogSizeMB`, `-Force`, `-OfflinePath`.

## Air-gapped labs
Sysmon is not redistributable, so fetch it once on a connected machine:
```powershell
.\windows\Prepare-Offline.ps1 -OutPath E:\winlogs-offline
# copy the repo and that folder to the lab, then
.\windows\Install-WinLogs.ps1 -OfflinePath E:\winlogs-offline
```
The bundle is checked against Microsoft's signature and a SHA-256 manifest.

## What you get
See [docs/what-gets-logged.md](docs/what-gets-logged.md). Third-party licenses: [THIRD_PARTY.md](THIRD_PARTY.md).

## Status
The Windows scripts parse cleanly but have **not been run on Windows yet**. Treat the first run as a test in a snapshot-able VM.
Not yet done: Linux, macOS, using the built-in Sysmon on Windows 11 / Server 2025, optional log forwarding.

## Resources
Original inspiration (older: the core Windows cheat sheet is Feb 2019, the Sysmon one Jan 2020):
- https://www.malwarearchaeology.com/cheat-sheets
- https://www.log-md.com/

Newer / maintained:
- https://github.com/olafhartong/sysmon-modular (the Sysmon config bundled here, MIT)
- https://github.com/Yamato-Security/EnableWindowsLogSettings (audit/log settings aimed at Sigma coverage; GPL-3.0, so referenced rather than bundled)
- https://learn.microsoft.com/windows-server/administration/windows-commands/sysmon (Microsoft's Sysmon docs, including the built-in Windows 11 feature)
- https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing (advanced audit policy reference)
