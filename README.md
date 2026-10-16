# WinLogs: one-command logging setup for malware analysis and detection labs

[![test](https://github.com/SecClay/WinLogs/actions/workflows/test.yml/badge.svg)](https://github.com/SecClay/WinLogs/actions/workflows/test.yml)

WinLogs turns on the telemetry you want **before** you detonate malware, validate a security control, or run a detection-engineering exercise: Windows audit policy, PowerShell Script Block / Module / Transcription logging, Sysmon, `auditd`, and persistent `journald`. One script per OS, safe to re-run, fully revertable, and usable on air-gapped lab machines.

Built for disposable VMs: malware analysis sandboxes, DFIR and threat-hunting practice, Sigma rule testing, purple-team and blue-team labs. **Do not run it on production or work machines.** It turns on very verbose logging.

## Quick start

**Windows 10 / 11 / Server 2022 / 2025** (elevated PowerShell 5.1 or 7):
```powershell
.\windows\Install-WinLogs.ps1            # asks for confirmation, then applies everything
.\windows\Install-WinLogs.ps1 -WhatIf    # preview
.\windows\Install-WinLogs.ps1 -Revert    # undo
```

**Linux** (Debian/Ubuntu/Kali, RHEL/Fedora/Rocky/Alma, openSUSE, Arch; as root):
```bash
sudo ./linux/install.sh                  # asks for confirmation, then applies everything
sudo ./linux/install.sh --dry-run        # preview
sudo ./linux/install.sh --revert         # undo
```

## What you get

| | Windows | Linux |
|---|---|---|
| Audit policy | Advanced audit policy via `auditpol` (logon, account and group management, process creation 4688 with command line, object access, policy change, DPAPI, SAM, ...) plus a Server profile (Kerberos, Directory Service) | `auditd` with the [Neo23x0 ruleset](https://github.com/Neo23x0/auditd): exec, file, network, privilege and persistence rules |
| Scripting visibility | PowerShell Script Block (4104), Module (4103) and Transcription logging for Windows PowerShell and PowerShell 7 | Interactive bash commands logged to syslog |
| Process / network / DNS / file telemetry | **Sysmon** with the [sysmon-modular](https://github.com/olafhartong/sysmon-modular) config (on by default) | `auditd` execve rules; **Sysmon for Linux** is opt-in with `--with-sysmon` |
| Retention | Event logs raised to 1 GB for Security, Sysmon and PowerShell; Task Scheduler, DNS-Client and more channels enabled | `auditd` keeps 10 x 200 MB with synchronous writes; `journald` persistent with rate limiting off |
| Object auditing | Per-object audit rules (SACLs) on persistence and tamper-prone registry keys and folders | n/a (covered by `auditd` watches) |
| Undo | `-Revert` | `--revert` |

Details and event IDs: [docs/what-gets-logged.md](docs/what-gets-logged.md).

## Air-gapped labs

Sysmon is Microsoft software that this repo does not redistribute, and lab machines often have no internet. Fetch what you need once on a connected machine, carry the folder in, and install offline:

```powershell
.\windows\Prepare-Offline.ps1 -OutPath E:\winlogs-offline        # Sysmon, signature + SHA-256 checked
.\windows\Install-WinLogs.ps1 -OfflinePath E:\winlogs-offline
```
```bash
sudo ./linux/prepare-offline.sh ./winlogs-offline                # run on a machine matching the lab image
sudo ./linux/install.sh --offline-dir ./winlogs-offline          # verified against SHA256SUMS
```

## Tested

CI runs the full install, verify-events and revert cycle on Windows Server 2022 and 2025 (Windows PowerShell 5.1 and PowerShell 7), Windows 11 on ARM64, and Ubuntu 22.04 and 24.04. The Fedora job runs in a container, so it covers package install, config and revert but not live auditing.

Not yet tested: Windows 10 and x64 Windows 11 client builds, a real domain controller, RHEL-family live auditing (Rocky/Alma), Debian, Kali, openSUSE, Arch, and Sysmon for Linux. Treat the first run as a test inside a snapshot-able VM. macOS is planned.

## Related projects

Maintained logging guidance and tools worth knowing, and what inspired this one:
- [Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings): Windows log settings aimed at Sigma coverage
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular): modular Sysmon configs
- [Neo23x0/auditd](https://github.com/Neo23x0/auditd): best-practice auditd rules
- [Malware Archaeology logging cheat sheets](https://www.malwarearchaeology.com/cheat-sheets) and [Log-MD](https://www.log-md.com/): the original inspiration (the core Windows sheet dates from 2019)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/windows-server/administration/windows-commands/sysmon) and [advanced security auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)

Bundled third-party files and their licenses: [THIRD_PARTY.md](THIRD_PARTY.md).

## Disclaimer

Built to set up temporary systems that will run hostile software. It works for the author's labs; test it in yours before trusting it. No warranty.
