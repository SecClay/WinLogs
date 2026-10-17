# WinLogs: one-command logging setup for malware analysis and detection labs

[![test](https://github.com/ClaySecAI/WinLogs/actions/workflows/test.yml/badge.svg)](https://github.com/ClaySecAI/WinLogs/actions/workflows/test.yml)

WinLogs turns on the telemetry you want **before** you detonate malware, validate a security control, or run a detection-engineering exercise: Windows audit policy, PowerShell Script Block / Module / Transcription logging, Sysmon, `auditd`, and persistent `journald`. One script per OS, safe to re-run, fully revertable, and usable on air-gapped lab machines.

Built for disposable VMs: malware analysis sandboxes, DFIR and threat-hunting practice, Sigma rule testing, purple-team and blue-team labs. **Do not run it on production or work machines.** It turns on very verbose logging.

**Scope:** logging only. WinLogs configures the logs and the components that produce and keep them (audit policy, Sysmon, `auditd`, `eslogger`, retention). Other tooling, such as network capture, endpoint query tools or evidence collectors, belongs in a separate setup stage that can read the logs this one produces.

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

**macOS 13+** (as root; nothing to download):
```bash
sudo ./macos/install.sh                  # asks for confirmation, then applies everything
sudo ./macos/install.sh --dry-run        # preview
sudo ./macos/install.sh --revert         # undo
```
`eslogger` needs Full Disk Access, which macOS only lets a person grant by hand; the installer tells you exactly where. See [docs/logged-macos.md](docs/logged-macos.md).

## What you get

| | Windows | Linux | macOS |
|---|---|---|---|
| Audit policy | Advanced audit policy via `auditpol` (logon, account and group management, process creation 4688 with command line, object access, policy change, DPAPI, SAM, ...) plus a Server profile (Kerberos, Directory Service) | `auditd` with the [Neo23x0 ruleset](https://github.com/Neo23x0/auditd): exec, file, network, privilege and persistence rules | Apple's `eslogger` (Endpoint Security) as a LaunchDaemon: exec, file create/delete/rename, persistence items, XProtect, logins, sudo/su, profile and TCC changes |
| Scripting visibility | PowerShell Script Block (4104), Module (4103) and Transcription logging for Windows PowerShell and PowerShell 7 | Interactive bash commands logged to syslog | Interactive zsh commands logged to the unified log |
| Process / network / DNS / file telemetry | **Sysmon** with the [sysmon-modular](https://github.com/olafhartong/sysmon-modular) config (on by default) | `auditd` execve rules; **Sysmon for Linux** is opt-in with `--with-sysmon` | `eslogger` JSON events (no Sysmon equivalent; no network connect events) |
| Retention | Event logs raised to 1 GB for Security, Sysmon and PowerShell; Task Scheduler, DNS-Client and more channels enabled | `auditd` keeps 10 x 200 MB with synchronous writes; `journald` persistent with rate limiting off | `/var/log/winlogs/eslogger.ndjson` rotated at 100 MB x 10; optional daily unified-log archives |
| Object auditing | Per-object audit rules (SACLs) on persistence and tamper-prone registry keys and folders | n/a (covered by `auditd` watches) | n/a (covered by `eslogger` file events) |
| Undo | `-Revert` | `--revert` | `--revert` |

Per-OS details, event IDs and limits: [Windows](docs/logged-windows.md) · [Linux](docs/logged-linux.md) · [macOS](docs/logged-macos.md) · [side-by-side overview](docs/what-gets-logged.md).

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
macOS needs no offline step: it only uses tools that ship with the OS.

## Tested

CI runs the full install, verify-events and revert cycle on Windows Server 2022 and 2025 (Windows PowerShell 5.1 and PowerShell 7), Windows 11 on ARM64, Ubuntu 22.04 and 24.04, and macOS 14 and 15 (Apple silicon). The Fedora job runs in a container, so it covers package install, config and revert but not live auditing.

Not yet tested: Windows 10 and x64 Windows 11 client builds, a real domain controller, RHEL-family live auditing (Rocky/Alma), Debian, Kali, openSUSE, Arch, and Sysmon for Linux, and on macOS: Intel Macs, macOS 13, and a Mac where Full Disk Access has not been granted. Treat the first run as a test inside a snapshot-able VM.

## Origin: from a Windows 7 script to a CI-tested, cross-platform tool

WinLogs started in the Windows 7 era as a quick PowerShell script for turning on useful logging in malware labs. It worked, and it aged: it leaned on legacy tooling (LocalGPO) and had no way to test changes without a live lab.

The modernization started with a single task given to Claude: "modernize." Working together, we updated it for current Windows, removed the dependency on LocalGPO, built CI that exercises install, verify and revert without live targets, and extended it to Linux and macOS.

The takeaway for anyone with an old tool of their own: give an agent a clear outcome, and make automated tests the thing you trust.

## Related projects

Maintained logging guidance and tools worth knowing, and what inspired this one:
- [Yamato-Security/EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings): Windows log settings aimed at Sigma coverage
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular): modular Sysmon configs
- [Neo23x0/auditd](https://github.com/Neo23x0/auditd): best-practice auditd rules
- [Cybereason: Blue teaming on macOS with eslogger](https://www.cybereason.com/blog/blue-teaming-on-macos-with-eslogger): how Apple's `eslogger` is used for detection and analysis
- [Malware Archaeology logging cheat sheets](https://www.malwarearchaeology.com/cheat-sheets) and [Log-MD](https://www.log-md.com/): the original inspiration (the core Windows sheet dates from 2019)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/windows-server/administration/windows-commands/sysmon) and [advanced security auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)

Bundled third-party files keep their own licenses: [THIRD_PARTY.md](THIRD_PARTY.md).

## License

[MIT](LICENSE) for the WinLogs scripts and docs.

## Disclaimer

Built to set up temporary systems that will run hostile software. It works for the author's labs; test it in yours before trusting it. No warranty.

This is personal work. Views and projects here are my own; they do not represent my employer, past or present, and contain no employer data.
