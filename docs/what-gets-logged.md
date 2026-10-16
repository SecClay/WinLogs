# What gets logged

Each OS has its own page with the exact settings, where to find the events, and the limits.

| | [Windows](logged-windows.md) | [Linux](logged-linux.md) | [macOS](logged-macos.md) |
|---|---|---|---|
| Script | `windows/Install-WinLogs.ps1` | `linux/install.sh` | `macos/install.sh` |
| Process creation | Security 4688 with command line, Sysmon 1 | `auditd` `process_creation`, optional Sysmon for Linux | `eslogger` `exec` |
| Authentication and accounts | Audit policy (logon, account/group management, Kerberos on Server) | `auditd` (`pam`, `login`, `etcpasswd`, ...) | `eslogger` login, sudo, su, ssh, account changes |
| Scripting visibility | PowerShell Script Block, Module and Transcription | Interactive bash to syslog | Interactive zsh to the unified log |
| File / registry changes | Per-object audit rules (SACLs) on persistence keys and folders | `auditd` file watches and syscall rules | `eslogger` create/unlink/rename |
| Network connections | Sysmon 3, Filtering Platform 5156 | `auditd` socket rules, Sysmon for Linux | not available from Endpoint Security |
| Persistence | Run keys, services, scheduled tasks, StartUp | `cron`, `systemd`, profile and preload watches | Background Task Management items |
| Malware detections | Defender operational log | n/a | XProtect events via `eslogger` |
| Where it is stored | Event Log channels (sized up to 1 GB) | `/var/log/audit`, persistent journal | `/var/log/winlogs/eslogger.ndjson`, unified log |
| Undo | `-Revert` | `--revert` | `--revert` |
| Offline install | `Prepare-Offline.ps1` | `prepare-offline.sh` | nothing to download |
| CI | Server 2022/2025, Windows 11 ARM64 | Ubuntu 22.04/24.04, Fedora (container) | macOS 14/15 |
