# What the Windows script turns on

| Area | Setting | Where to look |
|---|---|---|
| Audit policy | `windows/audit.csv` via `auditpol /restore` (logon, account/group mgmt, process creation/termination, object access, policy change, sensitive privilege use, ...) | Security log |
| Command lines | `ProcessCreationIncludeCmdLine_Enabled=1` | Security 4688 |
| Legacy override | `SCENoApplyLegacyAuditPolicy=1` so advanced audit policy wins | n/a |
| PowerShell | Script Block (incl. invocation start/stop), Module (`*`), Transcription to `C:\ProgramData\WinLogs\transcripts`; set for Windows PowerShell and PowerShell 7 | Microsoft-Windows-PowerShell/Operational 4103/4104, transcript files |
| Sysmon | sysmon-modular balanced config (process, network, DNS, image load, registry, WMI, pipes, ...) | Microsoft-Windows-Sysmon/Operational |
| Channels enabled / enlarged | Task Scheduler/Operational, DNS-Client/Operational (both usually off), Defender, WMI-Activity, BITS-Client, Firewall, TerminalServices, CodeIntegrity, System, Application | each channel |
| Sizes | Security, Sysmon, PowerShell: `-LogSizeMB` (default 1024). Others: up to 256 MB. Logs are never shrunk. | n/a |

Changes from the original audit policy: added **PNP Activity** (USB / device insertion, 6416) and set **Other Object Access Events** to Success and Failure (scheduled task creation 4698/4702).

Notes
- File System and Registry auditing only produce events for objects that have a SACL; the policy alone does not audit every file.
- Filtering Platform Connection (5156/5158) is very noisy and overlaps Sysmon event 3. Remove that row from `audit.csv` if logs roll too quickly.
- Transcripts are plain files that malware running as admin can delete. Fine for a lab, not evidence-grade.
- Everything is recorded in `C:\ProgramData\WinLogs\state.json`; `-Revert` restores it.
