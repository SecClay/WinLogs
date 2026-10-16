# Third-party components

| Component | License | How WinLogs uses it |
|---|---|---|
| [sysmon-modular](https://github.com/olafhartong/sysmon-modular) config (`windows/sysmon/sysmonconfig-15.21.xml`) | MIT (copy in `windows/sysmon/LICENSE-sysmon-modular.md`) | **Bundled.** Release asset `sysmonconfig.xml`, SHA-256 `64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e`, matching the project's published `SHA256SUMS`. Targets Sysmon 15.21 (schema 4.91). |
| [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) | Sysinternals Software License Terms | **Not bundled.** The Sysinternals terms appear to prohibit redistribution, so the scripts download it from Microsoft (`Prepare-Offline.ps1` for air-gapped labs) and check the Microsoft Authenticode signature. Read the [license terms](https://live.sysinternals.com/Eula.txt) yourself. |

Rule for this repo: only bundle what the license clearly allows, and keep each license text next to the file.
Anything else is fetched by the user, with a signature or SHA-256 check.

The WinLogs scripts and docs themselves are MIT licensed; see `LICENSE`.
