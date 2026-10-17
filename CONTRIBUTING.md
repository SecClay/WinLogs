# Contributing

Bug reports, fixes and support for more platforms are welcome. Two things matter more than anything
else here: the scope stays logging only, and every change can be previewed and undone.

## Scope

WinLogs configures logs and the components that produce and keep them: audit policy, Sysmon,
`auditd`, `eslogger`, retention. It does not install analysis tools, change other security settings,
or weaken anything. A change outside that scope belongs in another project.

## Every change can be previewed and reverted

- Windows: anything `Install-WinLogs.ps1` applies must show in `-WhatIf` and be undone by `-Revert`.
- Linux and macOS: the same for `--dry-run` and `--revert` in `linux/install.sh` and
  `macos/install.sh`.

Add a test that shows it.

## Run the tests

Run them in a disposable VM, never on a machine you care about.

```powershell
.\tests\Test-WinLogs.ps1            # Windows PowerShell 5.1 and PowerShell 7
```

```bash
sudo ./tests/test-linux.sh
sudo ./tests/test-macos.sh
shellcheck -e SC1091 linux/install.sh linux/prepare-offline.sh tests/test-linux.sh
```

CI runs all of these on every pull request.

## Keep real systems out of it

Logs are full of hostnames, usernames, IP addresses and process command lines. Do not paste output
from a real machine into an issue or a pull request. Reproduce the problem on a lab VM, or replace
those values with placeholders such as `<host>`.

Security problems are reported privately; see [SECURITY.md](SECURITY.md). Everyone taking part
follows the [code of conduct](CODE_OF_CONDUCT.md).
