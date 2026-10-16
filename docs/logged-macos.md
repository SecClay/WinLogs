# macOS: what gets logged

See also: [Windows](logged-windows.md) · [Linux](logged-linux.md) · [overview](what-gets-logged.md)

`macos/install.sh` (macOS 13 Ventura or newer, run with `sudo`) uses only tools that ship with macOS, so there is nothing to download and no offline bundle to prepare.

## What it turns on

| Piece | How | Where to look |
|---|---|---|
| Endpoint Security events | Apple's `eslogger` runs as a LaunchDaemon (`com.winlogs.eslogger`) writing newline-delimited JSON | `/var/log/winlogs/eslogger.ndjson` (rotated at 100 MB, 10 kept, gzip, by `newsyslog`) |
| zsh command history | A marker block in `/etc/zshrc` logs each interactive command through `logger` | `log show --predicate 'eventMessage contains "winlogs-cmd"'` |
| Application firewall logging | `socketfilterfw --setloggingmode on` (previous mode restored on revert) | unified log / `/var/log/appfirewall.log` on older releases |
| Unified log snapshots (opt-in, `--with-log-archive`) | Daily `log collect --last 1d`, pruned after `--keep-days` (default 7) | `/var/log/winlogs/unified-YYYY-MM-DD.logarchive` |

Event types recorded (those this macOS supports; the list is checked against `eslogger --list-events` at install time): process exec, file create/unlink/rename, mount, kext load, background-item (persistence) add/remove, XProtect malware detected/remediated, logins (local, ssh, screen sharing), sudo/su, profile install/remove, Gatekeeper overrides, TCC changes, remote thread creation, code-signature invalidation, and local account/group changes.

## One manual step: Full Disk Access

`eslogger` is an Endpoint Security client, and macOS only lets a person (or an MDM) grant it Full Disk Access:

System Settings > Privacy & Security > Full Disk Access > `+` > press Cmd+Shift+G > `/usr/bin/eslogger`

Then restart it: `sudo launchctl kickstart -k system/com.winlogs.eslogger`.
The installer checks the daemon's error output and prints this reminder when access is missing. CI runners come with permissions already granted, so a green CI run does not prove a fresh Mac is configured.

## Limits worth knowing

- **No Sysmon equivalent and no network connection events.** Endpoint Security has no TCP/UDP connect event. If you need network telemetry, add a tool built for it (for example osquery, or an Objective-See tool such as Network Monitor). Those are not bundled here because their licenses have not been checked for redistribution.
- **OpenBSM (`audit`) is deliberately not used.** It is deprecated; `eslogger` is Apple's replacement.
- **Unified log redaction.** Many messages show `<private>` values. Turning private data on needs a configuration profile or reduced SIP, which this script does not do.
- **Log rotation gap.** After `newsyslog` rotates the file, `eslogger` is restarted by launchd, so a few seconds of events can be missed at rotation time.
- **Shell logging covers zsh only** (the default shell) and is easy for an attacker to bypass.
- `/etc/zshrc` is edited between marker comments; `--revert` restores the original file exactly.

## Not yet verified
Intel Macs, macOS 13, and behaviour on a Mac where Full Disk Access has not been granted. CI covers macOS 14 and 15 on Apple silicon.
