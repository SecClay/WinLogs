# Linux: what gets logged

See also: [Windows](logged-windows.md) · [macOS](logged-macos.md) · [overview](what-gets-logged.md)

`linux/install.sh` (run with `sudo`) supports Debian/Ubuntu/Kali (`apt`), RHEL/Fedora/Rocky/Alma (`dnf`/`yum`), openSUSE (`zypper`) and Arch (`pacman`). CI exercises Ubuntu 22.04 and 24.04 on real VMs and Fedora in a container.

## What it turns on

| Piece | How | Where to look |
|---|---|---|
| Audit rules | `auditd` plus the [Neo23x0 ruleset](https://github.com/Neo23x0/auditd) (Apache-2.0), installed as `/etc/audit/rules.d/90-winlogs.rules`; `UID_MIN` is read from `/etc/login.defs` | `ausearch -k <key>`, `/var/log/audit/audit.log` |
| Audit retention | `max_log_file = 200` (MB), `num_logs = 10`, rotate, `flush = SYNC` so events hit disk immediately | `/etc/audit/auditd.conf` |
| journald | Persistent storage (`/var/log/journal`), `SystemMaxUse` 2G by default (`--journal-size`), rate limiting off so bursts are not dropped | `journalctl`, `/etc/systemd/journald.conf.d/90-winlogs.conf` |
| Shell commands | Interactive bash commands logged to syslog, facility `local6`, tag `winlogs-cmd` (`--no-shell-logging` skips it) | `journalctl -t winlogs-cmd` or `/var/log/syslog` |
| Sysmon for Linux (opt-in) | `--with-sysmon` installs Microsoft's package and a small config (process create/terminate, network connect, file create/delete); experimental, not bundled | syslog (`/var/log/syslog` or the journal) |
| Auditing switched on | The last step runs `auditctl -e 1` (restarting journald on Ubuntu 22.04 turns kernel auditing back off) | `auditctl -s` shows `enabled 1` |

## What the audit rules cover

Rule keys in the Neo23x0 set, grouped. Use them with `ausearch -k <key>`.

- **Process execution:** `process_creation` (every `execve`/`execveat`; the highest-volume rule), `32bit_abi`, `process_vm`, `tracing`, `userfaultfd`
- **Persistence and startup:** `cron`, `systemd`, `init`, `udev`, `shell_profiles`, `systemwide_preloads`, `libpath`, `boot_writes`, `sysconfig`, `svc_defaults`
- **Accounts and authentication:** `etcpasswd`, `etcgroup`, `rootkey`, `sshd`, `pam`, `login`, `session`
- **Files and permissions:** `file_creation`, `file_modification`, `file_access`, `perm_mod`, `delete`, `specialfiles`, `bin_writes`, `usr_writes`, `unauthedfileaccess`, `T1070_006_timestomp`
- **Kernel and tampering:** `modules`, `modprobe`, `KEXEC`, `bpf`, `socket_bpf_filter_attached`, `io_uring`, `sysctl`, `mac_policy`, `namespaces`, `auditlog`, `auditconfig`
- **Network:** `network_socket_created`, `raw_network_socket_created`, `network_modifications`, `firewall`, `network`
- **Containers:** `docker`, `containers`
- **Package and software changes:** `software_mgmt`

The ruleset is broad on purpose. If volume is a problem, comment out `process_creation` or the `file_*` rules in `/etc/audit/rules.d/90-winlogs.rules` and run `sudo augenrules --load`.

## Good to know

- **Kernel and container limits:** auditing needs a real kernel audit subsystem. In a container the install warns instead of failing, and no audit events are produced.
- **Shell logging** covers interactive bash only and is easy for an attacker to bypass; treat it as a convenience, not evidence.
- **Reboots:** the rules persist through `rules.d`, and journald and auditd start at boot.
- **Offline:** `linux/prepare-offline.sh` downloads the packages with a `SHA256SUMS` file; `install.sh --offline-dir DIR` verifies it first. Run it on a machine that matches the lab image.
- **Revert:** `sudo ./linux/install.sh --revert` restores edited files from backups and removes the ones it created. Installed packages are left in place.

## Not yet verified
Rocky/Alma (RHEL-family live auditing), Debian, Kali, openSUSE, Arch, and `--with-sysmon`.
