#!/usr/bin/env bash
# WinLogs for macOS: forensic-grade logging for disposable malware / detection labs.
#
#   sudo ./install.sh                apply (asks for confirmation)
#   sudo ./install.sh --dry-run      show what would change
#   sudo ./install.sh --revert       undo
#
# Turns on: Apple's eslogger (Endpoint Security events as JSON, run as a LaunchDaemon with rotation),
# zsh command logging to the unified log, application firewall logging, and (opt-in) daily unified-log
# archives. macOS 13 (Ventura) or newer. Everything used ships with macOS: nothing to download.
#
# MANUAL STEP: eslogger needs Full Disk Access. macOS only allows that by hand (or MDM):
#   System Settings > Privacy & Security > Full Disk Access > "+" > press Cmd+Shift+G > /usr/bin/eslogger
# This script detects when it is missing and says so.
#
# Written for the system bash (3.2): no associative arrays, no mapfile, no ${var,,}.
set -euo pipefail

STATE_DIR=/var/db/winlogs
MANIFEST="$STATE_DIR/manifest"          # lines: "created <path>" | "backup <path>" | "fw <on|off>" | "label <launchd label>"
BACKUP_DIR="$STATE_DIR/backup"
LOG_DIR=/var/log/winlogs
LIBEXEC=/usr/local/libexec/winlogs
ES_LABEL=com.winlogs.eslogger
ES_PLIST=/Library/LaunchDaemons/$ES_LABEL.plist
ES_WRAPPER=$LIBEXEC/eslogger-run.sh
ES_LOG=$LOG_DIR/eslogger.ndjson
ES_PID=/var/run/winlogs-eslogger.pid
NEWSYSLOG=/etc/newsyslog.d/winlogs.conf
COLLECT_LABEL=com.winlogs.logcollect
COLLECT_PLIST=/Library/LaunchDaemons/$COLLECT_LABEL.plist
COLLECT_SCRIPT=$LIBEXEC/logcollect.sh
ZSHRC=/etc/zshrc
FWCTL=/usr/libexec/ApplicationFirewall/socketfilterfw
MARK_BEGIN="# >>> winlogs >>>"
MARK_END="# <<< winlogs <<<"

YES=0 DRY=0 REVERT=0 SHELLLOG=1 ARCHIVE=0 KEEP_DAYS=7 ES_MAX_MB=100 ES_KEEP=10

# Endpoint Security events worth keeping. Anything this macOS does not support is dropped at install time.
WANTED_EVENTS="exec create unlink rename mount kextload btm_launch_item_add btm_launch_item_remove \
xp_malware_detected xp_malware_remediated login_login login_logout lw_session_login lw_session_logout \
sudo su openssh_login openssh_logout screensharing_attach screensharing_detach profile_add profile_remove \
authentication gatekeeper_user_override tcc_modify remote_thread_create cs_invalidated \
od_create_user od_delete_user od_modify_password od_group_add od_group_remove od_group_set"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; echo "Options: --yes --dry-run --revert --no-shell-logging --with-log-archive --keep-days N --es-max-mb N"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y) YES=1 ;;
        --dry-run) DRY=1 ;;
        --revert) REVERT=1 ;;
        --no-shell-logging) SHELLLOG=0 ;;
        --with-log-archive) ARCHIVE=1 ;;
        --keep-days) KEEP_DAYS="${2:?--keep-days needs a number}"; shift ;;
        --es-max-mb) ES_MAX_MB="${2:?--es-max-mb needs a number}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '    (dry-run) %s\n' "$*"; else "$@"; fi; }

[ "$(uname -s)" = Darwin ] || die "This script is for macOS."
[ "$(id -u)" = 0 ] || die "Run as root (sudo)."

OS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
[ "$OS_MAJOR" -ge 13 ] || die "macOS 13 (Ventura) or newer is required (this is $(sw_vers -productVersion))."

confirm() {
    if [ "$YES" = 1 ] || [ "$DRY" = 1 ]; then return 0; fi
    warn "This turns on very verbose logging. Use it on disposable lab machines only."
    read -r -p "Type YES to continue: " a
    [ "$a" = YES ] || die "Aborted."
}

record() { if [ "$DRY" != 1 ]; then mkdir -p "$STATE_DIR"; echo "$*" >> "$MANIFEST"; fi; }
already_recorded() { [ -f "$MANIFEST" ] && grep -qxF "$*" "$MANIFEST"; }

# Back up a file the first time we touch it; remember files we create.
claim() {
    local f="$1"
    if [ "$DRY" = 1 ]; then return 0; fi
    mkdir -p "$BACKUP_DIR"
    if already_recorded "created $f"; then return 0; fi
    if [ -e "$f" ]; then
        if ! already_recorded "backup $f"; then cp -p "$f" "$BACKUP_DIR/$(echo "$f" | tr / _)"; record "backup $f"; fi
    else
        record "created $f"
    fi
}

supported_events() {
    # eslogger --list-events prints one event per line; keep only events we want and this macOS knows.
    local avail ev out=""
    avail="$(/usr/bin/eslogger --list-events 2>/dev/null || true)"
    if [ -z "$avail" ]; then echo "exec create unlink rename"; return; fi
    for ev in $WANTED_EVENTS; do
        if echo "$avail" | grep -qx "$ev"; then out="$out $ev"; fi
    done
    echo "${out# }"
}

install_eslogger() {
    [ -x /usr/bin/eslogger ] || { warn "/usr/bin/eslogger not found; skipping Endpoint Security logging."; return; }
    local events; events="$(supported_events)"
    say "Installing eslogger LaunchDaemon ($(echo "$events" | wc -w | tr -d ' ') event types)"
    if [ "$DRY" = 1 ]; then echo "    (dry-run) write $ES_WRAPPER, $ES_PLIST, $NEWSYSLOG; launchctl bootstrap"; return; fi

    mkdir -p "$LIBEXEC" "$LOG_DIR"; chmod 700 "$LOG_DIR"
    claim "$ES_WRAPPER"
    cat > "$ES_WRAPPER" <<EOF
#!/bin/sh
# Written by WinLogs. Records its PID so newsyslog can signal it after rotating the log;
# eslogger exits on SIGHUP and launchd (KeepAlive) starts it again on the fresh file.
echo \$\$ > $ES_PID
exec /usr/bin/eslogger $events
EOF
    chmod 755 "$ES_WRAPPER"

    claim "$ES_PLIST"
    cat > "$ES_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$ES_LABEL</string>
    <key>ProgramArguments</key><array><string>$ES_WRAPPER</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>5</integer>
    <key>StandardOutPath</key><string>$ES_LOG</string>
    <key>StandardErrorPath</key><string>$LOG_DIR/eslogger.err</string>
</dict>
</plist>
EOF
    chown root:wheel "$ES_PLIST"; chmod 644 "$ES_PLIST"

    mkdir -p /etc/newsyslog.d
    claim "$NEWSYSLOG"
    # logfile  mode  count  size(KB)  when  flags(Z=gzip B=binary)  pid_file  signal(1=HUP)
    printf '%s\t640\t%s\t%s\t*\tZB\t%s\t1\n' "$ES_LOG" "$ES_KEEP" "$((ES_MAX_MB * 1024))" "$ES_PID" > "$NEWSYSLOG"

    launchctl bootout "system/$ES_LABEL" >/dev/null 2>&1 || true
    launchctl bootstrap system "$ES_PLIST" || warn "launchctl bootstrap failed for $ES_LABEL."
    record "label $ES_LABEL"
}

install_shell_logging() {
    [ "$SHELLLOG" = 1 ] || return 0
    say "Logging interactive zsh commands to the unified log"
    if [ "$DRY" = 1 ]; then echo "    (dry-run) append marker block to $ZSHRC"; return; fi
    claim "$ZSHRC"
    if grep -qF "$MARK_BEGIN" "$ZSHRC" 2>/dev/null; then return; fi
    cat >> "$ZSHRC" <<EOF

$MARK_BEGIN
# WinLogs: log each interactive zsh command (user, pwd) via logger. Easy to bypass; not tamper-proof.
__winlogs_cmd() {
    local c; c="\$(fc -ln -1 2>/dev/null)"
    c="\${c#"\${c%%[![:space:]]*}"}"
    [ -n "\$c" ] && logger -p local6.info -t winlogs-cmd "user=\$USER uid=\$UID pwd=\$PWD cmd=\$c"
}
autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook precmd __winlogs_cmd
$MARK_END
EOF
}

install_firewall_logging() {
    [ -x "$FWCTL" ] || return 0
    local cur; cur="$("$FWCTL" --getloggingmode 2>/dev/null | grep -io 'on\|off' | head -1 | tr '[:upper:]' '[:lower:]' || true)"
    say "Turning on application firewall logging (was: ${cur:-unknown})"
    if [ "$DRY" = 1 ]; then echo "    (dry-run) $FWCTL --setloggingmode on"; return; fi
    if [ -n "$cur" ] && ! already_recorded "fw on" && ! already_recorded "fw off"; then record "fw $cur"; fi
    "$FWCTL" --setloggingmode on >/dev/null 2>&1 || warn "Could not change firewall logging mode."
}

install_log_archive() {
    [ "$ARCHIVE" = 1 ] || return 0
    say "Scheduling a daily unified-log archive (keeping $KEEP_DAYS days)"
    if [ "$DRY" = 1 ]; then echo "    (dry-run) write $COLLECT_SCRIPT, $COLLECT_PLIST"; return; fi
    mkdir -p "$LIBEXEC" "$LOG_DIR"
    claim "$COLLECT_SCRIPT"
    cat > "$COLLECT_SCRIPT" <<EOF
#!/bin/sh
# Written by WinLogs: snapshot the last day of the unified log, then prune old snapshots.
/usr/bin/log collect --last 1d --output "$LOG_DIR/unified-\$(date +%F).logarchive" >/dev/null 2>&1
find "$LOG_DIR" -maxdepth 1 -name 'unified-*.logarchive' -mtime +$KEEP_DAYS -exec rm -rf {} +
EOF
    chmod 755 "$COLLECT_SCRIPT"
    claim "$COLLECT_PLIST"
    cat > "$COLLECT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$COLLECT_LABEL</string>
    <key>ProgramArguments</key><array><string>$COLLECT_SCRIPT</string></array>
    <key>StartCalendarInterval</key><dict><key>Hour</key><integer>0</integer><key>Minute</key><integer>5</integer></dict>
</dict>
</plist>
EOF
    chown root:wheel "$COLLECT_PLIST"; chmod 644 "$COLLECT_PLIST"
    launchctl bootout "system/$COLLECT_LABEL" >/dev/null 2>&1 || true
    launchctl bootstrap system "$COLLECT_PLIST" || warn "launchctl bootstrap failed for $COLLECT_LABEL."
    record "label $COLLECT_LABEL"
}

check_eslogger() {
    [ "$DRY" = 1 ] && return 0
    [ -f "$ES_PLIST" ] || return 0
    sleep 4
    local err=""; [ -f "$LOG_DIR/eslogger.err" ] && err="$(tail -c 600 "$LOG_DIR/eslogger.err")"
    if echo "$err" | grep -qi -E 'not permitted|NOT_PERMITTED|full disk|privilege'; then
        warn "eslogger is blocked: grant Full Disk Access to /usr/bin/eslogger, then restart it with:"
        warn "  sudo launchctl kickstart -k system/$ES_LABEL"
        warn "  (System Settings > Privacy & Security > Full Disk Access > + > Cmd+Shift+G > /usr/bin/eslogger)"
    elif launchctl print "system/$ES_LABEL" >/dev/null 2>&1; then
        say "eslogger is running; output: $ES_LOG"
    else
        warn "eslogger is not loaded; check: sudo launchctl print system/$ES_LABEL"
    fi
}

do_revert() {
    [ -f "$MANIFEST" ] || die "No manifest at $MANIFEST; nothing to revert."
    confirm
    say "Reverting"
    while read -r kind path; do
        case "$kind" in
            label) run launchctl bootout "system/$path" >/dev/null 2>&1 || true ;;
        esac
    done < "$MANIFEST"
    while read -r kind path; do
        case "$kind" in
            created)
                if [ "$path" = "$ZSHRC" ]; then continue; fi
                run rm -f "$path" ;;
            backup)
                if [ "$path" = "$ZSHRC" ]; then continue; fi
                run cp -p "$BACKUP_DIR/$(echo "$path" | tr / _)" "$path" ;;
            fw)
                if [ -x "$FWCTL" ]; then run "$FWCTL" --setloggingmode "$path" >/dev/null 2>&1 || true; fi ;;
        esac
    done < "$MANIFEST"
    # /etc/zshrc: strip our marker block (keeps anything else that changed since); delete it if we created it.
    if [ -f "$ZSHRC" ] && grep -qF "$MARK_BEGIN" "$ZSHRC"; then
        if [ "$DRY" != 1 ]; then
            awk -v b="$MARK_BEGIN" -v e="$MARK_END" '$0==b{skip=1} !skip{print} $0==e{skip=0}' "$ZSHRC" > "$ZSHRC.winlogs.tmp"
            if already_recorded "backup $ZSHRC"; then
                # Restore the exact original (also drops the blank line we added before the block).
                cp -p "$BACKUP_DIR/$(echo "$ZSHRC" | tr / _)" "$ZSHRC"; rm -f "$ZSHRC.winlogs.tmp"
            else
                cat "$ZSHRC.winlogs.tmp" > "$ZSHRC"; rm -f "$ZSHRC.winlogs.tmp"
            fi
        fi
    fi
    if already_recorded "created $ZSHRC" && [ "$DRY" != 1 ] && [ ! -s "$ZSHRC" ]; then rm -f "$ZSHRC"; fi
    run rmdir "$LIBEXEC" >/dev/null 2>&1 || true
    run rm -f "$ES_PID"
    if [ "$DRY" != 1 ]; then rm -rf "$STATE_DIR"; fi
    say "Reverted. Collected logs were left in $LOG_DIR (delete them when you are done)."
}

if [ "$REVERT" = 1 ]; then do_revert; exit 0; fi

say "WinLogs on macOS $(sw_vers -productVersion) ($(uname -m))"
confirm
install_eslogger
install_shell_logging
install_firewall_logging
install_log_archive
check_eslogger

echo
say "Done. Look at: tail -f $ES_LOG ; log show --last 5m --predicate 'eventMessage contains \"winlogs-cmd\"'"
say "Undo: sudo $0 --revert"
