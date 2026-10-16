#!/usr/bin/env bash
# End-to-end test for the macOS script. Needs root on a DISPOSABLE macOS 13+ machine (e.g. a CI runner).
# Whether eslogger actually captures events depends on Full Disk Access, which a script cannot grant,
# so that one check is reported but never fails the run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
check() { if "${@:2}"; then echo "  PASS  $1"; else echo "  FAIL  $1"; echo "::error::FAIL $1"; fail=$((fail+1)); fi; }
runq() {
    local out
    if ! out="$("$@" 2>&1)"; then
        echo "$out" | tail -25
        echo "::error::$* failed: $(echo "$out" | tail -12 | tr '\n' '|')"
        return 1
    fi
    echo "$out" | tail -6
}
sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fwmode() { /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>&1 | grep -io 'on\|off' | head -1 | tr '[:upper:]' '[:lower:]'; }

PLIST=/Library/LaunchDaemons/com.winlogs.eslogger.plist
ZSHRC_BEFORE="$(sum /etc/zshrc)"
FW_BEFORE="$(fwmode)"

echo "== dry-run changes nothing"
runq ./macos/install.sh --dry-run >/dev/null
check "dry-run left no LaunchDaemon" test ! -e "$PLIST"
check "dry-run left no state dir"    test ! -d /var/db/winlogs
check "dry-run left /etc/zshrc alone" test "$(sum /etc/zshrc)" = "$ZSHRC_BEFORE"

echo "== install"
runq ./macos/install.sh --yes --with-log-archive
check "eslogger LaunchDaemon plist written" test -s "$PLIST"
check "eslogger wrapper written"            grep -q 'exec /usr/bin/eslogger exec' /usr/local/libexec/winlogs/eslogger-run.sh
check "eslogger job loaded in launchd"      launchctl print system/com.winlogs.eslogger
check "newsyslog rotation config written"   test -s /etc/newsyslog.d/winlogs.conf
check "log-archive job written"             test -s /Library/LaunchDaemons/com.winlogs.logcollect.plist
check "/etc/zshrc still parses"             zsh -n /etc/zshrc
check "zsh command hook defined"            bash -c "zsh -ic 'whence -w __winlogs_cmd' 2>/dev/null | grep -q function"
check "firewall logging is on"              test "$(fwmode)" = on

echo "== events (informational)"
marker="winlogs-marker-$RANDOM$RANDOM"
/usr/bin/true "$marker"
sleep 4
n=$(grep -c "$marker" /var/log/winlogs/eslogger.ndjson 2>/dev/null || true)
echo "::notice::eslogger captured marker lines: ${n:-0} | size: $(stat -f %z /var/log/winlogs/eslogger.ndjson 2>&1) | err: $(tail -c 300 /var/log/winlogs/eslogger.err 2>&1 | tr '\n' '|')"

echo "== re-run is idempotent"
runq ./macos/install.sh --yes
check "exactly one zshrc block after re-run" test "$(grep -c '>>> winlogs >>>' /etc/zshrc)" = 1

echo "== revert"
runq ./macos/install.sh --yes --revert
check "LaunchDaemon plist removed"   test ! -e "$PLIST"
check "log-archive plist removed"    test ! -e /Library/LaunchDaemons/com.winlogs.logcollect.plist
check "newsyslog config removed"     test ! -e /etc/newsyslog.d/winlogs.conf
check "job unloaded from launchd"    bash -c '! launchctl print system/com.winlogs.eslogger >/dev/null 2>&1'
check "/etc/zshrc restored exactly"  test "$(sum /etc/zshrc)" = "$ZSHRC_BEFORE"
check "firewall logging mode restored" test "$(fwmode)" = "$FW_BEFORE"
check "state dir removed"            test ! -d /var/db/winlogs

if [ "$fail" = 0 ]; then echo "All checks passed."; else echo "$fail check(s) failed."; exit 1; fi
