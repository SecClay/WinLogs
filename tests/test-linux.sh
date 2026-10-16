#!/usr/bin/env bash
# End-to-end test for the Linux script. Needs root on a DISPOSABLE Debian/Ubuntu-style machine
# with internet (e.g. a CI runner). Exercises dry-run, offline prep, offline install, events, re-run, revert.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
# Without systemd (e.g. a container) auditd and journald can't run, so skip the live-kernel checks.
LIVE=1; [ -d /run/systemd/system ] || LIVE=0
skip() { echo "  SKIP  $1 (no systemd)"; }
check() { if "${@:2}"; then echo "  PASS  $1"; else echo "  FAIL  $1"; echo "::error::FAIL $1"; fail=$((fail+1)); fi; }
# Run a script; on failure surface its output as a CI annotation.
runq() {
    local out
    if ! out="$("$@" 2>&1)"; then
        echo "$out" | tail -25
        echo "::error::$* failed: $(echo "$out" | tail -12 | tr '\n' '|')"
        return 1
    fi
    echo "$out" | tail -5
}
rules_loaded() { [ "$(auditctl -l 2>/dev/null | grep -c .)" -gt 50 ]; }

echo "== dry-run changes nothing"
runq ./linux/install.sh --dry-run >/dev/null
check "dry-run left no rules file"  test ! -e /etc/audit/rules.d/90-winlogs.rules
check "dry-run left no state dir"   test ! -d /var/lib/winlogs

echo "== prepare-offline"
runq ./linux/prepare-offline.sh /tmp/winlogs-offline
check "SHA256SUMS written" test -s /tmp/winlogs-offline/SHA256SUMS

echo "== install (offline)"
runq ./linux/install.sh --yes --offline-dir /tmp/winlogs-offline
check "audit rules file installed"  test -s /etc/audit/rules.d/90-winlogs.rules
if [ "$LIVE" = 1 ]; then check "audit rules loaded in kernel" rules_loaded; else skip "audit rules loaded in kernel"; fi
check "auditd.conf retention raised" grep -q '^max_log_file = 200' /etc/audit/auditd.conf
check "journald drop-in present"    test -s /etc/systemd/journald.conf.d/90-winlogs.conf
if [ "$LIVE" = 1 ]; then check "journald is persistent" test -d /var/log/journal; else skip "journald is persistent"; fi
check "bash logging hook present"   test -s /etc/profile.d/winlogs-cmdlog.sh

if [ "$LIVE" = 1 ]; then
echo "== events actually appear"
marker="winlogs-marker-$RANDOM$RANDOM"
# Launch via systemd: on some kernels (seen on Ubuntu 22.04) processes that were already running when
# auditing was first switched on are not audited, but freshly started services are.
systemd-run --quiet --wait --collect /bin/echo "$marker" >/dev/null 2>&1 || /bin/echo "$marker" >/dev/null
sleep 2
# auditd flushes to disk asynchronously, so retry for a while.
found_marker() { for _ in $(seq 10); do ausearch --input-logs -i -k process_creation -ts recent 2>/dev/null | grep -q "$marker" && return 0; sleep 2; done; return 1; }
check "execve audited (process_creation)" found_marker
else skip "events actually appear"; fi

echo "== re-run is idempotent"
runq ./linux/install.sh --yes
check "second run kept one backup of auditd.conf" test "$(grep -c '^backup /etc/audit/auditd.conf' /var/lib/winlogs/manifest)" -le 1

echo "== revert"
runq ./linux/install.sh --yes --revert
check "rules file removed"     test ! -e /etc/audit/rules.d/90-winlogs.rules
check "journald drop-in gone"  test ! -e /etc/systemd/journald.conf.d/90-winlogs.conf
check "profile hook gone"      test ! -e /etc/profile.d/winlogs-cmdlog.sh
check "state dir removed"      test ! -d /var/lib/winlogs

if [ "$fail" = 0 ]; then echo "All checks passed."; else echo "$fail check(s) failed."; exit 1; fi
