#!/usr/bin/env bash
# WinLogs for Linux: quick forensic-grade logging for disposable malware / detection labs.
#
#   sudo ./install.sh                  apply (asks for confirmation)
#   sudo ./install.sh --dry-run        show what would change
#   sudo ./install.sh --revert         undo
#   sudo ./install.sh --offline-dir D  install packages from a folder made by prepare-offline.sh
#
# Turns on: auditd + the Neo23x0 ruleset, persistent journald with no rate limiting, larger audit
# log retention, and bash command logging to syslog. Sysmon for Linux is opt-in (--with-sysmon).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/var/lib/winlogs
BACKUP_DIR="$STATE_DIR/backup"
MANIFEST="$STATE_DIR/manifest"          # lines: "created <path>" | "backup <path>" | "pkg <name>"
RULES_DST=/etc/audit/rules.d/90-winlogs.rules
JOURNAL_DROPIN=/etc/systemd/journald.conf.d/90-winlogs.conf
PROFILE_DST=/etc/profile.d/winlogs-cmdlog.sh
AUDITD_CONF=/etc/audit/auditd.conf

YES=0 DRY=0 REVERT=0 SYSMON=0 SHELLLOG=1 OFFLINE="" JOURNAL_MAX=2G

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; echo "Options: --yes --dry-run --revert --offline-dir DIR --with-sysmon --no-shell-logging --journal-size SIZE"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y) YES=1 ;;
        --dry-run) DRY=1 ;;
        --revert) REVERT=1 ;;
        --with-sysmon) SYSMON=1 ;;
        --no-shell-logging) SHELLLOG=0 ;;
        --offline-dir) OFFLINE="${2:?--offline-dir needs a folder}"; shift ;;
        --journal-size) JOURNAL_MAX="${2:?--journal-size needs a value like 2G}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '    (dry-run) %s\n' "$*"; else "$@"; fi; }

[ "$(id -u)" = 0 ] || die "Run as root (sudo)."
[ "$(uname -s)" = Linux ] || die "This script is for Linux."

confirm() {
    [ "$YES" = 1 ] || [ "$DRY" = 1 ] && return 0
    warn "This turns on very verbose logging. Use it on disposable lab machines only."
    read -r -p "Type YES to continue: " a
    [ "$a" = YES ] || die "Aborted."
}

detect_pm() {
    if   command -v apt-get >/dev/null; then PM=apt;    AUDIT_PKG=auditd
    elif command -v dnf     >/dev/null; then PM=dnf;    AUDIT_PKG=audit
    elif command -v yum     >/dev/null; then PM=yum;    AUDIT_PKG=audit
    elif command -v zypper  >/dev/null; then PM=zypper; AUDIT_PKG=audit
    elif command -v pacman  >/dev/null; then PM=pacman; AUDIT_PKG=audit
    else die "No supported package manager (apt, dnf, yum, zypper, pacman)."; fi
}

record() { [ "$DRY" = 1 ] || { mkdir -p "$STATE_DIR"; echo "$*" >> "$MANIFEST"; }; }
already_recorded() { [ -f "$MANIFEST" ] && grep -qxF "$*" "$MANIFEST"; }

# Back up a file the first time we touch it (revert restores it); record files we create.
claim() {
    local f="$1"
    [ "$DRY" = 1 ] && return 0
    mkdir -p "$BACKUP_DIR"
    # A file we created on an earlier run is ours, not something to back up and restore.
    if already_recorded "created $f"; then return 0; fi
    if [ -e "$f" ]; then
        already_recorded "backup $f" || { cp -a "$f" "$BACKUP_DIR/$(echo "$f" | tr / _)"; record "backup $f"; }
    else
        already_recorded "created $f" || record "created $f"
    fi
}

pkg_installed() {
    case "$PM" in
        apt) dpkg -s "$1" >/dev/null 2>&1 ;;
        dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
        pacman) pacman -Qi "$1" >/dev/null 2>&1 ;;
    esac
}

install_packages() {
    if pkg_installed "$AUDIT_PKG"; then say "$AUDIT_PKG already installed"; return; fi
    say "Installing $AUDIT_PKG"
    if [ -n "$OFFLINE" ]; then
        [ -d "$OFFLINE" ] || die "Offline folder not found: $OFFLINE"
        ( cd "$OFFLINE" && { [ ! -f SHA256SUMS ] || sha256sum -c --quiet SHA256SUMS; } ) \
            || die "Offline bundle failed its SHA256SUMS check."
        case "$PM" in
            apt) run dpkg -i "$OFFLINE"/*.deb ;;
            dnf|yum) run "$PM" install -y --disablerepo='*' "$OFFLINE"/*.rpm ;;
            zypper) run zypper --non-interactive install --allow-unsigned-rpm "$OFFLINE"/*.rpm ;;
            pacman) run pacman -U --noconfirm "$OFFLINE"/*.pkg.tar.* ;;
        esac
    else
        case "$PM" in
            apt) run env DEBIAN_FRONTEND=noninteractive apt-get install -y "$AUDIT_PKG" ;;
            dnf|yum) run "$PM" install -y "$AUDIT_PKG" ;;
            zypper) run zypper --non-interactive install "$AUDIT_PKG" ;;
            pacman) run pacman -S --noconfirm "$AUDIT_PKG" ;;
        esac
    fi
    record "pkg $AUDIT_PKG"
}

install_audit_rules() {
    say "Installing audit rules"
    local uid_min
    uid_min="$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || true)"
    uid_min="${uid_min:-1000}"
    [ -d "$(dirname "$RULES_DST")" ] || run mkdir -p "$(dirname "$RULES_DST")"
    claim "$RULES_DST"
    if [ "$DRY" = 1 ]; then echo "    (dry-run) write $RULES_DST (UID_MIN=$uid_min)"; return; fi
    sed "s/auid>=1000/auid>=$uid_min/g" "$HERE/audit/neo23x0-audit.rules" > "$RULES_DST"
    # Some kernels boot with audit disabled; make sure it is switched on after the rules load.
    printf '\n# WinLogs: make sure auditing is enabled\n-e 1\n' >> "$RULES_DST"
    chmod 640 "$RULES_DST"

    # Keep more audit history than the distro default.
    if [ -f "$AUDITD_CONF" ]; then
        claim "$AUDITD_CONF"
        sed -i -E 's/^max_log_file *=.*/max_log_file = 200/; s/^num_logs *=.*/num_logs = 10/; s/^max_log_file_action *=.*/max_log_file_action = ROTATE/; s/^flush *=.*/flush = SYNC/' "$AUDITD_CONF"
    fi

    if command -v systemctl >/dev/null && systemctl list-unit-files auditd.service >/dev/null 2>&1; then
        systemctl enable auditd >/dev/null 2>&1 || true
    fi
    # RHEL-family refuses "systemctl restart auditd"; "service" works everywhere.
    service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 \
        || warn "Could not restart auditd (container or no kernel audit support?)."
    if command -v augenrules >/dev/null; then augenrules --load >/dev/null 2>&1 || warn "augenrules --load failed."
    else auditctl -R "$RULES_DST" >/dev/null 2>&1 || warn "auditctl -R failed."; fi
    # Belt and braces: on some kernels (seen on Ubuntu 22.04) auditing is still off after the rules load.
    auditctl -e 1 >/dev/null 2>&1 || warn "Could not enable auditing (container or no kernel audit support?)."
}

configure_journald() {
    say "Making journald persistent (max $JOURNAL_MAX, no rate limiting)"
    [ "$DRY" = 1 ] && { echo "    (dry-run) write $JOURNAL_DROPIN"; return; }
    command -v journalctl >/dev/null || { warn "No systemd-journald here; skipping."; return; }
    mkdir -p /etc/systemd/journald.conf.d /var/log/journal
    claim "$JOURNAL_DROPIN"
    cat > "$JOURNAL_DROPIN" <<EOF
[Journal]
Storage=persistent
SystemMaxUse=$JOURNAL_MAX
RateLimitIntervalSec=0
RateLimitBurst=0
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || warn "Could not restart journald."
}

configure_shell_logging() {
    [ "$SHELLLOG" = 1 ] || return 0
    say "Logging interactive bash commands to syslog (local6)"
    [ "$DRY" = 1 ] && { echo "    (dry-run) write $PROFILE_DST"; return; }
    claim "$PROFILE_DST"
    cat > "$PROFILE_DST" <<'EOF'
# WinLogs: log each interactive bash command to syslog (user is easy to bypass; not tamper-proof).
if [ -n "${BASH_VERSION:-}" ] && [ -n "${PS1:-}" ]; then
    __winlogs_cmd() {
        local c; c="$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9]* *//')"
        [ -n "$c" ] && logger -p local6.info -t winlogs-cmd "user=$(id -un) uid=$(id -u) pwd=$PWD cmd=$c"
    }
    case ":${PROMPT_COMMAND:-}:" in *:__winlogs_cmd:*) ;; *) PROMPT_COMMAND="__winlogs_cmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;; esac
fi
EOF
}

install_sysmon() {
    [ "$SYSMON" = 1 ] || return 0
    [ -z "$OFFLINE" ] || die "--with-sysmon needs internet (Microsoft package repo); offline Sysmon is not supported yet."
    say "Installing Sysmon for Linux from Microsoft's package repo (experimental)"
    # shellcheck source=/dev/null
    . /etc/os-release
    local tmp; tmp="$(mktemp -d)"
    case "$PM" in
        apt)
            run curl -fsSL -o "$tmp/ms.deb" "https://packages.microsoft.com/config/$ID/$VERSION_ID/packages-microsoft-prod.deb"
            run dpkg -i "$tmp/ms.deb"; run apt-get update -y
            run env DEBIAN_FRONTEND=noninteractive apt-get install -y sysmonforlinux ;;
        dnf|yum)
            run rpm -Uvh "https://packages.microsoft.com/config/$ID/${VERSION_ID%%.*}/packages-microsoft-prod.rpm"
            run "$PM" install -y sysmonforlinux ;;
        *) die "Sysmon for Linux packages are only wired up for apt and dnf/yum here." ;;
    esac
    record "pkg sysmonforlinux"
    run sysmon -accepteula -i "$HERE/sysmon/sysmonconfig-linux.xml"
    rm -rf "$tmp"
}

do_revert() {
    [ -f "$MANIFEST" ] || die "No manifest at $MANIFEST; nothing to revert."
    confirm
    say "Reverting"
    while read -r kind path; do
        case "$kind" in
            created) run rm -f "$path" ;;
            backup)  run cp -a "$BACKUP_DIR/$(echo "$path" | tr / _)" "$path" ;;
        esac
    done < "$MANIFEST"
    if command -v augenrules >/dev/null; then run augenrules --load >/dev/null 2>&1 || true; fi
    run service auditd restart >/dev/null 2>&1 || true
    run systemctl restart systemd-journald >/dev/null 2>&1 || true
    if grep -qxF "pkg sysmonforlinux" "$MANIFEST"; then run sysmon -u force >/dev/null 2>&1 || true; fi
    [ "$DRY" = 1 ] || rm -rf "$STATE_DIR"
    say "Reverted. Packages we installed were left in place (remove them with your package manager if you want)."
}

if [ "$REVERT" = 1 ]; then do_revert; exit 0; fi

detect_pm
say "WinLogs on $(grep -m1 ^PRETTY_NAME= /etc/os-release | cut -d= -f2- | tr -d '"') using $PM"
confirm
install_packages
install_audit_rules
configure_journald
configure_shell_logging
install_sysmon

# Last step on purpose: on Ubuntu 22.04 restarting journald switches kernel auditing back off.
if [ "$DRY" != 1 ] && command -v auditctl >/dev/null; then
    auditctl -e 1 >/dev/null 2>&1 || warn "Could not enable auditing (container or no kernel audit support?)."
fi

echo
say "Done. Check: auditctl -l | wc -l ; ausearch --input-logs -k process_creation -ts recent ; journalctl --disk-usage"
say "Undo: sudo $0 --revert"
