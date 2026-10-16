#!/usr/bin/env bash
# Download the packages WinLogs needs so an air-gapped Linux lab can install without internet.
#
#   ./prepare-offline.sh [OUT_DIR]        (run as root, on a machine with internet)
#
# Run it on a machine that matches the lab image (same distro and release, ideally a fresh copy of the
# lab VM template) so every dependency the lab is missing gets downloaded. Then copy OUT_DIR to the lab:
#   sudo ./install.sh --offline-dir OUT_DIR
set -euo pipefail

OUT="${1:-./winlogs-offline-linux}"
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
rm -f "$OUT"/*.deb "$OUT"/*.rpm "$OUT"/*.pkg.tar.* "$OUT/SHA256SUMS"

if command -v apt-get >/dev/null; then
    apt-get update -y
    # --reinstall so the package is fetched even if it is already installed here.
    apt-get install -y --reinstall --download-only -o "Dir::Cache::archives=$OUT" auditd
    rm -f "$OUT/lock"; rm -rf "$OUT/partial"
elif command -v dnf >/dev/null; then
    # dnf4 takes --downloaddir on install; dnf5 (Fedora 41+) uses the download command instead.
    dnf install -y --downloadonly --downloaddir="$OUT" audit 2>/dev/null \
        || dnf download --resolve --destdir="$OUT" audit
elif command -v yum >/dev/null; then
    yum install -y --downloadonly --downloaddir="$OUT" audit
elif command -v zypper >/dev/null; then
    zypper --non-interactive --pkg-cache-dir "$OUT" install --download-only audit
    find "$OUT" -name '*.rpm' -exec mv -t "$OUT" {} + 2>/dev/null || true
elif command -v pacman >/dev/null; then
    pacman -Sw --noconfirm --cachedir "$OUT" audit
else
    echo "No supported package manager." >&2; exit 1
fi

cd "$OUT"
find . -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.pkg.tar.*' \) -printf '%P\n' | sort > .pkgs
[ -s .pkgs ] || { echo "Nothing was downloaded." >&2; exit 1; }
xargs -d '\n' sha256sum < .pkgs > SHA256SUMS
rm -f .pkgs
echo "Offline bundle ready: $OUT ($(wc -l < SHA256SUMS) packages)"
echo "Copy it to the lab, then: sudo ./install.sh --offline-dir $OUT"
