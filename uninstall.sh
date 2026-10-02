#!/usr/bin/env bash
# GNULTE uninstaller — removes the Go binaries and docs.
#
# Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.
set -euo pipefail

BINDIR="${BINDIR:-/usr/local/bin}"
DOCDIR="/usr/local/share/doc/gnulte-go"

if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "[*] re-running as root via sudo..."
        exec sudo -H "${BASH_SOURCE[0]}" "$@"
    else
        echo "uninstaller must run as root (no sudo found)." >&2
        exit 1
    fi
fi

PURGE="${PURGE:-0}"
for arg in "$@"; do
    [[ "$arg" == "--purge" ]] && PURGE=1
done

for f in gnulte gnulte-scan gnulte-wifi gnulte-lan gnulte-devices gnulte-doctor gnulte-trace gnulte-top gnulte-traffic; do
    if [[ -f "$BINDIR/$f" ]]; then
        rm -f "$BINDIR/$f"
        echo "[+] Removed $BINDIR/$f"
    fi
done

if [[ -d "$DOCDIR" ]]; then
    rm -rf "$DOCDIR"
    echo "[+] Removed $DOCDIR"
fi

if [[ "$PURGE" == "1" && -n "${SUDO_USER:-}" ]]; then
    # Safety acceptance lives in the calling user's config home.
    for home in "/home/$SUDO_USER" "/root"; do
        [[ -f "$home/.config/gnulte-go/acceptance.json" ]] && rm -f "$home/.config/gnulte-go/acceptance.json"
    done
    echo "[+] Purged safety acceptance records."
fi

echo "GNULTE uninstalled."