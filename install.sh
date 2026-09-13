#!/usr/bin/env bash
# GNULTE installer — installs the Go binaries system-wide.
#
# Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINDIR="${BINDIR:-/usr/local/bin}"
DOCDIR="/usr/local/share/doc/gnulte-go"
VERSION="10.0"

# --- root handling ---

if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "[*] re-running as root via sudo..."
        exec sudo -H "${BASH_SOURCE[0]}" "$@"
    else
        echo "installer must run as root (no sudo found)." >&2
        exit 1
    fi
fi

# --- build ---

echo "[*] building binaries (static)..."
export CGO_ENABLED=0
if ! command -v go >/dev/null 2>&1; then
    # A user-local toolchain is common; locate it before giving up.
    if [[ -n "${SUDO_USER:-}" ]]; then
        for p in "/home/$SUDO_USER/.local/bin" "/home/$SUDO_USER/.local/go-root/bin" "/home/$SUDO_USER/go/bin"; do
            if [[ -x "$p/go" ]]; then
                export PATH="$p:$PATH"
                break
            fi
        done
    fi
fi
if ! command -v go >/dev/null 2>&1; then
    echo "Go toolchain not found in PATH." >&2
    exit 1
fi
cd "$SRC_DIR"
go build -trimpath -ldflags "-s -w" -o gnulte ./cmd/gnulte || exit 1
go build -trimpath -ldflags "-s -w" -o gnulte-scan ./cmd/gnulte-scan || exit 1
go build -trimpath -ldflags "-s -w" -o gnulte-wifi ./cmd/gnulte-wifi || exit 1

# --- verify before installing ---

for f in gnulte gnulte-scan gnulte-wifi; do
    if ! file "$f" | grep -q "ELF"; then
        echo "built $f does not look like an ELF binary; aborting." >&2
        exit 1
    fi
done
if ! ./gnulte --version | grep -q "v${VERSION}"; then
    echo "gnulte does not report v${VERSION}; aborting." >&2
    exit 1
fi

echo "[*] installing to ${BINDIR}..."
mkdir -p "$BINDIR"
install -m755 "$SRC_DIR/gnulte" "$BINDIR/gnulte"
install -m755 "$SRC_DIR/gnulte-scan" "$BINDIR/gnulte-scan"
install -m755 "$SRC_DIR/gnulte-wifi" "$BINDIR/gnulte-wifi"

# --- install legal / safety documentation ---

echo "[*] installing documentation..."
mkdir -p "$DOCDIR"
for doc in LICENSE; do
    if [[ -f "$SRC_DIR/$doc" ]]; then
        install -m644 "$SRC_DIR/$doc" "$DOCDIR/$doc"
    fi
done
for doc in GNULTE SAFETY DISCLAIMER AUTHORIZED-USE NETWORK-TESTING; do
    if [[ -f "$SRC_DIR/docs/$doc.md" ]]; then
        install -m644 "$SRC_DIR/docs/$doc.md" "$DOCDIR/$doc.md"
    fi
done

echo ""
echo "GNULTE v${VERSION} installed successfully."
echo "  Binaries: ${BINDIR}/gnulte, ${BINDIR}/gnulte-scan, ${BINDIR}/gnulte-wifi"
echo "  Docs:     ${DOCDIR}/"
echo ""
echo "Run gnulte (it elevates via sudo as needed)."
echo "On first launch it shows safety documents and requires acknowledgment."