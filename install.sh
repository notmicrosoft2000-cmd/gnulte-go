#!/usr/bin/env bash
# GNULTE installer — installs the Go binaries system-wide.
#
# Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINDIR="${BINDIR:-/usr/local/bin}"
DOCDIR="/usr/local/share/doc/gnulte-go"

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
go build -trimpath -ldflags "-s -w" -o gnulte-lan ./cmd/gnulte-lan || exit 1
go build -trimpath -ldflags "-s -w" -o gnulte-devices ./cmd/gnulte-devices || exit 1
go build -trimpath -ldflags "-s -w" -o gnulte-doctor ./cmd/gnulte-doctor || exit 1
go build -trimpath -ldflags "-s -w" -o gnulte-trace ./cmd/gnulte-trace || exit 1
go build -trimpath -ldflags "-s -w" -o gnulte-top ./cmd/gnulte-top || exit 1

# --- verify before installing ---

for f in gnulte gnulte-scan gnulte-wifi gnulte-lan gnulte-devices gnulte-doctor gnulte-trace gnulte-top; do
    if ! file "$f" | grep -q "ELF"; then
        echo "built $f does not look like an ELF binary; aborting." >&2
        exit 1
    fi
done
# The version is read from the freshly built tool — never hard-coded — so the
# installer cannot silently drift behind the source tree.
VERSION="$(./gnulte --version | grep -oE 'v[0-9]+\.[0-9]+' | head -1 || true)"
if [[ -z "$VERSION" ]]; then
    echo "gnulte does not report a version number; aborting." >&2
    exit 1
fi
for b in gnulte gnulte-scan gnulte-wifi gnulte-lan gnulte-devices gnulte-doctor gnulte-trace gnulte-top; do
    if ! "./$b" --version 2>/dev/null | grep -q "$VERSION"; then
        echo "$b does not report $VERSION; aborting." >&2
        exit 1
    fi
done

echo "[*] installing to ${BINDIR}..."
mkdir -p "$BINDIR"
install -m755 "$SRC_DIR/gnulte" "$BINDIR/gnulte"
install -m755 "$SRC_DIR/gnulte-scan" "$BINDIR/gnulte-scan"
install -m755 "$SRC_DIR/gnulte-wifi" "$BINDIR/gnulte-wifi"
install -m755 "$SRC_DIR/gnulte-lan" "$BINDIR/gnulte-lan"
install -m755 "$SRC_DIR/gnulte-devices" "$BINDIR/gnulte-devices"
install -m755 "$SRC_DIR/gnulte-doctor" "$BINDIR/gnulte-doctor"
install -m755 "$SRC_DIR/gnulte-trace" "$BINDIR/gnulte-trace"
install -m755 "$SRC_DIR/gnulte-top" "$BINDIR/gnulte-top"

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
echo "GNULTE ${VERSION} installed successfully."
echo "  Binaries: ${BINDIR}/gnulte, ${BINDIR}/gnulte-scan, ${BINDIR}/gnulte-wifi, ${BINDIR}/gnulte-lan, ${BINDIR}/gnulte-devices, ${BINDIR}/gnulte-doctor, ${BINDIR}/gnulte-trace, ${BINDIR}/gnulte-top"
echo "  Docs:     ${DOCDIR}/"
echo ""
echo "Run gnulte (it elevates via sudo as needed)."
echo "On first launch it shows safety documents and requires acknowledgment."