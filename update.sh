#!/usr/bin/env bash
set -euo pipefail

# GNULTE updater: fetch a fresh source tree into a temporary directory and
# hand it to install.sh. The caller's working tree is never touched.
TARBALL_URL="https://github.com/notmicrosoft2000-cmd/gnulte-go/archive/refs/heads/main.tar.gz"

if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go is required to build GNULTE. Install Go and try again." >&2
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  DOWNLOADER=curl
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER=wget
else
  echo "Error: curl or wget is required to download the GNULTE source." >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "GNULTE: downloading the latest source..."
cd "$WORKDIR"
if [ "$DOWNLOADER" = curl ]; then
  curl -fsSL "$TARBALL_URL" -o source.tar.gz
else
  wget -q -O source.tar.gz "$TARBALL_URL"
fi

echo "GNULTE: extracting source..."
tar -xzf source.tar.gz
if [ ! -d gnulte-go-main ]; then
  echo "Error: downloaded archive did not contain gnulte-go-main." >&2
  exit 1
fi
cd gnulte-go-main
chmod +x ./install.sh 2>/dev/null || true

echo "GNULTE: installing (install.sh may ask for sudo)..."
./install.sh

echo "GNULTE: update complete."
