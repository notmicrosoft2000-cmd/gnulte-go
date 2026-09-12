#!/usr/bin/env bash
# Build the gnulte-go binaries. Go is expected at ~/.local/bin/go (the
# user-local toolchain installed for this project) or anywhere on PATH.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
cd "$(dirname "$0")"

echo "== building gnulte-scan (cmd/gnulte-scan) =="
go build -o gnulte-scan ./cmd/gnulte-scan

echo "== building gnulte traffic engine (cmd/gnulte) =="
go build -o gnulte ./cmd/gnulte

echo "== running tests =="
go test ./...
go vet ./...

echo "== done: ./gnulte-scan ./gnulte =="