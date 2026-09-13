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

echo "== building gnulte-wifi (cmd/gnulte-wifi) =="
go build -o gnulte-wifi ./cmd/gnulte-wifi

echo "== building gnulte-traffic (cmd/gnulte-traffic) =="
go build -o gnulte-traffic ./cmd/gnulte-traffic

echo "== running tests =="
go test ./...
go vet ./...

echo "== done: ./gnulte-scan ./gnulte ./gnulte-wifi ./gnulte-traffic =="