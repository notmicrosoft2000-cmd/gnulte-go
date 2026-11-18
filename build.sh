#!/usr/bin/env bash
# Build the gnulte-go binaries. Go is expected at ~/.local/bin/go (the
# user-local toolchain installed for this project) or anywhere on PATH.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
cd "$(dirname "$0")"

echo "== building gnulte-scan (cmd/gnulte-scan) =="
go build -o gnulte-scan ./cmd/gnulte-scan

echo "== building gnulte (cmd/gnulte) =="
go build -o gnulte ./cmd/gnulte

echo "== building gnulte-wifi (cmd/gnulte-wifi) =="
go build -o gnulte-wifi ./cmd/gnulte-wifi

echo "== building gnulte-watch (cmd/gnulte-watch) =="
go build -o gnulte-watch ./cmd/gnulte-watch

echo "== building gnulte-inventory (cmd/gnulte-inventory) =="
go build -o gnulte-inventory ./cmd/gnulte-inventory

echo "== building gnulte-quicksum (cmd/gnulte-quicksum) =="
go build -o gnulte-quicksum ./cmd/gnulte-quicksum

echo "== running tests =="
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...

echo "== done: ./gnulte-scan ./gnulte ./gnulte-wifi ./gnulte-watch ./gnulte-inventory ./gnulte-quicksum =="
