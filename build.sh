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

echo "== building gnulte-lan (cmd/gnulte-lan) =="
go build -o gnulte-lan ./cmd/gnulte-lan

echo "== building gnulte-devices (cmd/gnulte-devices) =="
go build -o gnulte-devices ./cmd/gnulte-devices

echo "== building gnulte-doctor (cmd/gnulte-doctor) =="
go build -o gnulte-doctor ./cmd/gnulte-doctor

echo "== building gnulte-trace (cmd/gnulte-trace) =="
go build -o gnulte-trace ./cmd/gnulte-trace

echo "== building gnulte-top (cmd/gnulte-top) =="
go build -o gnulte-top ./cmd/gnulte-top

echo "== running tests =="
go test ./...
go vet ./...

echo "== done: ./gnulte-scan ./gnulte ./gnulte-wifi ./gnulte-lan ./gnulte-devices ./gnulte-doctor ./gnulte-trace ./gnulte-top =="