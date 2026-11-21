# Verification — v17.0

This checklist records what was actually run against this checkout on
2026-11-18, and what still needs a machine with root and live hardware. The
first section passed here. The second is a hand-off, not a claim.

## Verified here

From the repository root, with Go 1.21 on Linux:

```
go build ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
go test -count=1 ./cmd/... ./internal/...
go test -race -count=1 ./cmd/... ./internal/...
GOOS=darwin go vet ./cmd/... ./internal/...
gofmt -l cmd internal
```

All six exited 0; `gofmt` printed nothing. The scope is deliberate: plain
`./...` also walks an ignored sample directory that is unreadable in this
sandbox, so it cannot give an honest result here. The race run covers the new
pure helpers in `cmd/gnulte-wifi` and `internal/airframes` along with the rest
of the tree.

Version and root-free CLI paths:

```
go run ./cmd/<name> --version      # each of the seven commands
go run ./cmd/gnulte-wifi --list-reasons
go run ./cmd/gnulte-report --help
go run ./cmd/gnulte-quicksum --json
```

All seven version banners print v17.0. `--list-reasons` prints ten named codes,
the report help exits 0, and quicksum exits 0 with a WARN for the missing root
privilege, which is expected in a sandbox.

Site checks: every relative link in the HTML pages resolves to a file, and
`site/feed.xml` parses as Atom XML with the v17.0 entry first.

## Launcher and simple menu

A later pass on the same checkout added `gnulte-hub` and the plain-language
front end in `gnulte`. The full matrix above was run again after those edits,
including the race build and the Darwin vet, with no failures. The piped hub
run used option 8 to read the safety documents through `gnulte --docs`, then
option 9 to quit. Two PTY runs reached the simple menu: option 4 quit without
starting anything, and `1q` opened the effect menu and aborted. All eight
`--version` banners report v17.0.

The PTY runs used `script -qec './gnulte' /dev/null` with input on stdin. They
cover menu navigation only; no shaping session was started, so the root and
live-hardware checks below still stand.

## Deferred — root or live hardware needed

Run these on a bare box before the release can be called proven there:

1. Install with `sudo ./install.sh`, then run `--version` on each installed
   binary. All seven must agree on v17.0; the installer already aborts on a
   version mismatch.
2. Run `sudo gnulte-quicksum` and clear any FAIL before shaping.
3. On a network you own, put an adapter in monitor mode and send a single
   deauth burst with `gnulte-wifi`. Confirm the station drops and reconnects on
   its own.
4. Repeat with a named reason, two comma-separated stations and a streak, and
   with channel hopping. Check the jitter and dwell lines in the closing
   summary against what the flags asked for.
5. Run a shaping session and confirm the qdisc and iptables rules are gone on
   both a clean exit and an interrupt. This is the restore guarantee the soak
   runner was meant to hammer.
6. Work the interactive paths through the PTY harness at
   `~/Documents/gnulte-verify/pty17.py`.

The soak runner from the plan was skipped by decision. Step 5 covers one cycle
of the same ground; a longer back-to-back run is still worth doing on hardware.
