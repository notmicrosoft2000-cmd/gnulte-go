# GNULTE v17 — "Unplugged" — master plan

Status: **locked**. Owner: this session. Branch/chain: incremental bumps `16.6 → 16.7 → … → 17.0` on `main`, each independently shippable and testable.

## Locked decisions

- **Spine: Program A — zero-dependency core.** Replace every helper-binary shell-out with in-Go implementations so the toolkit runs on a bare box. `tc` / `iptables` stay: they *are* the kernel interface.
- **New tools:** `gnulte-doctor`, `gnulte-trace`, `gnulte-top` (the top-3 from the vetting list). Total tool count goes 5 → 8.
- **Cadence:** incremental, each bump tested end-to-end before the next.
- **Wifi:** reason-code presets + client-steer ship. **Monitor-mode channel scanning is OUT for v17** (no nl80211 spike, no verification-mode scope creep).
- The agreed-but-never-started v17 backlog is folded in: `gnulte --compare`, gnulte-lan `--json`, `--watch` stderr alerts, soak runner, gofmt of the 7 drifted files.

## Constraints (hard)

- Pure stdlib Go 1.21; **no new dependencies, no go.mod change** (module proxy blocked; github only).
- Linux target. `GOOS=darwin go vet ./...` must stay clean → use `*_linux.go` / build tags for platform-specific code; cross-platform code stays shared.
- Sandbox has **no root**: the engine cannot be exercised end-to-end here. `GNULTE_AS_ROOT=1` is the harness shim (re-exec skip). Live net checks go through PTY harnesses (`~/Documents/gnulte-verify/pty17.py` pattern; add `pty18.py` per feature as needed).
- `gofmt -l` must show **only** the 7 pre-existing drifted files until 16.15 (when they get formatted as a targeted cleanup): `cmd/gnulte-lan/view.go`, `internal/engine/qdisc.go`, `internal/engine/qdisc_test.go`, `internal/inventory/inventory.go`, `internal/inventory/inventory_test.go`, `internal/scanner/diff.go`, `internal/scanner/diff_test.go`. New code must not add drift.
- Verification per bump: `go build ./...` → `go vet ./...` → `go test -count=1 ./...` → `go test -race -count=1 ./...` → `GOOS=darwin go vet ./...` → gofmt check. Version bump (`const version` in the 5 `cmd/*/main.go` + README title/shield/alt) in the same commit as the feature.

## Build chain

### 16.6 — In-Go ARP sweep — **SHIPPED**
Kill the `arping` / `arp-scan` shell-outs in `internal/discover`. Benefits every sweep tool.

- New raw AF_PACKET socket path (reuse frame craft/parse from `internal/arpspoof`; add what's missing, e.g. a who-has request builder).
- Bounded-concurrency sweep over the /24; sends who-has per target, reads replies, collects MAC + RTT-ish timing.
- Delete the `exec.LookPath("arping")` / `arp-scan` fallbacks and the `menu.go` pre-flight entry for them.
- Tests: unit tests feed synthesized ARP reply frames → parser (deterministic, no root); update pty harness to prove gnulte-devices / gnulte-lan sweeps still list real hosts.
- Touch: internal/discover, internal/arpspoof (maybe), cmd/gnulte/menu.go.

**As built:** `arpspoof.BuildARPRequest` / `ParseARPReply` / `ReadReply` / `LocalIP` added; the sweep lives in `internal/discover/arpsweep{,_linux,_other}.go` (`runSweep`, `probeSet.note`); `Neighbors` split into the cheap kernel read and `DiscoverNeighbors` (the old `arp-scan --localnet` boost), with the six discovery call sites switched over. `engine.arpLookupMAC` now uses `discover.ResolveMAC` instead of `arping -c 1`. Tests: `internal/arpspoof/frame_test.go`, `internal/discover/arpsweep_test.go`. Live-sweep proof needs a root box — pending user verification.

### 16.7 — In-Go ICMP echo  — **SHIPPED** (v16.7)
Engine per-second telemetry stops shelling to `ping`. Builds the raw-ICMP core later tools reuse.

- Raw `IPPROTO_ICMP` echo request/reply: checksum, id/seq, timeout, RTT. Engine already re-execs as root, so this is the root path.
- Non-root tools (gnulte-lan/scan pings) keep their current TCP/UDP probes — no behavior change there.
- Feed `hostStat` (avg/p50/p95) in the same shape as today.
- Tests: synthetic echo-reply parsing; framing checks; keep old `ping`-based behaviour behind nothing — it just goes away in the engine.
- Touch: internal/engine, internal/discover (share the ICMP pinger).

**As built:** new `internal/icmp` package — pure `Checksum`/`BuildEcho`/`Decode`
(the decoder accepts either a bare ICMP message or one behind its IPv4 header,
and reports the TTL) plus a Linux raw-socket `Ping` (`SO_RCVTIMEO`-bounded reads
that honour the deadline and context) and an off-Linux stub. `probe.Ping` tries
the in-Go probe first through a test seam (`rawPing`); a non-nil error (no raw
socket: non-root or non-Linux) falls back to the system `ping`, while a silent
target is silence and is *not* retried through the subprocess. Engine
`DepsCheck` no longer requires `ping`, and the boot sequence prints an
"in-process" ICMP row instead. Tests: `internal/icmp/icmp_test.go` (checksum
vector, framing, IP-header/TTL, impostor rejection, payload copy), a root-gated live
loopback test, and three fallback-selection tests in `internal/probe` (a mutant
battery killed the inverted-selection, bad-checksum and no-IP-strip variants).
Live raw-socket proof needs a root box — pending user verification.

### 16.8 — In-Go capture + pcap writer  — **SHIPPED** (v16.8)
`gnulte --capture FILE` stops needing `tcpdump`.

- AF_PACKET sniff + a pure-stdlib pcap writer (global header magic `d4 c3 b2 a1`, linktype EN10MB=1, per-packet ts_sec/ts_usec/incl_len/orig_len). `-` = raw pcap to stdout like tcpdump.
- Capture runs concurrently with the shaping session; stopped on teardown; file closed cleanly (no `exec.LookPath("tcpdump")`).
- Tests: write frames → reopen → validate magic/linktype/len for both byte orders; menu.go LookPath list drops tcpdump.
- Touch: internal/engine, new internal/pcap (or internal/capture).

**As built:** new `internal/pcap` (pure `Writer`/`Reader`; little-endian output,
reader auto-detects either order; snaplen truncation preserves orig_len) and
`internal/engine/capture{,_linux,_other}.go`. The loop reads an `AF_PACKET`
socket (opened synchronously, so a permission/interface problem fails Start), a
host filter (byte-exact IPv4/IPv6 keys, VLAN-aware, empty set = capture all,
ARP skipped under a filter) replaces the old `tcpdump host …` args, and matching
frames stream through the pcap writer until the context is cancelled; both the
socket and the file are closed on the way out, then the file is chowned back.
`DepsCheck` and the engine transcript no longer mention `tcpdump`; the flag help
now says "as pcap". Tests: `internal/pcap` round-trip in both byte orders,
snaplen truncation, empty-valid-file, garbage rejection; `internal/engine`
filter/normalisation plus a fake-source loop test (filtering, empty filter,
cancel-and-valid-partial-file). Live AF_PACKET proof needs a root box — pending
user verification.

### 16.9 — `gnulte-doctor` (new tool)  — **SHIPPED** (v16.9)
Pre-flight + fix-it report; makes the zero-dep chain a friendly claim.

- Checks: euid root (per tool), ip_forward, netem/iptables kernel modules (`/proc/modules` or `tc qdisc show`), `tc`/`iptables` present, interface up + has IPv4, default route, duplicate-IP scan (reuse dupcheck), safety acceptance record.
- Output: PASS/WARN/FAIL table + fix-it hints; `--json`; non-zero exit on FAIL. Reuses the install.sh guidance.
- Tests: check registry against injected fake facts (dependency-inject the gatherers).
- Touch: new cmd/gnulte-doctor.

**As built:** new `internal/doctor` separates gathering (`Gather(ctx) Facts`,
reads euid, PATH, `/proc/sys/net/ipv4/ip_forward`, `/proc/modules`, netutil's
route, the safety record, and the discovery neighbour table) from judging
(`Run(Facts) []Check`, pure). Ten checks: privileges, `tc`, `iptables`,
`ip_forward`, netem and netfilter modules, default route, interface up,
duplicate IPs, safety acceptance. `Warn` (not `Fail`) covers non-root, missing
modules that may be built in, an empty ARP table, LAN conflicts and an
unaccepted safety record; `Fail` (→ exit 1) covers a missing `tc`/`iptables`,
an unavailable `ip_forward`, no route, or a down interface. `Check` marshals
`status` as the word PASS/WARN/FAIL for `--json`. New `cmd/gnulte-doctor`
(`-j/--json`, `-q/--quiet`, `-v/--version`) renders the table with fix-it hints;
wired into build/install/uninstall and the README tool table. Tests inject fake
facts for every branch, plus exit-code and JSON-wording guards.

### 16.10 — `gnulte-trace` (new tool)  — **SHIPPED** (v16.10)
mtr-style traceroute: hop-by-hop RTT, animated TUI + HTML report + `--json`.

- Raw ICMP probes at TTL 1..N (reuses 16.7 core): each hop probed several times for min/avg/max/loss; stop on "port unreachable"/echo-reply from target. Re-exec as root (like the other root tools).
- Live table (mtr-like), final HTML report, machine output.
- Tests: synthetic ICMP time-exceeded frames; hop-extraction logic; live only with root → pty proof skipped in sandbox, rely on unit level + `GOOS` build tags.
- Touch: new cmd/gnulte-trace.

**As built:** `internal/icmp` gains `TraceProbe` (Linux raw ICMP echo with a
per-probe `IP_TTL`, `icmp_other.go` stub off Linux) and the pure `DecodeTrace`,
which classifies an echo reply (the target), a time-exceeded (a router, with the
quoted request matched by id/seq), or a destination-unreachable — rejecting
packets that are not our probe's answer. New `internal/trace` owns the walk:
`Walk(ctx, target, Options, ProbeFunc, onHop)` probes each TTL `Probes` times,
accumulates min/avg/max/loss and the hop address, and stops at the target, an
unreachable, the hop limit or context cancellation — all behind a probe seam so
it is tested without a socket. New `cmd/gnulte-trace` (`-m/-c/-t/-i`, `--json`,
`--html`, `-q`) drives a `tui.Screen` live table (goroutine walk + mutex-guarded
hops + `Poll` for `q`), falls back to an incremental plain view when stdout is
not a terminal, prints the finished table to the scrollback, and re-execs
through sudo once like the other root tools. Wired into build/install/uninstall
and the README tool table.

### 16.11 — `gnulte-top` (new tool)  — **SHIPPED** (v16.11)
Live per-host/per-flow bandwidth top + CSV/JSON export.

- Reuse `internal/traffic` Counter (AF_PACKET). Live TUI sorted by combined rate (gnulte-lan talkers pattern), ↓/↑ rate, totals, peers; `--interval`, `--json`/`--csv`, per-host filter. Re-exec as root.
- Tests: formatting/sorting units; pty render-check with the GNULTE_AS_ROOT shim (rates 0 in sandbox, must render + quit clean).
- Touch: new cmd/gnulte-top.

**As built:** new pure `internal/toptalk` owns the ranking and formatting core
(`Rows`, `FlowRows`, `Peers`, `HostOf`, `HumanBytes`, `HumanRate`, `Bar`), so the
table maths is `go test`-able with no socket. New `cmd/gnulte-top` (`-i/-n`,
`--json`, `--csv`, `--flows`, `--host`, `--iface`, `-q/-v`) reuses the
`internal/traffic` AF_PACKET `Counter`, re-execs through sudo once like the other
root tools, and drives a `tui.Screen` live table; the counter is a **garnish** —
if the socket cannot be opened (non-root, down interface) the tool still runs and
simply reports zero rates. `--csv`/`--json` export a single sample without
painting the screen, and a non-terminal stdout gets incremental plain lines
instead of the live view. Wired into build/install/uninstall, the README tool
table and the Unplugged bullet list.

### 16.12 — Engine scenarios  — **SHIPPED** (v16.12)
- **JSON scenario scripts**: phases `{duration, latency, jitter, loss, dup, reorder, bandwidth, wobble?, burst?}` advanced on a clock; live dashboard shows current phase; `--scenario file.json`.
- **Wobble** (sawtooth/sine latency) and **burst loss** (N-second windows with elevated loss) generators.
- **`--per-target profile.json`** mapping ip→override on top of global params.
- **Profile folder**: `~/.config/gnulte/profiles/*.json` loadable via `--profile name` (built-ins first), `--profile save:name`.
- **End-of-session summary**: min/avg/p95/max latency, loss distribution, rough MOS — into console + HTML report.
- **TUI sparklines**: rolling latency/loss strip charts in the dashboard.
- Tests: scenario clock with fake time, parameter application, summary math, report contains summary.
- Touch: internal/engine, cmd/gnulte, internal/reportdir.

**As built:** new pure `internal/scenario` (`Parse`/`Load`/`Validate`, `At(elapsed)`
clock, sine/sawtooth `Wobble`, windowed `Burst`, `Describe`) and
`internal/profiles` (`Dir`/`Path`/`Load`/`Save`/`Parse`/`List`, name-guarded to
stay inside the folder). The profile folder is `~/.config/gnulte-go/profiles`
(the toolkit keeps its `gnulte-go` config dir rather than the bare `gnulte` the
plan text assumed). `engine` gains the shared exported `Impairment` type (the
global fields and every override collapse into it), `Config.PerTarget`, and a
`leafPlan` that puts override classes first (lower `tc` prio) and the global
class last — with no overrides the tree is byte-for-byte unchanged. `cmd/gnulte`
adds `--scenario`, `--per-target` (a partial JSON override merged over the
global base), `--profile save:NAME`, and a folder-aware `--list-profiles`; a
scenario tick calls `Session.UpdateParams` from the phase clock and sets the
dashboard phase. New `cmd/gnulte/summary.go` computes the console/report rollup
(nearest-rank p95, population σ, run-length loss buckets, rough E-model MOS).
Monitor records a parallel `LossSeries` (0/100 per attempt) for the loss
sparkline and run-length distribution, both trimmed with the latency history.

### 16.13 — Watch history (gnulte-lan)  — **SHIPPED** (v16.13)
- `--json` live feed (baseline + per-second host/alert events; narrative to stderr — same pattern as gnulte-scan).
- **stderr alerts** with hysteresis (N consecutive hits before firing/unfiring).
- **Device timeline**: JSONL store of host up/down transitions (reuse inventory dir layout).
- **7-day trend charts** in the HTML report (per-host daily avg/p95 + up-hours; embedded pure-JS sparkline — no external libs).
- **Network health score** (loss, RTT vs baseline, churn).
- **Screen 6**: alarms history + today's timeline.
- Tests: alert hysteresis FSM, timeline round-trip, JSON feed schema, screen-6 render via pty.
- Touch: cmd/gnulte-lan, internal/monitor or new internal/history.

**As built:** the timeline lives in a new pure `internal/history` package
(`Kind{up,down,snapshot}`, `Entry`, `Path`/`Append`/`Load`, `Window`/`OnDay`/
`Daily` rollups with a per-day mean loss, `HealthScore`, and a `Latch`
debouncer) writing JSONL to `~/.config/gnulte-go/watch-history.jsonl` — the same
config dir as the device store, not the plan text's bare `gnulte`. `cmd/gnulte-lan`
gains `-json` (baseline/tick/alert objects on stdout, every narrative line moved
to stderr), `-history-file`, `-no-history` and `-alert-debounce N` (default 2).
Each tick feeds one `Latch` per host from the latest ping result and appends a
store entry plus a stderr alert on a debounced flip; the session closes with one
health snapshot per reachable host. Screen 6 renders the session's alarms and
today's stored transitions; the HTML report gains a 7-day latency bar chart per
host and a 0–100 health score (loss first, then drift from the host's own
baseline, spread and churn). Tests cover the latch FSM, daily loss aggregation,
the feed schema, the screen-6 render and the trend/health math.

### 16.14 — Sweepers with memory + `--compare`
- Extend the inventory store with ports / banners / alive-times.
- gnulte-scan/devices alert "**new port appeared**" / "port closed since last run" on stderr + report.
- **Banner depth**: TLS ClientHello via stdlib `tls.Dial` (ServerHello version/cipher, SNI), SSH version grab (line read), SMB negotiate parse — all pure stdlib, tested against in-process fake servers.
- **Sleep/wake tracking**: derive awake-hours from repeated sightings; report it.
- **`gnulte --compare A B`**: diff two report JSON snapshots → human + HTML "what changed".
- **`--oui-file`**: merge a user CSV vendor table on top of the built-in.
- Touch: cmd/gnulte-scan, cmd/gnulte-devices, cmd/gnulte, internal/inventory, internal/ident.

### 16.15 — Cleanup + soak + report + wifi
- **gofmt the 7 drifted files** (targeted cleanup; verify the diff is formatting-only).
- **Soak runner**: a `go test`-tagged long test / hidden `gnulte soak` running sessions back-to-back asserting clean restores + a script.
- **`gnulte-report`**: archive/merge/compare reports across tools and days (backs `--compare`), index HTML.
- **Wifi**: `--reason <code|preset>` (named deauthentication reasons), `--streak`/client-steer, per-frame jitter counters, channel-dwell stats. No monitor mode.
- Touch: repo-wide formatting, new cmd/gnulte-report, cmd/gnulte-wifi.

### 17.0 — Cap
Full docs pass, bare-box verification checklist executed, version → 17.0, README title/shield/alt + tool table (8 tools), `social-preview` refresh if time allows.

## Verification conventions (every bump)

1. `go build ./... && go vet ./...`
2. `go test -count=1 ./...` then `go test -race -count=1 ./...`
3. `GOOS=darwin go vet ./...` clean
4. `gofmt -l` == the 7 pre-existing files only (until 16.15)
5. New tests must **discriminate** against old behaviour (prove they fail on the pre-bump code; the v16 lesson).
6. PTY harness for interactive paths, `--no-report`, `GNULTE_AS_ROOT=1` in the sandbox.
7. Version string + README bump in the same commit; push `main` after green.

## Historical notes

- v16.1 (`a268dd0`): 18-bug audit batch — crash/race fixes, per-screen currentIP handoff, `--watch` cadence, corrective gateway re-announce, atomic inventory writes, monitor log cap. v16.5 (`9e5263a`): version bump.
- PTY harness lives at `~/Documents/gnulte-verify/pty17.py` (24/24 on v16.5, 18/22 against HEAD — the 4 fails are exactly the wrong-target/cadence bugs it guards).
- Repo README still claims "no external dependencies"; Program A makes that morally true by removing the last binary shell-outs.