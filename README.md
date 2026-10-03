# GNULTE · Go edition

> **v16.13 — Unplugged** · the GNU LAN Network Testing Environment, rewritten in pure Go
> (standard library only, no external dependencies)

![version](https://img.shields.io/badge/version-16.13-62a0ea)
![language](https://img.shields.io/badge/Go-1.21-00ADD8)
![platform](https://img.shields.io/badge/platform-Linux-9cf)
![tests](https://img.shields.io/badge/tests-go%20vet%20%2B%20go%20test-2ea44f)
![license](https://img.shields.io/badge/license-GPL--3.0--or--later-%23c0392b)
[![website](https://img.shields.io/badge/website-GNULTE%20site-1d3a5c)](https://notmicrosoft2000-cmd.github.io/gnulte/)

![GNULTE v16.13 — Unplugged](social-preview.png)

GNULTE is a suite of focused Linux tools for measuring how devices behave when
their network misbehaves — on networks you own or are explicitly authorised to
test. Scan the LAN, shape a target’s traffic with real kernel `tc netem`,
watch every device live, and hand off from one tool to the next: the whole
toolkit shares one live view of your network.

## The eight tools

| Binary | Root | What it does |
| --- | --- | --- |
| `gnulte` | **yes** | Interactive shaping engine — ARP-spoofed routing into `tc netem` (latency, jitter, loss, duplication, reordering, bandwidth), live dashboard, live `tc -s qdisc` telemetry, HTML report. Discreet `-S` stealth spoofing |
| `gnulte-lan` | optional | Live LAN watch with a **six-screen console** — hosts, talkers (ranked with bars & peers), flows (A ⇄ B, root socket), neighbours (ARP), screen 5’s **Live Interconnection map** (devices as nodes, live flows as pulsing edges), and screen 6’s **history** (session alarms + today’s recorded timeline). `--json` emits a JSON-lines feed; the report adds a 7-day trend |
| `gnulte-scan` | optional | Parallel sweep + in-Go deep port scanner — OUI vendor, mDNS/NetBIOS names, device types, OS fingerprinting, `-T` tabbed browser, and live re-scanning with `--watch N` |
| `gnulte-devices` | no | Instant ARP/neighbour inventory — vendors, mDNS hostnames, type guesses, HTML reports |
| `gnulte-wifi` | **yes** | Targeted 802.11 deauthentication for authorised Wi-Fi disassociation testing — per-frame jitter, rotating reason codes, channel hopping |
| `gnulte-doctor` | no | Pre-flight health check — privileges, `tc`/`iptables`, `ip_forward`, the netem/netfilter modules, default route and interface, duplicate IPs, and the safety-record. PASS/WARN/FAIL table with fix-it hints, `--json`, non-zero exit on any failure |
| `gnulte-trace` | **yes** | mtr-style hop-by-hop path probe — in-process ICMP echo at every TTL, a live table with per-hop last/avg/best/worst and loss, `--json`, and a self-contained HTML report. No `traceroute(8)` |
| `gnulte-top` | **yes** | Live per-host and per-conversation bandwidth — an in-process AF_PACKET counter ranked into a top-talker table with ↓/↑ rates, peers and bars, plus `--flows`, `--csv` and `--json`. No iptables, no `top(1)` |

## Unplugged (v16.6+)

v17's **Unplugged** programme, in progress. The goal is a toolkit that runs on a
bare box with nothing but the kernel: the shell-outs to `arping`, `arp-scan` and
`tcpdump` are being replaced by in-process raw-socket code, one per increment,
each independently shippable.

- **v16.6 — in-Go ARP sweep.** The LAN sweep no longer shells out. `gnulte-scan
  --arp` now crafts who-has frames in-process over AF_PACKET and matches the
  answers itself, so `arping` and `arp-scan` are not required anywhere. The
  kernel's neighbour table is still read for cheap lookups, and
  `DiscoverNeighbors` additionally sweeps the interface subnet as root, which is
  what the old `arp-scan --localnet` boost did — devices that answer ARP but
  never originate traffic (phones in doze, printers, TVs) are learned either
  way, with no helper binary installed.

- **v16.7 — in-Go ICMP echo.** The live-shaping telemetry no longer shells out
  to `ping`: echo requests are built, checksummed and matched in-process over a
  raw `IPPROTO_ICMP` socket, with the round-trip measured on the socket and the
  reply TTL read back from the IP header. Non-root tools keep the system `ping`
  as a fallback, so `gnulte-lan` and `gnulte-scan` behave exactly as before;
  the shaping engine no longer needs `ping` installed at all.

- **v16.8 — in-Go capture.** `gnulte --capture FILE` no longer runs `tcpdump`.
  A raw `AF_PACKET` socket feeds a small standard-library libpcap writer
  (`internal/pcap`), so capture records alongside the shaping session and stops
  cleanly on teardown, with the file handed back to the invoking user.
  `tcpdump` is no longer required by the engine.

- **v16.9 — `gnulte-doctor`.** A new zero-dependency pre-flight command that
  reports whether a machine is ready to run the toolkit: privileges, the
  `tc`/`iptables` binaries, `ip_forward`, the netem/netfilter kernel modules, the
  default route and interface, duplicate IPs, and the safety-record. It prints a
  PASS/WARN/FAIL table with fix-it hints, supports `--json`, and exits non-zero
  when anything fails, so a script can gate on it.

- **v16.10 — `gnulte-trace`.** An mtr-style hop-by-hop path probe with no
  `traceroute(8)` behind it: `internal/icmp` gains a per-TTL echo probe that
  decodes the time-exceeded and destination-unreachable errors routers send
  back, and `internal/trace` walks the path accumulating last/avg/best/worst and
  loss per hop. The command shows a live table while it runs, then a finished
  table in the scrollback, and can emit `--json` or a self-contained HTML
  report.

- **v16.11 — `gnulte-top`.** A live per-host and per-conversation bandwidth
  view built on the same in-process `AF_PACKET` counter the LAN watch already
  uses. It ranks the talkers (`internal/toptalk`) with ↓/↑ rates, peer counts
  and bars, can follow `--flows`, and exports a snapshot as `--csv` or `--json`
  instead of painting the screen.

- **v16.12 — scenarios, per-target shaping, profiles & a session summary.** A
  shaping run can now be scripted: `--scenario FILE` plays timed phases — each
  with its own latency/jitter/loss and an optional sine or sawtooth wobble or an
  on/off loss burst — into the live tree, and the dashboard names the phase in
  force. `--per-target FILE` gives individual hosts their own `tc`/netem class
  over a JSON override, `--profile save:NAME` stores the current parameters as a
  reusable preset, and `--list-profiles` shows the built-ins plus your own. When
  the run ends, a session summary rolls up min/avg/p95/max, jitter, loss with a
  run-length distribution, and a rough E-model MOS — printed on the console and
  embedded in the HTML report.

- **v16.13 — watch history & a machine feed.** The LAN watch now remembers: a new
  pure `internal/history` package keeps a JSONL timeline of every debounced
  up/down transition under the toolkit's config dir, and each finished session
  files a per-host health snapshot. `--json` turns the dashboard into a
  JSON-lines feed — a baseline object, a per-second object of host rates and
  latency, and an alert for each transition — with every human line moved to
  stderr; `-alert-debounce N` sets the consecutive-sample hysteresis before an
  alarm fires; `--history-file`/`-no-history` control where the timeline lives.
  Screen 6 shows the session's alarms beside today's recorded transitions, and
  the HTML report grows a 7-day latency bar chart per host with a blunt 0–100
  health score (loss first, then drift from the host's own baseline, spread and
  up/down churn). Still no `ping`, no external store, no new dependency.

## Steady Hands (v16)

A stability release. The base is still v15's **Live Interconnection** — one
shared device store (`~/.config/gnulte-go/devices.json`) wiring the five tools
together — with the sharp edges filed off and a few things added:

- **Ctrl+C exits cleanly instead of killing the run.** A shared signal handler
  was racing each tool's own graceful shutdown and winning with a hard
  `os.Exit(130)`, so the first Ctrl+C cut a run dead mid-teardown. It now
  restores the screen and terminal on the first signal and lets the shutdown
  finish, forcing the exit only on a *second* Ctrl+C or after a grace period.
  This was not cosmetic: the old hard kill skipped `sess.Stop()`, leaving
  targets with a poisoned ARP cache and no connectivity.
- **A live watch stops when you tell it to.** The name-identification waits
  (reverse DNS, mDNS, NetBIOS) bounded themselves by a *deadline* but never
  checked for *cancellation* — exactly what `signal.NotifyContext` produces —
  so interrupting a scan mid-sweep took **10.9s** to respond. Every wait now
  ends at once. Measured: **0.00s**.
- **Honest sampling cadence.** The gap is measured from when a reading lands,
  not from when the probe started, so a target that takes two seconds to answer
  still gets its full one-second gap instead of the next probe firing the
  instant the slow one returns. A run also starts measuring immediately.
- **gnulte-lan arrows do one thing.** The phantom-repeat bug is gone: holding
  an arrow key no longer scoots the cursor dozens of rows past where you
  pointed it. Two quick taps still queue and drain as two moves.
- **`gnulte --note TEXT`.** Label a run at launch; the note rides into the
  console header and the report.
- **`gnulte-scan --watch N --json`.** One JSON object per sweep on stdout
  (`{"kind":"baseline"}`, then `{"kind":"delta"}` with the movement), narrative
  to stderr — so `gnulte-scan --watch 5 --json | jq` is a working motion
  sensor. Mutually exclusive with `-q`/`--yaml`/`--csv`.
- **Quick scan.** `r` re-scans on demand in the `-T` browser, with a
  `▲ new ▼ gone ~ changed` legend on the status line. Devices the shared store
  already knows are marked `*` in the target picker, and you can select by
  keyword (`Mobile`, `@hostname`).

## Install

Requires [Go 1.21+](https://go.dev/dl/) and, for shaping, `iproute2`,
`iptables`, and `iputils`. No external ARP or packet capture tools are
required: raw ARP probing/injection and capture are implemented in-process.

```sh
git clone https://github.com/notmicrosoft2000-cmd/gnulte-go.git
cd gnulte-go
./build.sh          # builds all five binaries, runs go vet + go test ./...
sudo ./install.sh   # installs to /usr/local/bin + safety docs
```

Update: `git pull && sudo ./install.sh` — the installer reads the version from
the freshly built binaries and aborts if they disagree, so it can never drift
behind the source tree. Uninstall: `sudo ./uninstall.sh [--purge]`.

## Quick start

```sh
sudo gnulte                                            # guided menu: target → conditions → run
sudo gnulte -t 192.168.1.50 -l 300 -j 30 --duration 90 # 300ms latency + 30ms jitter, 90s auto-stop
sudo gnulte -r 192.168.1.0/24 -w 192.168.1.100 --profile throttle --duration 600

gnulte-lan                                            # five-screen live watch (auto-discovers subnet)
gnulte-lan -t 192.168.1.20 --duration 60              # one host, up close
gnulte-scan --deep                                    # sweep + in-Go port scan + OS fingerprint
gnulte-scan --watch 5                                 # live re-scan: ▲ new · ▼ gone · ~ changed
gnulte-scan -T                                        # tabbed browser: Devices / Log / Summary
gnulte-devices -s                                     # instant ARP inventory + optional sweep
```

### gnulte-lan keys

`↑↓` browse · `⏎`/`g` hand off to `gnulte -t <ip>` · `Tab`/`d` detail ·
`1–5` (or `t`/`f`/`n`/`m`) screens · `x` save the watch to the shared store ·
`s` sort · `a` alarm-only · `o` settings · `Esc` peel · `q` quit.

## Safety

GNULTE performs ARP-based man-in-the-middle routing, kernel-level traffic
impairment, packet capture, LAN discovery, and 802.11 injection. **Only use
these tools on networks, systems and devices you own or are explicitly
authorised to test.** The authors grant no permission to test any particular
third-party network; users are responsible for complying with all applicable
laws, contracts and policies. See `SAFETY.md`, `DISCLAIMER.md` and
`AUTHORIZED-USE.md`.

## Website & documentation

The full manual lives on the [GNULTE site](https://notmicrosoft2000-cmd.github.io/gnulte/)
— [features](https://notmicrosoft2000-cmd.github.io/gnulte/features.html),
[wiki](https://notmicrosoft2000-cmd.github.io/gnulte/wiki.html),
[changelog](https://notmicrosoft2000-cmd.github.io/gnulte/changelog.html), and
[scripted Studio re-enactments](https://notmicrosoft2000-cmd.github.io/gnulte/preview.html)
built from the real binaries’ banners.

State lives under `~/.config/gnulte-go/` (`config.json`, `devices.json`,
`acceptance.json`, `profiles.json`); reports are filed under `~/GNULTE Reports/`.

## License

GPL-3.0-or-later. Verification and regression work is plain `go test` — no CI
required, no third-party modules.

<div align="center"><sub>GNU LAN Network Testing Environment · scan first, ask permission first, clean up after.</sub></div>