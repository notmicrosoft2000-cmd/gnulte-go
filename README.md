# GNULTE · Go edition

> **v15.0 — “Live Interconnection”** · the GNU LAN Network Testing Environment, rewritten in pure Go
> (standard library only, no external dependencies)

![version](https://img.shields.io/badge/version-15.0-62a0ea)
![language](https://img.shields.io/badge/Go-1.21-00ADD8)
![platform](https://img.shields.io/badge/platform-Linux-9cf)
![tests](https://img.shields.io/badge/tests-go%20vet%20%2B%20go%20test-2ea44f)
![license](https://img.shields.io/badge/license-GPL--3.0--or--later-%23c0392b)
[![website](https://img.shields.io/badge/website-GNULTE%20site-1d3a5c)](https://notmicrosoft2000-cmd.github.io/gnulte/)

![GNULTE v15.0 — Live Interconnection](social-preview.png)

GNULTE is a suite of focused Linux tools for measuring how devices behave when
their network misbehaves — on networks you own or are explicitly authorised to
test. Scan the LAN, shape a target’s traffic with real kernel `tc netem`,
watch every device live, and hand off from one tool to the next: the whole
toolkit shares one live view of your network.

## The five tools

| Binary | Root | What it does |
| --- | --- | --- |
| `gnulte` | **yes** | Interactive shaping engine — ARP-spoofed routing into `tc netem` (latency, jitter, loss, duplication, reordering, bandwidth), live dashboard, live `tc -s qdisc` telemetry, HTML report. Discreet `-S` stealth spoofing |
| `gnulte-lan` | optional | Live LAN watch with a **five-screen console** — hosts, talkers (ranked with bars & peers), flows (A ⇄ B, root socket), neighbours (ARP), and screen 5’s **Live Interconnection map** (devices as nodes, live flows as pulsing edges) |
| `gnulte-scan` | optional | Parallel sweep + in-Go deep port scanner — OUI vendor, mDNS/NetBIOS names, device types, OS fingerprinting, `-T` tabbed browser, and live re-scanning with `--watch N` |
| `gnulte-devices` | no | Instant ARP/neighbour inventory — vendors, mDNS hostnames, type guesses, HTML reports |
| `gnulte-wifi` | **yes** | Targeted 802.11 deauthentication for authorised Wi-Fi disassociation testing — per-frame jitter, rotating reason codes, channel hopping |

## Live Interconnection (v15)

One shared device store (`~/.config/gnulte-go/devices.json`) wires the five
tools together — **one watch feeds the whole toolkit**:

- **gnulte-lan screen 5 — the map.** Devices become nodes; live flows become
  edges that pulse (`▸`) as traffic moves, re-arranged to a stable layout
  every tick. Like FLOWS it needs the raw capture socket, announced with an
  explicit `⛔ needs the capture socket (root)` gate otherwise.
- **Handoff.** Press `⏎` (or `g`) on a host and `gnulte -t <ip>` opens against
  it in a fresh terminal — or prints the exact command when no terminal
  emulator is found. The detail pane moved to `Tab`/`d`.
- **Live shaping telemetry.** While a run is live, the dashboard reads the
  kernel queue (`tc -s qdisc`) and shows `netem live · delayed … · reordered …
  · dropped … · backlog … · delay …` — the impairment landing on real packets.
- **Targets from the watch.** `w` in the target menu picks devices straight
  from the shared store; gnulte-scan’s `-T` Summary cross-references the same
  store (`known from last LAN watch`).
- **Live re-scan.** `gnulte-scan --watch 5` re-discovers every N seconds and
  prints exactly what moved — `▲` new · `▼` gone · `~` changed — and the `-T`
  browser runs the same cadence, marks each row, and adds `/` filter focus
  plus `v` vendor filtering.

## Install

Requires [Go 1.21+](https://go.dev/dl/) and, for shaping, `iproute2`,
`arpspoof` (`dsniff`) or `arp-scan`, and `iputils`.

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