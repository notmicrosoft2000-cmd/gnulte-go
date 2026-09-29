// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/traffic"
	"gnulte-go/internal/ux"
)

// The interactive watch view (tui.Screen): screen modes, cursor, ordering,
// per-host hues. It lives on the alternate screen when stdin/stdout are a live
// terminal; piped and -q runs keep the classic buildLines transcript instead.
//
// v13.5 turns the watch into a four-screen console:
//
//	1 HOSTS     the live dashboard, one fixed-shape block per host
//	2 TALKERS   hosts ranked by combined rate, with bars and peers
//	3 FLOWS     per-conversation pairs A ⇄ B (needs the root capture socket)
//	4 ARP       the neighbour table: MAC · vendor · type · host · live RTT
//
// v15 adds screen 5, the Live Interconnection map:
//
//	5 MAP       gateway · self · every device as a node; live pairs as edges
//	             (needs the root capture socket), busiest link pulsing
//
// Rows scale with terminal width (compact 2-line < 78 cols, normal 3-line,
// wide 4-line ≥ 116 cols) and every host keeps one stable hue across screens
// so you can follow a device by colour alone.

// Screen modes.
const (
	scrHosts = iota
	scrTalkers
	scrFlows
	scrArp
	scrMap
)

// screenLabel is the mode tag shown in the header status line.
func screenLabel(s int) string {
	switch s {
	case scrTalkers:
		return "TALKERS"
	case scrFlows:
		return "FLOWS"
	case scrArp:
		return "ARP"
	case scrMap:
		return "MAP"
	default:
		return "HOSTS"
	}
}

// Row layout bands, chosen once per draw from the terminal width. Height is
// stable within a band, so the only time the frame resizes is a real resize.
const (
	layoutCompact = iota // < 78 cols: two lines per host
	layoutNormal         // 78–115 cols: the three-line v13.4 block
	layoutWide           // ≥ 116 cols: four lines, extra stats
)

func layoutFor(width int) int {
	switch {
	case width > 0 && width < 78:
		return layoutCompact
	case width >= 116:
		return layoutWide
	default:
		return layoutNormal
	}
}

// viewState is everything the operator can change while the watch runs:
// which host the cursor sits on, how rows are ordered, which screen is up,
// whether the detail pane is open, and whether only alarming hosts are shown.
type viewState struct {
	cursor    int  // index into the current (filtered, sorted) row order
	sortMode  int  // sortAddr, sortTraffic or sortPing
	alarmOnly bool // hide hosts that are not alarming
	detail    bool // host detail pane open, for the cursor host
	screen    int  // scrHosts, scrTalkers, scrFlows or scrArp
	showHelp  bool // expanded key hints
	auto      bool // whole-LAN watch mode (router skipped)
	count     int  // how many rows the last draw showed (after the alarm filter)
	currentIP string
	gCmd      string // transient "gnulte -t <ip>" hint shown under the footer
}

// Row ordering modes.
const (
	sortAddr = iota
	sortTraffic
	sortPing
)

func (s *viewState) sortName() string {
	switch s.sortMode {
	case sortTraffic:
		return "traffic"
	case sortPing:
		return "latency"
	default:
		return "address"
	}
}

// watchEnv is the frame-time environment the view needs beyond the watched
// rows themselves: the network the watch runs on, the operator's own machine,
// the gateway's last latency, the aggregate flags, the terminal width (for row
// layout scaling) and the fresh neighbour table (for the ARP screen).
type watchEnv struct {
	nic, subnet string
	selfIP      string
	gwIP        string
	gwRTT       int // gateway RTT ms: -2 not tried yet, -1 last attempt failed
	iv          int
	start       time.Time
	up          int // hosts with at least one successful ping
	alarmOn     bool
	hasCounter  bool // raw capture socket live (root)
	width       int  // terminal columns, for layoutFor
	neigh       map[string]string
	pulse       bool // map screen: highlight the busiest link this draw
}

// vrow is one host row with its sort keys and rendered lines precomputed.
type vrow struct {
	ip    string
	lines []string
	slide int64 // combined rx+tx bytes this tick (traffic sort)
	ping  int64 // average RTT ms (latency sort)
	alarm bool
}

// vrows builds the visible row set in the current sort/filter order and
// clamps cursor and scroll into range. Every row is exactly the lines of its
// layout band (two, three or four — see watchRow*), so the frame height is
// stable no matter how much — or how little — is known about a host.
func vrows(st *viewState, hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	stats map[string]*hostStat, iv int, layout int) []vrow {

	order := make([]int, len(hosts))
	for i := range hosts {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ia, ib := hosts[order[a]], hosts[order[b]]
		switch st.sortMode {
		case sortTraffic:
			ra, rb := rates[ia], rates[ib]
			ta, tb := ra.RXBytes+ra.TXBytes, rb.RXBytes+rb.TXBytes
			if ta != tb {
				return ta > tb
			}
			return ia < ib
		case sortPing:
			pa, pb := stats[ia].ping.avg(), stats[ib].ping.avg()
			if pa != pb {
				return pa > pb // unhealthiest links first
			}
			return ia < ib
		default:
			return ia < ib
		}
	})

	out := make([]vrow, 0, len(order))
	for _, i := range order {
		ip := hosts[i]
		stt := stats[ip]
		if st.alarmOnly && !stt.alarm {
			continue
		}
		r := rates[ip]
		out = append(out, vrow{
			ip:    ip,
			slide: r.RXBytes + r.TXBytes,
			ping:  stt.ping.avg(),
			alarm: stt.alarm,
			lines: watchRowFor(ip, info[ip], r, stt, iv, layout),
		})
	}
	if len(out) == 0 {
		st.cursor = 0
		st.count = 0
		st.currentIP = ""
		return out
	}
	if st.cursor < 0 {
		st.cursor = 0
	}
	if st.cursor > len(out)-1 {
		st.cursor = len(out) - 1
	}
	st.count = len(out)
	st.currentIP = out[st.cursor].ip
	return out
}

// watchRowFor picks the layout band's row renderer.
func watchRowFor(ip string, h hostInfo, r traffic.Rate, st *hostStat, iv, layout int) []string {
	switch layout {
	case layoutCompact:
		return watchRowCompact(ip, h, r, st, iv)
	case layoutWide:
		return watchRowWide(ip, h, r, st, iv)
	default:
		return watchRow(ip, h, r, st, iv)
	}
}

// ipCell paints a host's IP in its stable, per-host hue, padded to width. The
// hue index comes from the hostStat's palette slot, so the same device keeps
// the same colour on every row and every screen.
func ipCell(ip string, hue, width int) string {
	return ux.C(ux.Hue(hue), ux.TruncPad(ip, width))
}

// watchRow renders the fixed three-line block every dashboard host occupies,
// sparse or not. The height never changes — a host with no identity and no
// pings yet still fills all three lines — so rows never make the frame grow
// and shrink between ticks. Line 1 is traffic + latency + health glyph, line
// 2 the identity, line 3 the session health detail.
func watchRow(ip string, h hostInfo, r traffic.Rate, st *hostStat, iv int) []string {
	// The badge column is always reserved so alarming hosts do not shift the
	// rate columns right by a glyph.
	badge := "  "
	if st.alarm {
		badge = ux.C(ux.Red, " ⚠")
	}
	line1 := "  " + ipCell(ip, st.color, 15) + badge + " " +
		ux.TruncPad(rateLine(r.RXBytes, r.RXPkts, iv), 21) + "  " +
		ux.TruncPad(upRateLine(r.TXBytes, r.TXPkts, iv), 21) + "  " +
		pingCell(st) + " " + grade(st)

	line2 := "  "
	if id := identityLine(h); id != "" {
		line2 += id
	} else {
		line2 += ux.C(ux.Dim, "unknown device — no ARP entry")
	}
	line2 = ux.TruncPad(line2, 78)

	inner := statsLine(st, iv)
	line3 := "  " + ux.TruncPad(inner, 66)
	if st.alarm {
		line3 = "  " + ux.C(ux.Red, "⚠ ALARM ·") + " " + ux.TruncPad(inner, 66)
	}
	return []string{line1, line2, line3}
}

// watchRowCompact is the two-line form for terminals under 78 columns: one
// line of traffic + latency, one line of identity + health. Exactly two lines
// no matter how little is known.
func watchRowCompact(ip string, h hostInfo, r traffic.Rate, st *hostStat, iv int) []string {
	badge := " "
	if st.alarm {
		badge = ux.C(ux.Red, "⚠")
	} else {
		badge = ux.C(ux.Dim, "·")
	}
	line1 := "  " + ipCell(ip, st.color, 12) + " " + badge + " " +
		ux.TruncPad(rateLine(r.RXBytes, r.RXPkts, iv), 13) + " " +
		ux.TruncPad(upRateLine(r.TXBytes, r.TXPkts, iv), 13) + " " +
		pingShort(st)

	line2 := "  "
	if id := identityLine(h); id != "" {
		line2 += ux.TruncPad(id, 42)
	} else {
		line2 += ux.C(ux.Dim, "unknown device")
	}
	if p := statsCompact(st, iv); p != "" {
		line2 += "  " + p
	}
	line2 = ux.TruncPad(line2, 76)
	return []string{line1, line2}
}

// watchRowWide is the four-line form for terminals of 116 columns or more:
// the normal traffic line with wider rate cells, identity, the health line
// with p50/p95 latency, and a session-totals line (what the detail pane used
// to hoard, now on every row).
func watchRowWide(ip string, h hostInfo, r traffic.Rate, st *hostStat, iv int) []string {
	badge := "  "
	if st.alarm {
		badge = ux.C(ux.Red, " ⚠")
	}
	line1 := "  " + ipCell(ip, st.color, 15) + badge + " " +
		ux.TruncPad(rateLine(r.RXBytes, r.RXPkts, iv), 24) + "  " +
		ux.TruncPad(upRateLine(r.TXBytes, r.TXPkts, iv), 24) + "  " +
		pingCell(st) + " " + grade(st)

	line2 := "  "
	if id := identityLine(h); id != "" {
		line2 += id
	} else {
		line2 += ux.C(ux.Dim, "unknown device — no ARP entry")
	}
	line2 = ux.TruncPad(line2, 98)

	inner := statsLine(st, iv)
	if p := st.ping; p.count > 0 {
		inner += ux.C(ux.Dim, fmt.Sprintf(" · p50 %dms · p95 %dms", p.pct(50), p.pct(95)))
	}
	line3 := "  " + ux.TruncPad(inner, 98)

	line4 := ux.C(ux.Dim, fmt.Sprintf("  session ↓ %s · ↑ %s · peak ↓ %s · ↑ %s · bytes ↓ %s · ↑ %s",
		ux.HumanRate(bps(st.totRX, iv)), ux.HumanRate(bps(st.totTX, iv)),
		ux.HumanRate(bps(st.peakRX, iv)), ux.HumanRate(bps(st.peakTX, iv)),
		humanBytes(st.totRX), humanBytes(st.totTX)))
	return []string{line1, line2, line3, line4}
}

// statsCompact is the health tail for the compact two-line row.
func statsCompact(st *hostStat, iv int) string {
	p := st.ping
	if p.count+p.drops == 0 {
		return ux.C(ux.Dim, "no pings yet")
	}
	var parts []string
	if p.last < 0 {
		parts = append(parts, ux.C(ux.Red, "last ✗"))
	} else {
		parts = append(parts, fmt.Sprintf("jitter %dms", p.jitter()))
	}
	parts = append(parts, fmt.Sprintf("loss %.0f%%", p.loss()))
	parts = append(parts, fmt.Sprintf("↓ %s", ux.HumanRate(bps(st.totRX, iv))))
	parts = append(parts, fmt.Sprintf("↑ %s", ux.HumanRate(bps(st.totTX, iv))))
	return ux.C(ux.Dim, strings.Join(parts, " · "))
}

// hostRowLines is the transcript variant of a host block (buildLines): the
// fixed three-line sparse form below 9 hosts, one compact line when the LAN
// is big enough that a wall of blocks would drown the output.
func hostRowLines(ip string, h hostInfo, r traffic.Rate, st *hostStat, iv int, dense bool) []string {
	if dense {
		line := "  " + ipCell(ip, st.color, 15)
		if st.alarm {
			line += " " + ux.C(ux.Red, "⚠")
		}
		line += "  " + ux.TruncPad(rateLine(r.RXBytes, r.RXPkts, iv)+"   "+upRateLine(r.TXBytes, r.TXPkts, iv), 40)
		line += "  " + pingShort(st)
		if short := idShort(h); short != "" {
			line += "  " + ux.C(ux.Dim, short)
		}
		return []string{line}
	}
	return watchRow(ip, h, r, st, iv)
}

// pingCell is the fixed-width "ping Nms" cell of line 1 (never overflows:
// "--" for a host nothing has answered yet, "✗" for a host whose last ping
// dropped).
func pingCell(st *hostStat) string {
	if st.ping.count+st.ping.drops == 0 {
		return ux.TruncPad(ux.C(ux.Dim, "ping --"), 11)
	}
	if st.ping.last < 0 {
		return ux.TruncPad(ux.C(ux.Red, "ping ✗"), 11)
	}
	return ux.TruncPad(ux.C(ux.Dim, fmt.Sprintf("ping %dms", st.ping.last)), 11)
}

// grade is the one-glyph health verdict shown on line 1: ·  no samples yet,
// ✓  stable, ~  some loss or jitter, ✗  heavy loss, ⚠  alarming now.
func grade(st *hostStat) string {
	p := st.ping
	if p.count+p.drops == 0 {
		return ux.C(ux.Dim, "·")
	}
	if st.alarm {
		return ux.C(ux.Red, "⚠")
	}
	switch {
	case p.loss() >= 10:
		return ux.C(ux.Red, "✗")
	case p.loss() > 2 || p.jitter() > 30:
		return ux.C(ux.Yellow, "~")
	default:
		return ux.C(ux.Green, "✓")
	}
}

// statsLine is the session health line: jitter (or a red marker when the last
// ping dropped), loss, and the whole-watch average speeds. It is the line
// that tells an operator which device is a good GNULTE test target.
func statsLine(st *hostStat, iv int) string {
	p := st.ping
	if p.count+p.drops == 0 {
		return ux.C(ux.Dim, "no pings yet")
	}
	var parts []string
	if p.last < 0 {
		parts = append(parts, ux.C(ux.Red, "last ✗"))
	} else {
		parts = append(parts, fmt.Sprintf("jitter %dms", p.jitter()))
	}
	parts = append(parts, fmt.Sprintf("loss %.0f%%", p.loss()))
	parts = append(parts, fmt.Sprintf("avg ↓ %s", ux.HumanRate(bps(st.totRX, iv))))
	parts = append(parts, fmt.Sprintf("↑ %s", ux.HumanRate(bps(st.totTX, iv))))
	return ux.C(ux.Dim, strings.Join(parts, " · "))
}

// buildView renders one interactive frame: the screen header, the body for
// the active screen (host rows, ranked talkers, conversation flows, or the
// neighbour table), the session totals, and the key-hint footer. height is
// the terminal height; bodies that do not fit scroll instead of overflowing.
func buildView(st *viewState, hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	flows []traffic.Flow, hostSet map[string]bool, stats map[string]*hostStat,
	env watchEnv, height int) []string {

	const (
		headerH = 4 // rule, status, self/gw, blank
		footerH = 1
		totalH  = 3 // blank, rule, TOTAL
	)
	layout := layoutFor(env.width)
	helpExtra, gcmdExtra := 0, 0
	if st.showHelp {
		helpExtra = 2
	}
	if st.gCmd != "" {
		gcmdExtra = 1
	}
	overhead := headerH + footerH + helpExtra + gcmdExtra + totalH

	out := envHeader(st, hosts, rates, env)

	switch st.screen {
	case scrTalkers:
		out = append(out, talkersLines(hosts, info, rates, stats, flows, hostSet, env, height-overhead)...)
	case scrFlows:
		out = append(out, flowsLines(flows, hostSet, stats, env, height-overhead)...)
	case scrArp:
		out = append(out, arpLines(st, hosts, info, stats, env, height-overhead)...)
	case scrMap:
		out = append(out, mapLines(hosts, info, rates, stats, flows, hostSet, env, height-overhead)...)
	default:
		// ----- host rows, windowed by line budget so the cursor never leaves
		// the screen and the frame never overflows a short terminal -----
		rows := vrows(st, hosts, info, rates, stats, env.iv, layout)
		detailH := 0
		if st.detail && len(rows) > 0 {
			detailH = 11
		}
		budget := height - headerH - footerH - helpExtra - gcmdExtra - detailH - totalH
		top, end := hostSlice(rows, st.cursor, budget)
		if len(rows) == 0 {
			out = append(out, ux.C(ux.Dim, "  no hosts — press a to clear the alarm filter"))
		}
		if top > 0 {
			out = append(out, ux.C(ux.Dim, fmt.Sprintf("  ▴ %d more…", top)))
		}
		for i := top; i < end; i++ {
			vr := rows[i]
			lines := vr.lines
			if i == st.cursor && len(lines) > 0 {
				lines = cursorLines(lines)
			}
			out = append(out, lines...)
		}
		if end < len(rows) {
			out = append(out, ux.C(ux.Dim, fmt.Sprintf("  ▾ %d more…", len(rows)-end)))
		}

		// ----- detail pane for the cursor host -----
		if st.detail && len(rows) > 0 {
			ci := ux.Clamp(st.cursor, 0, len(rows)-1)
			cip := rows[ci].ip
			out = append(out, detailLines(cip, info[cip], stats[cip], rates[cip],
				flows, hostSet, env.iv, netTotals(hosts, rates))...)
		}
	}

	// ----- session totals (all screens) -----
	tot := netTotals(hosts, rates)
	out = append(out, "", ux.C(ux.Dim, "  "+strings.Repeat("─", 40)))
	out = append(out, fmt.Sprintf("  %-17s %s",
		ux.C(ux.Bold, "TOTAL"), ux.TruncPad(rateLine(tot.rx, tot.rxp, env.iv)+"    "+upRateLine(tot.tx, tot.txp, env.iv), 46)))

	// ----- footer hints -----
	out = append(out, "  "+ux.C(ux.Dim, footerHint(st)))
	if st.gCmd != "" {
		out = append(out, "  "+ux.C(ux.Bold+ux.Green, "⬢ "+st.gCmd))
	}
	if st.showHelp {
		out = append(out, ux.C(ux.Dim, "  1 hosts · 2 talkers (ranked ↓/↑ + whom each talks to) · 3 flows (pairs, root socket)"))
		out = append(out, ux.C(ux.Dim, "  4 ARP neighbours · 5 map (interconnection, root socket) · s sort · ⏎ test with gnulte · Tab/d detail · x save devices"))
	}
	// Hard guarantee: never draw taller than the terminal (a very short TTY
	// with every pane open can exhaust even the packed budget).
	if len(out) > height {
		out = out[:height]
	}
	return out
}

// netTotals sums the whole watched set's rates for the session-total line and
// the header's net figures.
type netTotal struct {
	rx, tx, rxp, txp int64
}

func netTotals(hosts []string, rates map[string]traffic.Rate) netTotal {
	var t netTotal
	for _, ip := range hosts {
		r := rates[ip]
		t.rx += r.RXBytes
		t.tx += r.TXBytes
		t.rxp += r.RXPkts
		t.txp += r.TXPkts
	}
	return t
}

// envHeader emits the screen header: rule, status, self/gateway lines and the
// blank spacer. The status line carries the screen tag, the host count, the
// LAN-wide net rate and the gateway's RTT context.
func envHeader(st *viewState, hosts []string, rates map[string]traffic.Rate, env watchEnv) []string {
	ruleTxt := "  ── " + env.nic
	if env.subnet != "" {
		ruleTxt += " · " + env.subnet
	}
	ruleTxt += " " + strings.Repeat("─", 22)
	out := []string{ux.C(ux.Cyan, ruleTxt)}

	status := "  " + ux.C(ux.Bold+ux.Header, "LIVE LAN WATCH") +
		ux.C(ux.Dim, " · "+screenLabel(st.screen)) +
		ux.C(ux.Dim, fmt.Sprintf("   every %ds · %d host%s · %s · sort %s · %d up",
			env.iv, len(hosts), plural(len(hosts)), watchMode(st.auto), st.sortName(), env.up))
	if env.hasCounter {
		t := netTotals(hosts, rates)
		status += ux.C(ux.Dim, fmt.Sprintf(" · net ↓ %s ↑ %s",
			ux.HumanRate(bps(t.rx, env.iv)), ux.HumanRate(bps(t.tx, env.iv))))
	} else {
		status += ux.C(ux.Yellow, "  ¡ speeds-free")
	}
	status += ux.C(ux.Dim, "  "+elapsed(env.start))
	if env.alarmOn {
		status += ux.C(ux.Red, "  ⚠")
	}
	out = append(out, status)

	gw := "  self " + ux.C(ux.Header, env.selfIP)
	if env.gwIP != "" {
		gw += ux.C(ux.Dim, " · gw ") + ux.C(ux.Target, env.gwIP) + " " + gwCell(env.gwRTT)
	}
	out = append(out, gw)
	out = append(out, "")
	return out
}

func watchMode(auto bool) string {
	if auto {
		return "LAN watch"
	}
	return "watched set"
}

// gateLines is the "this screen needs the root capture socket" placeholder —
// the sudo-gated sections explain themselves instead of rendering an empty
// table.
func gateLines(name, why string) []string {
	return []string{
		"  " + ux.C(ux.Bold, name) + ux.C(ux.Red, "  ⛔ needs the capture socket (root)"),
		"",
		"  " + ux.C(ux.Dim, why),
		"",
		"  " + ux.C(ux.Green, "  re-run with: sudo gnulte-lan"),
		"  " + ux.C(ux.Dim, "  (the watch auto-elevates via sudo — a socket here means root is live)"),
		"",
		ux.C(ux.Dim, "  meanwhile the HOSTS screen still shows latency, identity and alarms."),
	}
}

// talkersLines is screen 2: every watched host ranked by its combined rate
// this interval, with a down/up bar split and its peer count, followed by the
// "communicators" block — the LAN-internal conversation pairs (who talks to
// whom without leaving the subnet).
func talkersLines(hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	stats map[string]*hostStat, flows []traffic.Flow, hostSet map[string]bool,
	env watchEnv, budget int) []string {

	out := []string{
		"  " + ux.C(ux.Bold, "TOP TALKERS") + ux.C(ux.Dim, "  by combined rate this interval · bars scale to the busiest host · peers = hosts talked to"),
	}
	type tk struct {
		ip   string
		rx   int64
		tx   int64
		tot  int64
		peers int
	}
	var list []tk
	var maxR int64
	for _, ip := range hosts {
		r := rates[ip]
		tkt := tk{ip: ip, rx: r.RXBytes, tx: r.TXBytes, tot: r.RXBytes + r.TXBytes}
		for _, f := range flows {
			if hostSet[endpointHost(f.A)] && endpointHost(f.A) == ip ||
				hostSet[endpointHost(f.B)] && endpointHost(f.B) == ip {
				tkt.peers++
			}
		}
		if tkt.tot > maxR {
			maxR = tkt.tot
		}
		list = append(list, tkt)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].tot != list[j].tot {
			return list[i].tot > list[j].tot
		}
		return list[i].ip < list[j].ip
	})
	busy := 0
	for _, t := range list {
		if t.tot > 0 {
			busy++
		}
	}
	if busy == 0 {
		out = append(out, ux.C(ux.Dim, "  no traffic this interval — every host quiet"))
		out = append(out, ux.C(ux.Dim, "  (rates need the root capture socket; pings and identity still show on screen 1)"))
		return out
	}

	showBars := env.width >= 96
	for i, t := range list {
		if len(out) >= budget {
			out = append(out, ux.C(ux.Dim, fmt.Sprintf("  ▾ %d more…", len(list)-i)))
			break
		}
		line := fmt.Sprintf("  %2d  %s %s", i+1, ipCell(t.ip, stats[t.ip].color, 15), ux.TruncPad(ux.C(ux.Dim, nameOf(info[t.ip])), 18))
		dl := ux.C(ux.Dim, "↓ "+ux.HumanRate(bps(t.rx, env.iv)))
		ul := ux.C(ux.Dim, "↑ "+ux.HumanRate(bps(t.tx, env.iv)))
		if showBars {
			line += "  " + ux.TruncPad(dl, 12) + " " + bar(t.rx, maxR, 6) +
				"  " + ux.TruncPad(ul, 12) + " " + bar(t.tx, maxR, 6)
		} else {
			line += "  " + ux.TruncPad(dl, 15) + "  " + ux.TruncPad(ul, 15)
		}
		line += ux.C(ux.Dim, fmt.Sprintf("  peers %d", t.peers))
		out = append(out, line)
	}

	// Communicators: LAN-internal pairs — both ends on the watched subnet.
	var internal []traffic.Flow
	for _, f := range flows {
		if lanPair(f.A, f.B, env.subnet) {
			internal = append(internal, f)
		}
	}
	if len(internal) > 0 {
		sort.Slice(internal, func(i, j int) bool { return internal[i].Total() > internal[j].Total() })
		out = append(out, "", "  "+ux.C(ux.Bold, "COMMUNICATORS")+ux.C(ux.Dim, "  LAN-internal pairs that never leave "+env.subnet))
		shown := 0
		for _, f := range internal {
			if len(out) >= budget {
				out = append(out, ux.C(ux.Dim, fmt.Sprintf("  ▾ %d more pairs…", len(internal)-shown)))
				break
			}
			out = append(out, pairLine(f, hostSet, stats, env))
			shown++
		}
	}
	if len(out) == 1 {
		out = append(out, ux.C(ux.Dim, "  no traffic yet"))
	}
	return out
}

// pairLine is one conversation row for the flows/communicators tables:
// A ⇄ B with per-direction rates and a ⟷LAN tag for internal pairs.
func pairLine(f traffic.Flow, hostSet map[string]bool, stats map[string]*hostStat, env watchEnv) string {
	hue := func(e string) int {
		if s := stats[endpointHost(e)]; s != nil {
			return s.color
		}
		return 0
	}
	at := endpointTxt(f.A, hostSet[endpointHost(f.A)], hue(f.A))
	bt := endpointTxt(f.B, hostSet[endpointHost(f.B)], hue(f.B))
	tag := ""
	if lanPair(f.A, f.B, env.subnet) {
		tag = ux.C(ux.Cyan, " ⟷LAN")
	}
	line := "  " + at + " ⇄ " + bt + tag +
		ux.C(ux.Dim, "  A→B ") + ux.TruncPad(ux.C(ux.Dim, ux.HumanRate(bps(f.AB, env.iv))), 11) +
		ux.C(ux.Dim, " B→A ") + ux.TruncPad(ux.C(ux.Dim, ux.HumanRate(bps(f.BA, env.iv))), 11)
	return line
}

// endpointTxt names one flow endpoint as "ip:port", truncated to width and
// painted in the host's hue when it is a watched host (dim otherwise).
func endpointTxt(e string, watched bool, hue int) string {
	t := ux.TruncPad(e, 17)
	if watched {
		return ux.C(ux.Hue(hue), t)
	}
	return ux.C(ux.Dim, t)
}

// flowsLines is screen 3: the per-conversation table. Byte-accurate pair
// attribution comes from the raw capture socket, so without it (speeds-free
// run) the screen explains the sudo requirement instead of guessing.
func flowsLines(flows []traffic.Flow, hostSet map[string]bool, stats map[string]*hostStat,
	env watchEnv, budget int) []string {

	if !env.hasCounter {
		return gateLines("FLOWS",
			"per-conversation byte attribution needs the raw AF_PACKET socket, which is not open here.")
	}
	out := []string{
		"  " + ux.C(ux.Bold, "FLOWS") + ux.C(ux.Dim, "  conversations this interval · biggest pair first · ⟷LAN = both ends on "+env.subnet),
	}
	srt := append([]traffic.Flow(nil), flows...)
	sort.Slice(srt, func(i, j int) bool { return srt[i].Total() > srt[j].Total() })
	if len(srt) == 0 {
		out = append(out, ux.C(ux.Dim, "  no conversations this interval — quiet LAN"))
		return out
	}
	for i, f := range srt {
		if len(out) >= budget {
			out = append(out, ux.C(ux.Dim, fmt.Sprintf("  ▾ %d more conversations…", len(srt)-i)))
			break
		}
		out = append(out, pairLine(f, hostSet, stats, env))
	}
	return out
}

// mapLines is screen 5: the Live Interconnection map. The gateway is the hub,
// this machine is the second node, every watched device is a node card, and
// the pairs seen this interval are the edges — the busiest one pulses. The
// edges come from the raw capture socket, so without it the screen gates
// exactly like FLOWS.
func mapLines(hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	stats map[string]*hostStat, flows []traffic.Flow, hostSet map[string]bool,
	env watchEnv, budget int) []string {

	if !env.hasCounter {
		return gateLines("MAP",
			"live edges need the raw AF_PACKET socket, which is not open here — the map shows who talks to whom via live flows.")
	}
	out := []string{
		"  " + ux.C(ux.Bold, "INTERCONNECTION MAP") + ux.C(ux.Dim, "  every device a node · every live pair an edge · ▸ pulses the busiest link"),
		"",
	}

	// Hub cards: the gateway and this machine.
	gwTxt, gwName := "◇ " + ux.C(ux.Yellow, "no gateway"), " (none detected)"
	if env.gwIP != "" {
		gwTxt = "  ◇ " + ux.C(ux.Yellow, env.gwIP)
		gwName = " " + gwCell(env.gwRTT)
		if mac := env.neigh[env.gwIP]; mac != "" {
			if v := discover.VendorFor(mac); v != "" {
				gwName = " · " + v + gwName
			}
		}
	}
	out = append(out, gwTxt+ux.C(ux.Dim, gwName))
	out = append(out, "  ◉ "+ux.C(ux.Cyan, env.selfIP)+ux.C(ux.Dim, "  · this machine ("+env.nic+")"))
	out = append(out, "  "+ux.C(ux.Dim, "┃"))
	out = append(out, "  "+ux.C(ux.Dim, "┌──┼──┐   every device below reaches the net through the gateway"))

	// Node cloud: watched devices, hue-coloured exactly like the other screens.
	nodes := mapNodes(hosts, info, stats, env)
	out = append(out, "  "+ux.C(ux.Dim, "devices (hue = the same per-device colour as every screen)"))
	grid := mapGrid(nodes, env)
	for _, line := range grid {
		if len(out) >= budget {
			out = append(out, ux.C(ux.Dim, "  ▾ more devices below — resize the terminal"))
			return capMap(out, budget)
		}
		out = append(out, line)
	}

	// Edges: this interval's pairs that stay inside the map's own world.
	var edges []traffic.Flow
	for _, f := range flows {
		if mapEndpHost(f.A, hostSet, env) && mapEndpHost(f.B, hostSet, env) {
			edges = append(edges, f)
		}
	}
	out = append(out, "")
	out = append(out, "  "+ux.C(ux.Bold, "LIVE EDGES")+ux.C(ux.Dim, fmt.Sprintf("  %d pair(s) this interval · edge = A ⇄ B ↓ rate ↑ rate", len(edges))))
	if len(edges) == 0 {
		out = append(out, ux.C(ux.Dim, "  no live pairs this interval — the map is quiet"))
	} else {
		for _, line := range mapLinks(edges, stats, env) {
			if len(out) >= budget {
				out = append(out, ux.C(ux.Dim, "  ▾ more edges below — resize the terminal"))
				break
			}
			out = append(out, line)
		}
	}
	return capMap(out, budget)
}

// capMap guarantees the map body never exceeds its line budget.
func capMap(out []string, budget int) []string {
	if budget < 1 {
		return nil
	}
	if len(out) > budget {
		out = append(out[:budget-1], ux.C(ux.Dim, "  ▾ cut — resize the terminal to see the rest"))
	}
	return out
}

// mapNode is one device card on the map screen.
type mapNode struct {
	ip   string
	name string
	hue  int
}

// mapNodes builds the node set: every watched host except this machine and the
// gateway (which have their own hub cards), in IP order.
func mapNodes(hosts []string, info map[string]hostInfo, stats map[string]*hostStat, env watchEnv) []mapNode {
	var nodes []mapNode
	for _, ip := range hosts {
		if ip == env.selfIP || (env.gwIP != "" && ip == env.gwIP) {
			continue
		}
		name := nameOf(info[ip])
		if name == "" {
			name = "(no identity)"
		}
		nodes = append(nodes, mapNode{ip: ip, name: name, hue: stats[ip].color})
	}
	sort.Slice(nodes, func(i, j int) bool { return ipLess(nodes[i].ip, nodes[j].ip) })
	return nodes
}

// mapGrid lays the node cards out in width-scaled columns: one on narrow
// terminals, two on a normal window, three when wide. Every column card is
// exactly as tall as its mates, so the grid always forms clean rows.
func mapGrid(nodes []mapNode, env watchEnv) []string {
	cols := 1
	if env.width >= 116 {
		cols = 3
	} else if env.width >= 78 {
		cols = 2
	}
	if len(nodes) < cols {
		cols = len(nodes)
	}
	if cols <= 0 {
		return nil
	}
	compact := cols == 1 && env.width < 78
	// One card line each on compact terminals, two otherwise.
	all := make([][]string, 0, len(nodes))
	for _, n := range nodes {
		glyph := ux.C(ux.Hue(n.hue), "●")
		if compact {
			all = append(all, []string{"  " + glyph + " " + ux.C(ux.Hue(n.hue), ux.TruncPad(n.ip, 15)) + ux.C(ux.Dim, " · "+ux.TruncPad(n.name, 40))})
			continue
		}
		all = append(all, []string{
			"  " + glyph + " " + ux.C(ux.Hue(n.hue), ux.TruncPad(n.ip, 15)),
			"    " + ux.C(ux.Dim, ux.TruncPad(n.name, 16)),
		})
	}
	var out []string
	for r := 0; r < len(all); r += cols {
		chunk := all[r : r+min(cols, len(all)-r)]
		rows := 1
		if !compact {
			rows = 2
		}
		for i := 0; i < rows; i++ {
			var line string
			for c, card := range chunk {
				if c > 0 {
					line += "   "
				}
				if i < len(card) {
					line += card[i]
				}
			}
			out = append(out, line)
		}
	}
	return out
}

// mapLinks renders the top live pairs as the map's edge list, with a pulse
// marker on the busiest one when pulse is set.
func mapLinks(edges []traffic.Flow, stats map[string]*hostStat, env watchEnv) []string {
	srt := append([]traffic.Flow(nil), edges...)
	sort.Slice(srt, func(i, j int) bool { return srt[i].Total() > srt[j].Total() })
	maxLinks := 6
	if env.width < 116 {
		maxLinks = 4
	}
	if env.width < 78 {
		maxLinks = 3
	}
	var out []string
	for i, f := range srt {
		if i >= maxLinks {
			break
		}
		mark := "  "
		if i == 0 && env.pulse {
			mark = ux.C(ux.Cyan, "▸ ")
		}
		line := mark + ipCell(endpointHost(f.A), flowHue(stats, f.A), 15) +
			ux.C(ux.Dim, " ⇄ ") + ipCell(endpointHost(f.B), flowHue(stats, f.B), 15) +
			ux.C(ux.Dim, "  ↓ ") + ux.TruncPad(ux.C(ux.Dim, ux.HumanRate(bps(f.AB, env.iv))), 11) +
			ux.C(ux.Dim, " ↑ ") + ux.TruncPad(ux.C(ux.Dim, ux.HumanRate(bps(f.BA, env.iv))), 11)
		out = append(out, line)
	}
	return out
}

// flowHue looks the endpoint host's palette slot up, for the edge list — the
// same colour the host's node card wears.
func flowHue(stats map[string]*hostStat, e string) int {
	if s := stats[endpointHost(e)]; s != nil {
		return s.color
	}
	return 0
}

// mapEndpHost reports whether a flow endpoint is a node the map draws: this
// machine, the gateway, or a watched host.
func mapEndpHost(e string, hostSet map[string]bool, env watchEnv) bool {
	ip := endpointHost(e)
	return ip == env.selfIP || (env.gwIP != "" && ip == env.gwIP) || hostSet[ip]
}

// arpLines is screen 4: the neighbour table from /proc/net/arp, refreshed
// live. Every known MAC gets its vendor and (when it is a watched host) its
// live ping and health grade; the router and this machine appear too, dimmed.
func arpLines(st *viewState, hosts []string, info map[string]hostInfo,
	stats map[string]*hostStat, env watchEnv, budget int) []string {

	out := []string{
		"  " + ux.C(ux.Bold, "NEIGHBOURS") + ux.C(ux.Dim, "  /proc/net/arp · refreshed live · MAC · vendor · type · ping"),
	}
	keys := map[string]bool{}
	for ip := range env.neigh {
		keys[ip] = true
	}
	for _, ip := range hosts {
		keys[ip] = true
	}
	sorted := make([]string, 0, len(keys))
	for ip := range keys {
		sorted = append(sorted, ip)
	}
	sort.Slice(sorted, func(i, j int) bool { return ipLess(sorted[i], sorted[j]) })
	if len(sorted) == 0 {
		out = append(out, ux.C(ux.Dim, "  empty neighbour table — nothing on the link yet"))
		return out
	}
	for i, ip := range sorted {
		if len(out) >= budget {
			out = append(out, ux.C(ux.Dim, fmt.Sprintf("  ▾ %d more neighbours…", len(sorted)-i)))
			break
		}
		known := stats[ip] != nil
		h := info[ip]
		mac := env.neigh[ip]
		vendor := ""
		if mac != "" {
			vendor = discover.VendorFor(mac)
		}
		var ipTxt string
		if known {
			ipTxt = ipCell(ip, stats[ip].color, 15)
		} else {
			ipTxt = ux.C(ux.Dim, ux.TruncPad(ip, 15))
		}
		line := "  " + ipTxt + "  " + ux.TruncPad(ux.C(ux.Dim, mac), 17) + " " +
			ux.TruncPad(ux.C(ux.Dim, vendor), 16) + " " +
			ux.TruncPad(ux.C(ux.Dim, h.Type), 10) + " "
		if known && h.Host != "" {
			line += ux.TruncPad(ux.C(ux.Dim, h.Host), 14) + "  "
		} else {
			line += ux.TruncPad("", 14) + "  "
		}
		if known {
			line += pingCell(stats[ip]) + " " + grade(stats[ip])
		} else {
			line += ux.TruncPad(ux.C(ux.Dim, "no ping watch"), 11)
		}
		out = append(out, ux.TruncPad(line, 104))
	}
	if !env.hasCounter {
		out = append(out, ux.C(ux.Dim, "  byte-level ↓/↑ for these neighbours needs the capture socket (screen 3)"))
	}
	return out
}

// footerHint is the one-line key legend for the active screen.
func footerHint(st *viewState) string {
	switch st.screen {
	case scrTalkers:
		return "  talkers · 1/3/4/5 screens · ↑↓ host · ⏎ gnulte · Tab/d detail · x save · q quit"
	case scrFlows:
		return "  flows · 1/2/4/5 screens · ↑↓ host · ⏎ gnulte · Tab/d detail · x save · q quit"
	case scrArp:
		return "  neighbours · 1/2/3/5 screens · ↑↓ host · ⏎ gnulte · Tab/d detail · x save · q quit"
	case scrMap:
		return "  map · 1/2/3/4 screens · live edges pulsing · x save devices · h help · q quit"
	default:
		return "  ↑↓ host · ⏎ test with gnulte · Tab/d detail · s sort · a alarm-only · 2-5 screens · x save devices · o settings · h help · q quit"
	}
}

func nameOf(h hostInfo) string {
	if h.Host != "" {
		return h.Host
	}
	if h.Type != "" {
		return h.Type
	}
	if h.Vendor != "" {
		return h.Vendor
	}
	return ""
}

// lanPair reports whether both ends of a conversation fall inside the watched
// subnet — i.e. it is a LAN-internal "communicator" pair.
func lanPair(a, b, subnet string) bool {
	if subnet == "" {
		return false
	}
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return false
	}
	ia := net.ParseIP(endpointHost(a))
	ib := net.ParseIP(endpointHost(b))
	return ia != nil && ib != nil && n.Contains(ia) && n.Contains(ib)
}

// gwCell renders the gateway's last RTT: "--" before the first sample, "✗"
// after a failed ping, the green RTT otherwise.
func gwCell(rtt int) string {
	switch rtt {
	case -2:
		return ux.C(ux.Dim, "↔ --")
	case -1:
		return ux.C(ux.Red, "↔ ✗")
	default:
		return ux.C(ux.Green, "↔ "+fmt.Sprintf("%dms", rtt))
	}
}

// hostSlice picks the [start,end) host rows that fit inside the line budget,
// always including the cursor row. It anchors on the cursor and pulls context
// rows in front of it while the budget allows, so the cursor keeps its place
// and short terminals simply show fewer rows instead of a taller frame.
func hostSlice(rows []vrow, cursor, budget int) (start, end int) {
	n := len(rows)
	if n == 0 {
		return 0, 0
	}
	if budget < 1 {
		budget = 1
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= n {
		cursor = n - 1
	}
	// Pack forward from the cursor.
	used := 0
	end = cursor
	for end < n && used+len(rows[end].lines) <= budget {
		used += len(rows[end].lines)
		end++
	}
	// Pull context in front of the cursor while lines remain.
	start = cursor
	for start > 0 {
		if used+len(rows[start-1].lines) > budget {
			break
		}
		used += len(rows[start-1].lines)
		start--
	}
	// The cursor row itself always fits (its first line is shown even when the
	// whole row is taller than the budget).
	if start == end {
		start = cursor
		end = cursor + 1
	}
	return start, end
}

// cursorLines marks the selected host's first line with the arrow marker.
func cursorLines(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	out := make([]string, len(lines))
	copy(out, lines)
	first := out[0]
	switch {
	case strings.HasPrefix(first, "  "):
		first = "▸ " + first[2:]
	case strings.HasPrefix(first, " "):
		first = "▸ " + first[1:]
	default:
		first = "▸ " + first
	}
	out[0] = first
	return out
}

// detailLines renders the selected host's information pane: identity, rates,
// session averages, health verdict, latency history with percentiles, the
// exact gnulte command that would test it, and the flows it is involved in.
func detailLines(ip string, h hostInfo, st *hostStat, r traffic.Rate,
	flows []traffic.Flow, hostSet map[string]bool, iv int, tot netTotal) []string {

	head := "  ── " + ux.C(ux.Bold, "DETAIL · "+ipCell(ip, st.color, 0))
	if h.Host != "" {
		head += ux.C(ux.Dim, "  ("+h.Host+")")
	}
	head += ux.C(ux.Cyan, " ─"+strings.Repeat("─", 26))
	out := []string{head}

	id := identityLine(h)
	switch {
	case id == "":
		out = append(out, "     "+ux.C(ux.Dim, "no identity — ARP entry not found"))
	default:
		out = append(out, "     "+id)
	}

	dl := ux.TruncPad(rateLine(r.RXBytes, r.RXPkts, iv), 24)
	ul := ux.TruncPad(upRateLine(r.TXBytes, r.TXPkts, iv), 24)
	peak := fmt.Sprintf("peak ↓ %s · ↑ %s", ux.HumanRate(bps(st.peakRX, iv)), ux.HumanRate(bps(st.peakTX, iv)))
	avg := fmt.Sprintf("session avg ↓ %s · ↑ %s", ux.HumanRate(bps(st.totRX, iv)), ux.HumanRate(bps(st.totTX, iv)))
	out = append(out, "     "+ux.TruncPad(dl+"  "+ul, 50)+ux.C(ux.Dim, peak))
	out = append(out, "     "+ux.C(ux.Dim, avg))

	// The host's share of this interval's LAN traffic.
	if tot.rx+tot.tx > 0 && st.totRX+st.totTX > 0 {
		share := fmt.Sprintf("share of net ↓ %.0f%% · ↑ %.0f%%",
			float64(st.totRX)*100/float64(tot.rx+tot.tx),
			float64(st.totTX)*100/float64(tot.rx+tot.tx))
		out = append(out, "     "+ux.C(ux.Dim, share))
	}

	// Health verdict: is this device a sensible GNULTE test target right now?
	out = append(out, "     "+grade(st)+" "+healthText(st))

	// Latency line + three history sparklines from the same bounded window.
	lastS := fmt.Sprintf("%dms", st.ping.last)
	if st.ping.last < 0 {
		lastS = "✗"
	}
	pl := fmt.Sprintf("ping last %s · avg %dms · p50 %dms · p95 %dms · min %dms · max %dms · loss %.0f%% · jitter %dms",
		lastS, st.ping.avg(), st.ping.pct(50), st.ping.pct(95), st.ping.min, st.ping.max, st.ping.loss(), st.ping.jitter())
	out = append(out, "     "+ux.C(ux.Dim, pl))
	spk := "  latency " + ux.C(ux.Cyan, ux.SparkRTT(st.ping.samples, 26))
	spk += "   ↓ " + ux.C(ux.Cyan, sparkRates(st.rxHist, 12))
	spk += "   ↑ " + ux.C(ux.Cyan, sparkRates(st.txHist, 12))
	out = append(out, spk)

	// The one-command recipe for testing this host with GNULTE.
	out = append(out, "     "+ux.C(ux.Bold+ux.Green, "test with: gnulte -t "+ip))

	// The flows this host is part of this interval, biggest first.
	var mine []traffic.Flow
	for _, f := range flows {
		if hostSet[endpointHost(f.A)] && endpointHost(f.A) == ip ||
			hostSet[endpointHost(f.B)] && endpointHost(f.B) == ip {
			mine = append(mine, f)
		}
	}
	if len(mine) == 0 && len(flows) > 0 {
		out = append(out, "     "+ux.C(ux.Dim, "no traffic involving this host this interval"))
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Total() > mine[j].Total() })
	n := 3
	if len(mine) < n {
		n = len(mine)
	}
	for _, f := range mine[:n] {
		out = append(out, flowLine(f, hostSet, iv))
	}
	return out
}

// healthText is the plain-language pair of the grade glyph.
func healthText(st *hostStat) string {
	p := st.ping
	if p.count+p.drops == 0 {
		return ux.C(ux.Dim, "no pings yet — wait for the next interval")
	}
	switch {
	case st.alarm:
		return ux.C(ux.Red, "over an alarm threshold — check this one")
	case p.loss() >= 10:
		return ux.C(ux.Red, "flaky — heavy loss, poor test target")
	case p.jitter() > 30:
		return ux.C(ux.Yellow, "jittery — latency swings, retest before trusting")
	case p.loss() > 2:
		return ux.C(ux.Yellow, "some loss — watch it a bit longer")
	default:
		return ux.C(ux.Green, "stable — a good GNULTE test target")
	}
}

// bar renders one host's rate as a short horizontal bar scaled to the busiest
// host in the list, using the eight block levels. Cells the value fully
// covers are solid █; the cell the value lands in is partially filled; the
// rest stay blank, so bars fill left to right like iftop.
func bar(v, max int64, width int) string {
	if width <= 0 || max <= 0 {
		return ""
	}
	runes := []rune("▁▂▃▄▅▆▇█")
	out := make([]rune, width)
	frac := float64(v) / float64(max)
	for i := 0; i < width; i++ {
		lo := float64(i) / float64(width)
		hi := float64(i+1) / float64(width)
		switch {
		case frac >= hi:
			out[i] = runes[7] // fully covered cell
		case frac <= lo:
			out[i] = ' '
		default:
			level := int((frac-lo)/(hi-lo)*8 + 0.5)
			if level < 1 {
				level = 1
			}
			if level > 8 {
				level = 8
			}
			out[i] = runes[level-1]
		}
	}
	return string(out)
}

// sparkRates maps a bounded byte-rate history to block levels, scaled so the
// largest sample in the window saturates at █ (SparkRTT is absolute; this one
// is relative, which reads better for rate bursts).
func sparkRates(hist []int64, width int) string {
	if width <= 0 || len(hist) == 0 {
		return ""
	}
	start := 0
	if len(hist) > width {
		start = len(hist) - width
	}
	var max int64
	for _, v := range hist[start:] {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		return strings.Repeat("▁", len(hist)-start)
	}
	var b strings.Builder
	for _, v := range hist[start:] {
		if v <= 0 {
			b.WriteRune('▁')
			continue
		}
		lvl := int(7 * v / max)
		if lvl < 1 {
			lvl = 1
		}
		b.WriteRune([]rune("▂▃▄▅▆▇█")[lvl-1])
	}
	return b.String()
}

// elapsed formats the running time as MM:SS.
func elapsed(start time.Time) string {
	d := time.Since(start)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", m, s)
}

// plural appends "s" unless n == 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}