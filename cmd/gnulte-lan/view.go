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
	"sort"
	"strings"
	"time"

	"gnulte-go/internal/traffic"
	"gnulte-go/internal/ux"
)

// The interactive watch view (tui.Screen): cursor, ordering, panes. It lives
// on the alternate screen when stdin/stdout are a live terminal; piped and
// -q runs keep the classic buildLines transcript instead.

// viewState is everything the operator can change while the watch runs:
// which host the cursor sits on, how rows are ordered, whether the detail /
// talkers / help panes are visible, and whether only alarming hosts are shown.
type viewState struct {
	cursor    int  // index into the current (filtered, sorted) row order
	sortMode  int  // sortAddr, sortTraffic or sortPing
	alarmOnly bool // hide hosts that are not alarming
	detail    bool // host detail pane open, for the cursor host
	showTalk  bool // global top-talkers pane
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
// the gateway's last latency, and the aggregate flags.
type watchEnv struct {
	nic, subnet string
	selfIP      string
	gwIP        string
	gwRTT       int // gateway RTT ms: -2 not tried yet, -1 last attempt failed
	iv          int
	start       time.Time
	up          int // hosts with at least one successful ping
	alarmOn     bool
	hasCounter  bool
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
// clamps cursor and scroll into range. Every row is exactly three lines (see
// watchRow), so the frame height is stable no matter how much — or how
// little — is known about a host.
func vrows(st *viewState, hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	stats map[string]*hostStat, iv int) []vrow {

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
			lines: watchRow(ip, info[ip], r, stt, iv),
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
	line1 := "  " + ux.C(ux.Yellow, ux.TruncPad(ip, 15)) + badge + " " +
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

// hostRowLines is the transcript variant of a host block (buildLines): the
// fixed three-line sparse form below 9 hosts, one compact line when the LAN
// is big enough that a wall of blocks would drown the output.
func hostRowLines(ip string, h hostInfo, r traffic.Rate, st *hostStat, iv int, dense bool) []string {
	if dense {
		line := "  " + ux.C(ux.Yellow, ux.TruncPad(ip, 15))
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

// buildView renders one interactive frame: header strip, the host rows
// scrolled so the cursor stays visible, the detail pane, the top-talkers
// pane, totals, and the key-hint footer. height is the terminal height; rows
// that do not fit scroll instead of overflowing.
func buildView(st *viewState, hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	flows []traffic.Flow, hostSet map[string]bool, stats map[string]*hostStat,
	env watchEnv, height int) []string {

	const (
		headerH = 4 // rule, status, self/gw, blank
		footerH = 1
		totalH  = 3 // rule, TOTAL, blank spacer
	)
	footerExtra := 0
	if st.showHelp {
		footerExtra = 2
	}
	talkH, detailH := paneHeights(st, flows)

	rows := vrows(st, hosts, info, rates, stats, env.iv)
	mode := "watched set"
	if st.auto {
		mode = "LAN watch"
	}

	out := make([]string, 0, height)

	// ----- header: rule, status line, self/gateway line, blank -----
	ruleTxt := "  ── " + env.nic
	if env.subnet != "" {
		ruleTxt += " · " + env.subnet
	}
	ruleTxt += " " + strings.Repeat("─", 22)
	out = append(out, ux.C(ux.Cyan, ruleTxt))
	status := "  " + ux.C(ux.Bold+ux.Header, "LIVE LAN WATCH") +
		ux.C(ux.Dim, fmt.Sprintf("   every %ds · %d host%s · %s · sort %s · %d up",
			env.iv, len(hosts), plural(len(hosts)), mode, st.sortName(), env.up))
	status += ux.C(ux.Dim, "  "+elapsed(env.start))
	if env.alarmOn {
		status += ux.C(ux.Red, "  ⚠")
	}
	if !env.hasCounter {
		status += ux.C(ux.Yellow, "  ¡ speeds-free")
	}
	out = append(out, status)
	gw := "  self " + ux.C(ux.Header, env.selfIP)
	if env.gwIP != "" {
		gw += ux.C(ux.Dim, " · gw ") + ux.C(ux.Target, env.gwIP) + " " + gwCell(env.gwRTT)
	}
	out = append(out, gw)
	out = append(out, "")

	// ----- host rows, windowed by line budget so the cursor never leaves the
	// screen and the frame never overflows a short terminal -----
	budget := height - headerH - footerH - footerExtra - talkH - detailH - totalH
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
		out = append(out, detailLines(cip, info[cip], stats[cip], rates[cip], flows, hostSet, env.iv)...)
	}

	// ----- global top talkers of this interval -----
	if st.showTalk && len(flows) > 0 {
		out = append(out, "", ux.C(ux.Bold, "  TOP TALKERS")+ux.C(ux.Dim, "  this interval · bold = watched host"))
		n := 5
		if len(flows) < n {
			n = len(flows)
		}
		sort.Slice(flows, func(i, j int) bool { return flows[i].Total() > flows[j].Total() })
		for _, f := range flows[:n] {
			out = append(out, flowLine(f, hostSet, env.iv))
		}
	}

	// ----- session totals -----
	var totRX, totTX, totRXp, totTXp int64
	for _, ip := range hosts {
		r := rates[ip]
		totRX += r.RXBytes
		totTX += r.TXBytes
		totRXp += r.RXPkts
		totTXp += r.TXPkts
	}
	out = append(out, "", ux.C(ux.Dim, "  "+strings.Repeat("─", 40)))
	out = append(out, fmt.Sprintf("  %-17s %s",
		ux.C(ux.Bold, "TOTAL"), ux.TruncPad(rateLine(totRX, totRXp, env.iv)+"    "+upRateLine(totTX, totTXp, env.iv), 46)))

	// ----- footer hints -----
	out = append(out, "  "+ux.C(ux.Dim, "↑↓ host · ⏎ detail · s sort · t talkers · a alarm-only · o settings · g test cmd · h help · q quit"))
	if st.gCmd != "" {
		out = append(out, "  "+ux.C(ux.Bold+ux.Green, "⬢ "+st.gCmd)+ux.C(ux.Dim, "   (run it in another terminal)"))
	}
	if st.showHelp {
		out = append(out, ux.C(ux.Dim, "  s cycles traffic → latency → address; ⏎/Tab toggles the detail pane;"))
		out = append(out, ux.C(ux.Dim, "  o edits settings live (interval, history, alarms, beeps); hold ↑/↓ to scroll fast;"))
		out = append(out, ux.C(ux.Dim, "  g shows the gnulte command that tests the cursor host; Esc closes panes."))
	}
	// Hard guarantee: never draw taller than the terminal (a very short TTY
	// with every pane open can exhaust even the packed budget).
	if len(out) > height {
		out = out[:height]
	}
	return out
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

// paneHeights is how many fixed lines the detail and talkers panes consume,
// worst case (a detail pane can stretch to eleven lines with three flows).
func paneHeights(st *viewState, flows []traffic.Flow) (talkH, detailH int) {
	if st.showTalk && len(flows) > 0 {
		n := 5
		if len(flows) < n {
			n = len(flows)
		}
		talkH = n + 2 // blank + title + rows
	}
	if st.detail {
		detailH = 11
	}
	return talkH, detailH
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
// session averages, health verdict, latency history, the exact gnulte command
// that would test it, and the flows it is involved in this interval.
func detailLines(ip string, h hostInfo, st *hostStat, r traffic.Rate,
	flows []traffic.Flow, hostSet map[string]bool, iv int) []string {

	head := "  ── " + ux.C(ux.Bold, "DETAIL · "+ip)
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

	// Health verdict: is this device a sensible GNULTE test target right now?
	out = append(out, "     "+grade(st)+" "+healthText(st))

	// Latency line + three history sparklines from the same bounded window.
	lastS := fmt.Sprintf("%dms", st.ping.last)
	if st.ping.last < 0 {
		lastS = "✗"
	}
	pl := fmt.Sprintf("ping last %s · avg %dms · min %dms · max %dms · loss %.0f%% · jitter %dms",
		lastS, st.ping.avg(), st.ping.min, st.ping.max, st.ping.loss(), st.ping.jitter())
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
