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

// Package monitor pings monitored targets and renders live results.
// A single target logs the full ping history to the console; multiple targets
// switch to a per-second, self-updating dashboard.
package monitor

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gnulte-go/internal/probe"
	"gnulte-go/internal/sound"
	"gnulte-go/internal/traffic"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

// RTT is a single ping sample in milliseconds (-1 when the target did not
// answer within the timeout).
type RTT = int

// Stats tracks running ping statistics for one target.
type Stats struct {
	Count   int
	Drops   int
	Total   int64
	Min     int64
	Max     int64
	Last    RTT
	Samples []int
}

func (st *Stats) avg() int64 {
	if st.Count == 0 {
		return 0
	}
	return st.Total / int64(st.Count)
}

func (st *Stats) lossPct() float64 {
	attempts := st.Count + st.Drops
	if attempts == 0 {
		return 0
	}
	return float64(st.Drops) * 100 / float64(attempts)
}

// jitter returns the mean absolute deviation from the average RTT.
func (st *Stats) jitter() int64 {
	if st.Count == 0 {
		return 0
	}
	av := st.avg()
	var sum int64
	for _, s := range st.Samples {
		d := int64(s) - av
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / int64(len(st.Samples))
}

func (st *Stats) stdev() float64 {
	n := len(st.Samples)
	if n < 2 {
		return 0
	}
	av := st.avg()
	var ss float64
	for _, s := range st.Samples {
		d := float64(int64(s) - av)
		ss += d * d
	}
	return math.Sqrt(ss / float64(n-1))
}

// attempts is the total number of ping tries (successes + drops).
func (st *Stats) attempts() int { return st.Count + st.Drops }

// Result pairs one target with its final statistics (safe to read after Run).
type Result struct {
	IP    string
	Stats Stats
}

// outTTY reports whether the live console output is a real terminal (color).
var outTTY = func() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

const (
	cReset  = "\033[0m"
	cGreen  = "\033[0;32m"
	cRed    = "\033[0;31m"
	cYellow = "\033[1;33m"
	cDim    = "\033[2m"
	cCyan   = "\033[0;36m"
)

func paint(code, s string) string {
	if !outTTY {
		return s
	}
	return code + s + cReset
}

func dim(s string) string { return paint(cDim, s) }

// rttColor renders an RTT, color-coded by severity on terminals.
func rttColor(ms int) string {
	s := fmt.Sprintf("%dms", ms)
	switch {
	case ms < 200:
		return paint(cGreen, s)
	case ms < 500:
		return paint(cYellow, s)
	default:
		return paint(cRed, s)
	}
}

// segColor renders the sample sequence number, tinted when packets drop.
func segColor(n int) string { return paint(cDim, fmt.Sprintf("%03d", n)) }

// tickMark is a styled per-sample status glyph.
func tickMark(ok bool) string {
	if ok {
		return paint(cGreen, "✓")
	}
	return paint(cRed, "✗")
}

// trendOf renders the change against the previous sample as an arrow.
func trendOf(prev, cur RTT) string {
	if prev < 0 || cur < 0 {
		return "" // nothing to compare yet
	}
	d := cur - prev
	switch {
	case d == 0:
		return paint(cDim, "•")
	case d > 0:
		up := paint(cYellow, fmt.Sprintf("▲ +%d", d))
		if d >= 200 {
			up = paint(cRed, fmt.Sprintf("▲ +%d", d))
		}
		return up
	default:
		return paint(cGreen, fmt.Sprintf("▼ %d", d))
	}
}

func badText(s string) string { return paint(cRed, s) }

// cBold is used by badText callers and unreachable rows.
const cBold = "\033[1m"

// Monitor pings Targets on Interval and reports results.
type Monitor struct {
	Targets  []string
	Interval time.Duration
	// Timeout bounds a single ping. It should cover the planned latency so a
	// slow-but-reachable target is not reported as unreachable.
	Timeout time.Duration
	Sound   bool
	Quiet   bool

	// Iface and Impairment decorate the live console header (interface used
	// and the applied impairment recipe).
	Iface      string
	Impairment string

	// TCPPorts are the fallback probe ports tried when the target does not
	// answer ICMP echo (many hosts and firewalls filter it). Defaults to
	// 443, 80, 53 when empty. A TCP SYN/ACK or RST both prove the host is alive
	// and yield a measurable latency.
	TCPPorts []int

	// Log records every permanent console line for the post-test HTML report
	// (the whole live log history, not just the summary).
	Log   []string
	logMu sync.Mutex

	// ExportFile streams every sample as CSV (ts,ip,rtt_ms,ok) when set.
	ExportFile string
	// OnTick is invoked once per second while the monitor runs.
	OnTick func()

	// Traffic counts live per-host bytes/packets on Iface when the interface
	// name is known and the raw socket can be opened (root). It upgrades the
	// console with a down/up rate per target; without it, the console simply
	// omits the traffic column.
	Traffic *traffic.Counter

	// sel is the arrow-key-selected target index (atomic) for multi-target
	// monitoring: the host whose beeps are audible.
	sel int32

	// mu guards stats[i]/lastNote[i] writes from the per-target goroutines
	// against the dashboard reader in the main loop.
	mu sync.Mutex

	// Results is filled once Run returns.
	Results []Result

	expMu sync.Mutex
	exp   *os.File
}

// rec appends one plain-text console line to the session history.
func (m *Monitor) rec(line string) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.Log = append(m.Log, line)
}

func (m *Monitor) publish(ip string, st *Stats) {
	cp := *st
	cp.Samples = append([]int(nil), st.Samples...)
	m.Results = append(m.Results, Result{IP: ip, Stats: cp})
}

func (m *Monitor) openExport() error {
	if m.ExportFile == "" {
		return nil
	}
	f, err := os.Create(m.ExportFile)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("# ts,ip,rtt_ms,ok\n"); err != nil {
		f.Close()
		return err
	}
	m.exp = f
	return nil
}

// timeout returns the per-ping timeout, defaulting to 1s.
func (m *Monitor) timeout() time.Duration {
	if m.Timeout > 0 {
		return m.Timeout
	}
	return time.Second
}

func (m *Monitor) closeExport() {
	m.expMu.Lock()
	defer m.expMu.Unlock()
	if m.exp != nil {
		_ = m.exp.Close()
		m.exp = nil
	}
}

// exportCSV appends one sample row (thread-safe).
func (m *Monitor) exportCSV(ip string, rtt RTT) {
	m.expMu.Lock()
	defer m.expMu.Unlock()
	if m.exp == nil {
		return
	}
	fmt.Fprintf(m.exp, "%s,%s,%d,%t\n",
		time.Now().Format("2006-01-02T15:04:05"), ip, rtt, rtt >= 0)
}

// PingOnce performs a single ping with the given timeout and returns the RTT
// (or -1 on no reply) and the TTL seen in the reply. The timeout must cover
// the planned latency, or a slow but reachable target would be misread as
// offline.
func PingOnce(ctx context.Context, ip string, timeout time.Duration) (rtt RTT, ttl int) {
	return probe.Ping(ctx, ip, timeout)
}

// probePorts returns the configured TCP fallback ports (defaulted in probe).
func (m *Monitor) probePorts() []int {
	if len(m.TCPPorts) > 0 {
		return m.TCPPorts
	}
	return probe.DefaultPorts
}

// sample measures one target on the primary channel (ICMP echo) and falls back
// to TCP connects when echo is silent, so a target whose firewall filters ICMP
// is not misread as offline. It returns the RTT, a human note ("ttl=64",
// "tcp:443 4ms") and whether the target answered at all.
func (m *Monitor) sample(ctx context.Context, ip string) (rtt RTT, note string, ok bool) {
	rtt, ttl := PingOnce(ctx, ip, m.timeout())
	if rtt >= 0 {
		if ttl > 0 {
			note = fmt.Sprintf("ttl=%d", ttl)
		}
		return rtt, note, true
	}
	res := probe.ProbeTCP(ctx, ip, m.probePorts())
	if res.Alive() {
		return res.Latency(), res.Note(), true
	}
	return -1, "", false
}

// Run blocks until ctx is cancelled. Renders console-log history for one
// target or a live dashboard for several.
func (m *Monitor) Run(ctx context.Context) error {
	if err := m.openExport(); err != nil {
		return err
	}
	defer m.closeExport()
	if m.Iface != "" {
		if tc, err := traffic.New(m.Iface); err == nil && tc != nil {
			m.Traffic = tc
			defer func() {
				if m.Traffic != nil {
					m.Traffic.Close()
				}
			}()
		}
	}
	m.printHeader()
	if len(m.Targets) == 1 {
		return m.runSingle(ctx, m.Targets[0])
	}
	return m.runMulti(ctx)
}

// printHeader paints the static console header with the impairment recipe, the
// Bash monitor window style, and records it in the session log.
func (m *Monitor) printHeader() {
	if m.Quiet {
		return
	}
	bits := "beeps " + "on"
	if !m.Sound {
		bits = "beeps off"
	}
	if m.Interval > 0 {
		secs := int((m.Interval + 499*time.Millisecond) / time.Second)
		if secs < 1 {
			secs = 1
		}
		bits += fmt.Sprintf(" · every %ds", secs)
	}
	line := func(s, t string) {
		fmt.Println(s)
		m.rec(t)
	}
	line(dim("══════════════════════════════════════════════════════════════"),
		"══════════════════════════════════════════════════════════════")
	line(paint(cCyan, "GNULTE")+" · live test console", "GNULTE · live test console")
	if len(m.Targets) == 1 {
		line(fmt.Sprintf("  target      %s", m.Targets[0]), fmt.Sprintf("  target      %s", m.Targets[0]))
	} else {
		line(fmt.Sprintf("  targets     %d hosts", len(m.Targets)), fmt.Sprintf("  targets     %d hosts", len(m.Targets)))
	}
	if m.Iface != "" {
		line(fmt.Sprintf("  interface   %s", m.Iface), fmt.Sprintf("  interface   %s", m.Iface))
	}
	if m.Impairment != "" {
		line(fmt.Sprintf("  impairment  %s", m.Impairment), fmt.Sprintf("  impairment  %s", m.Impairment))
	}
	line(fmt.Sprintf("  session     %s", bits), fmt.Sprintf("  session     %s", bits))
	if len(m.Targets) > 1 && !m.Quiet && stdinIsTTY() {
		hint := "  ↑/↓ pick the target you hear · Ctrl+C stop"
		line(dim(hint), strings.TrimSpace(hint))
	}
	if m.Traffic != nil {
		line(paint(cCyan, "  ")+dim("live traffic: counting "+m.Iface), "  live traffic: counting "+m.Iface)
	}
	line(dim("══════════════════════════════════════════════════════════════"),
		"══════════════════════════════════════════════════════════════")
}

// runSingle prints each sample as a permanent log line (matches the Bash
// single-target console-log style), with a summary line every 10 samples.
func (m *Monitor) runSingle(ctx context.Context, ip string) error {
	st := &Stats{Samples: []int{}}
	tick := time.NewTicker(m.Interval)
	defer tick.Stop()
	seq := 0
	prev := RTT(-1)
	for {
		select {
		case <-ctx.Done():
			m.singleSummary(ip, st)
			m.publish(ip, st)
			return nil
		case <-tick.C:
			// honour an interrupt without bouncing through another ping
			select {
			case <-ctx.Done():
				m.singleSummary(ip, st)
				m.publish(ip, st)
				return nil
			default:
			}
			rtt, note, ok := m.sample(ctx, ip)
			seq++
			m.exportCSV(ip, rtt)
			st.Last = rtt
			now := time.Now().Format("15:04:05")
			if !ok {
				st.Drops++
				plain := fmt.Sprintf("  #%03d [%s] ✗ %-16s %10s  %s  %s",
					seq, now, ip, "unreachable", "timeout",
					fmt.Sprintf("(no reply in %ds)", int(m.timeout()/time.Second)))
				if !m.Quiet {
					fmt.Printf("  %s [%s] %s %-16s %10s  %s %s\n",
						segColor(seq), now, tickMark(false), ip,
						paint(cRed+cBold, "unreachable"), paint(cDim, "timeout"),
						dim(fmt.Sprintf("(no reply in %ds)", int(m.timeout()/time.Second))))
					m.rec(plain)
				}
				if m.Sound {
					sound.PingResult(0, false)
				}
			} else {
				st.Count++
				st.Total += int64(rtt)
				if st.Min == 0 || int64(rtt) < st.Min {
					st.Min = int64(rtt)
				}
				if int64(rtt) > st.Max {
					st.Max = int64(rtt)
				}
				st.Samples = append(st.Samples, rtt)
				if !m.Quiet {
					if note == "" {
						note = "—"
					}
					if strings.HasPrefix(note, "tcp:") {
						note += dim("  (icmp silent)")
					}
					line, plainLine := m.singleLine(seq, now, ip, rtt, note, prev)
					if tr := m.rateText(ip); tr != "" {
						line += "  " + paint(cCyan, tr)
						plainLine += "  " + tr
					}
					fmt.Println(line)
					m.rec(plainLine)
				}
				if m.Sound {
					sound.PingResult(rtt, true)
				}
				prev = rtt
			}
			if st.attempts()%10 == 0 {
				m.singleSummary(ip, st)
			}
			if m.OnTick != nil {
				m.OnTick()
			}
		}
	}
}

// singleLine renders one success sample, returning the coloured console line
// and the matching plain-text history line.
func (m *Monitor) singleLine(seq int, now, ip string, rtt RTT, note string, prev RTT) (string, string) {
	trCol := trendOf(prev, rtt)
	trPlain := ""
	if prev >= 0 {
		trPlain = trendPlain(prev, rtt)
	}
	colored := fmt.Sprintf("  %s [%s] %s %-16s %10s  %s",
		segColor(seq), now, tickMark(true), ip, rttColor(rtt), note)
	if trCol != "" {
		colored += " " + trCol
	}
	plain := fmt.Sprintf("  #%03d [%s] ✓ %-16s %10s  %s", seq, now, ip, fmt.Sprintf("%dms", rtt), note)
	if trPlain != "" {
		plain += " " + trPlain
	}
	return colored, plain
}

// trendPlain is the colour-free trend arrow used by the session log.
func trendPlain(prev, cur RTT) string {
	d := cur - prev
	switch {
	case d == 0:
		return "•"
	case d > 0:
		return fmt.Sprintf("▲ +%d", d)
	default:
		return fmt.Sprintf("▼ %d", d)
	}
}

func (m *Monitor) singleSummary(ip string, st *Stats) {
	if m.Quiet {
		return
	}
	if st.attempts() == 0 {
		return
	}
	seen := st.Count
	loss := st.lossPct()
	var head, plainHead string
	if seen > 0 {
		head = fmt.Sprintf("  %s · ok %d/%d · avg %s · min %s · max %s · jitter ±%dms · loss %.0f%%",
			ip, seen, st.attempts(), rttColor(int(st.avg())),
			rttColor(int(st.Min)), rttColor(int(st.Max)), st.jitter(), loss)
		plainHead = fmt.Sprintf("  %s · ok %d/%d · avg %dms · min %dms · max %dms · jitter ±%dms · loss %.0f%%",
			ip, seen, st.attempts(), st.avg(), st.Min, st.Max, st.jitter(), loss)
	} else {
		head = fmt.Sprintf("  %s · ok 0/%d · no replies · loss %.0f%%", ip, st.attempts(), loss)
		plainHead = head
	}
	delim := "────────────────────────────── summary ──────────────────────────────"
	delim2 := "──────────────────────────────────────────────────────────────────────"
	fmt.Println(dim(delim))
	m.rec(delim)
	fmt.Println(head)
	m.rec(plainHead)
	fmt.Println(dim(delim2))
	m.rec(delim2)
}

// runMulti renders a live dashboard that is rewritten each second. When the
// terminal allows it, the up/down arrows (or j/k) pick which target's beeps
// you hear; every sample of the selected host plays a tone pitched by its
// round-trip time, as in single-host monitoring.
func (m *Monitor) runMulti(ctx context.Context) error {
	stats := make([]*Stats, len(m.Targets))
	lastNote := make([]string, len(m.Targets))
	for i := range stats {
		stats[i] = &Stats{Samples: []int{}}
	}

	// Arrow-key selection. The reader forces the selection to the first host
	// when the terminal cannot be switched raw, so beeps always have a target.
	keyboard := len(m.Targets) > 1 && !m.Quiet && stdinIsTTY()
	restore := enableKeyboard(len(m.Targets), &m.sel)
	defer restore()

	// Flicker-free dashboard: switch to the terminal's alternate buffer and
	// repaint the whole frame in one flush every tick, so there is no per-line
	// flashing. Single-target runs deliberately stay a scrolling console log
	// (runSingle), and piped output skips the alternate buffer entirely.
	leave := func() {}
	view := false
	if !m.Quiet && ux.TTY() {
		if l, ok := tui.EnterView(); ok {
			leave, view = l, true
			tui.RegisterCleanup(l) // a hard interrupt still restores the screen
		}
	}
	defer leave()

	var wg sync.WaitGroup
	for i, ip := range m.Targets {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			tick := time.NewTicker(m.Interval)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					select {
					case <-ctx.Done():
						return
					default:
					}
					rtt, note, ok := m.sample(ctx, ip)
					m.exportCSV(ip, rtt)
					m.mu.Lock()
					lastNote[i] = note
					stats[i].Last = rtt
					if ok {
						stats[i].Count++
						stats[i].Total += int64(rtt)
						if stats[i].Min == 0 || int64(rtt) < stats[i].Min {
							stats[i].Min = int64(rtt)
						}
						if int64(rtt) > stats[i].Max {
							stats[i].Max = int64(rtt)
						}
						stats[i].Samples = append(stats[i].Samples, rtt)
					} else {
						stats[i].Drops++
					}
					m.mu.Unlock()
					// Beep every sample of the host the arrows have selected,
					// pitched by its latency — the sound mirrors what the
					// selected target's link is doing right now.
					if m.Sound && int(atomic.LoadInt32(&m.sel)) == i {
						sound.PingResult(rtt, ok)
					}
					if !m.Quiet {
						// History line: one permanent row per sample so the
						// report carries the whole log, not just the snapshot.
						mark, rttS := "✓", "—"
						if ok {
							rttS = fmt.Sprintf("%dms", rtt)
						} else {
							mark = "✗"
						}
						noteS := note
						if !ok {
							noteS = "unreachable"
						}
						if noteS == "" {
							noteS = "—"
						}
						m.rec(fmt.Sprintf("  [%s] %s %-16s %10s  %s",
							time.Now().Format("15:04:05"), mark, ip, rttS, noteS))
					}
				}
			}
		}(i, ip)
	}

	// Take the traffic baseline so the first dashboard second shows a real
	// rate rather than a giant first count.
	if m.Traffic != nil {
		m.Traffic.Snapshot()
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			for i, st := range stats {
				m.publish(m.Targets[i], st)
			}
			return nil
		case <-tick.C:
			m.renderDashboard(stats, lastNote, keyboard, view)
			if m.OnTick != nil {
				m.OnTick()
			}
		}
	}
}

func sparkChar(v int) byte {
	switch {
	case v < 0:
		return 'x'
	case v <= 80:
		return '.'
	case v <= 250:
		return '-'
	case v <= 500:
		return '='
	case v <= 1000:
		return '#'
	default:
		return 'M'
	}
}

// statusIcon is the live per-target glyph: operating normally, degraded, or
// offline.
func statusIcon(v RTT) string {
	switch {
	case v < 0:
		return paint(cRed, "✗")
	case v <= 300:
		return paint(cGreen, "✓")
	case v <= 800:
		return paint(cYellow, "⚠")
	default:
		return paint(cRed, "!!")
	}
}

func (m *Monitor) renderDashboard(stats []*Stats, lastNote []string, keyboard, view bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sel := int(atomic.LoadInt32(&m.sel))
	lines := make([]string, 0, 2+2*len(m.Targets))
	lines = append(lines, "")

	for i, ip := range m.Targets {
		st := stats[i]
		mark := "   "
		if keyboard && sel == i {
			mark = paint(cCyan, "▶  ")
		}
		idx := fmt.Sprintf("%2d", i+1)
		if keyboard && sel == i {
			idx = paint(cCyan, idx)
		} else {
			idx = paint(cDim, idx)
		}

		// Line 1: status, address, current latency, average, loss, traffic.
		last := paint(cDim, "--")
		if st.Last >= 0 {
			last = rttColor(int(st.Last))
		}
		tcpNote := ""
		if n := lastNote[i]; strings.HasPrefix(n, "tcp:") {
			if i2 := strings.Index(n, " "); i2 >= 0 {
				tcpNote = dim(fmt.Sprintf(" (tcp %sms)", n[len("tcp:"):i2]))
			} else {
				tcpNote = dim(" (tcp)")
			}
		}
		avg := paint(cDim, "--")
		if st.Count > 0 {
			avg = rttColor(int(st.avg()))
		}
		loss := paint(cGreen, fmt.Sprintf("%.0f%%", st.lossPct()))
		if st.lossPct() > 0 {
			loss = paint(cRed, fmt.Sprintf("%.0f%%", st.lossPct()))
		}
		tr := m.rateText(ip)
		trS := dim("↓ - ↑ -")
		if tr != "" {
			trS = paint(cCyan, tr)
		}
		lines = append(lines, fmt.Sprintf("  %s%s %s  %s  last %s  avg %s  loss %s  %s",
			mark, idx, statusIcon(st.Last), paint(cYellow, ip), last, avg, loss, trS))

		// Line 2: span metrics and the tiny latency sparkline, dim.
		mn, mx := "--", "--"
		if st.Count > 0 {
			mn, mx = fmt.Sprintf("%dms", st.Min), fmt.Sprintf("%dms", st.Max)
		}
		spark := "    "
		if n := len(st.Samples); n > 0 {
			start := 0
			if n > 30 {
				start = n - 30
			}
			sp := make([]byte, 0, n-start)
			for _, v := range st.Samples[start:] {
				sp = append(sp, sparkChar(v))
			}
			spark = string(sp[:min(len(sp), 30)])
		}
		lines = append(lines, fmt.Sprintf("      %-16s min %s · max %s · jitter ±%dms %s %s",
			"", mn, mx, st.jitter(), tcpNote, dim(spark)))
	}
	lines = append(lines, fmt.Sprintf("  [%s]", time.Now().Format("15:04:05")))

	if view {
		// Alternate buffer: one buffered write per second — no flicker.
		tui.DrawFrame(os.Stdout, ux.Width(), lines)
		return
	}
	// Piped/logged output: back up over the previous frame in one ANSI move.
	fmt.Printf("\033[%dA\033[J", len(lines))
	for _, ln := range lines {
		fmt.Println(ln)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// rateText renders one host's live down/up rates from the traffic counter, or
// an empty string when counters are off, e.g. "↓1.2KB/s ↑3.4KB/s".
func (m *Monitor) rateText(ip string) string {
	if m.Traffic == nil {
		return ""
	}
	r := m.Traffic.Snapshot()[ip]
	if r.RXBytes == 0 && r.TXBytes == 0 && r.RXPkts == 0 && r.TXPkts == 0 {
		return "↓0 ↑0"
	}
	s := "↓" + ux.HumanRate(r.RXBytes)
	if r.TXBytes > 0 {
		s += " " + "↑" + ux.HumanRate(r.TXBytes)
	}
	return s
}

// stdinIsTTY reports whether standard input is a real terminal (needed for the
// arrow-key listener).
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
