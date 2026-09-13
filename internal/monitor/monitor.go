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
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gnulte-go/internal/sound"
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

	// ExportFile streams every sample as CSV (ts,ip,rtt_ms,ok) when set.
	ExportFile string
	// OnTick is invoked once per second while the monitor runs.
	OnTick func()

	// Results is filled once Run returns.
	Results []Result

	expMu sync.Mutex
	exp   *os.File
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
	secs := int((timeout + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(secs), "-n", ip).Output()
	if err != nil {
		return -1, 0
	}
	s := string(out)
	if i := strings.Index(s, "ttl="); i >= 0 {
		j := i + 4
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		ttl, _ = strconv.Atoi(s[i+4 : j])
	}
	i := strings.Index(s, "time=")
	if i < 0 || i+5 > len(s) {
		return -1, ttl
	}
	rest := s[i+5:]
	j := strings.IndexAny(rest, " \n\t")
	if j < 0 {
		j = len(rest)
	}
	rtt, _ = strconv.Atoi(rest[:j])
	return rtt, ttl
}

// Run blocks until ctx is cancelled. Renders console-log history for one
// target or a live dashboard for several.
func (m *Monitor) Run(ctx context.Context) error {
	if err := m.openExport(); err != nil {
		return err
	}
	defer m.closeExport()
	m.printHeader()
	if len(m.Targets) == 1 {
		return m.runSingle(ctx, m.Targets[0])
	}
	return m.runMulti(ctx)
}

// printHeader paints the static console header with the impairment recipe, the
// Bash monitor window style.
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
	fmt.Println(dim("══════════════════════════════════════════════════════════════"))
	fmt.Println("  " + paint(cCyan, "GNULTE") + " · live test console")
	if len(m.Targets) == 1 {
		fmt.Printf("  target      %s\n", m.Targets[0])
	} else {
		fmt.Printf("  targets     %d hosts\n", len(m.Targets))
	}
	if m.Iface != "" {
		fmt.Printf("  interface   %s\n", m.Iface)
	}
	if m.Impairment != "" {
		fmt.Printf("  impairment  %s\n", m.Impairment)
	}
	fmt.Printf("  session     %s\n", bits)
	fmt.Println(dim("══════════════════════════════════════════════════════════════"))
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
			rtt, ttl := PingOnce(ctx, ip, m.timeout())
			seq++
			m.exportCSV(ip, rtt)
			st.Last = rtt
			now := time.Now().Format("15:04:05")
			if rtt < 0 {
				st.Drops++
				if !m.Quiet {
					fmt.Printf("  %s [%s] %s %-16s %10s  %s %s\n",
						segColor(seq), now, tickMark(false), ip,
						paint(cRed+cBold, "unreachable"), paint(cDim, "timeout"),
						dim(fmt.Sprintf("(no reply in %ds)", int(m.timeout()/time.Second))))
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
					ttlS := "—"
					if ttl > 0 {
						ttlS = strconv.Itoa(ttl)
					}
					line := fmt.Sprintf("  %s [%s] %s %-16s %10s  ttl=%s",
						segColor(seq), now, tickMark(true), ip, rttColor(rtt), ttlS)
					if tr := trendOf(prev, rtt); tr != "" {
						line += " " + tr
					}
					fmt.Println(line)
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

func (m *Monitor) singleSummary(ip string, st *Stats) {
	if m.Quiet {
		return
	}
	if st.attempts() == 0 {
		return
	}
	seen := st.Count
	loss := st.lossPct()
	fmt.Println(dim("────────────────────────────── summary ──────────────────────────────"))
	if seen > 0 {
		fmt.Printf("  %s · ok %d/%d · avg %s · min %s · max %s · jitter ±%dms · loss %.0f%%\n",
			ip, seen, st.attempts(), rttColor(int(st.avg())),
			rttColor(int(st.Min)), rttColor(int(st.Max)), st.jitter(), loss)
	} else {
		fmt.Printf("  %s · ok 0/%d · no replies · loss %.0f%%\n", ip, st.attempts(), loss)
	}
	fmt.Println(dim("──────────────────────────────────────────────────────────────────────"))
}

// runMulti renders a live dashboard that is rewritten each second.
func (m *Monitor) runMulti(ctx context.Context) error {
	stats := make([]*Stats, len(m.Targets))
	for i := range stats {
		stats[i] = &Stats{Samples: []int{}}
	}
	prevOK := make([]bool, len(m.Targets))
	started := make([]bool, len(m.Targets))

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
					rtt, _ := PingOnce(ctx, ip, m.timeout())
					m.exportCSV(ip, rtt)
					ok := rtt >= 0
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
					// Sound only on state transitions (avoids a beep per host/s).
					if m.Sound && started[i] && prevOK[i] != ok {
						sound.PingResult(rtt, ok)
					}
					started[i] = true
					prevOK[i] = ok
				}
			}
		}(i, ip)
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
			m.renderDashboard(stats)
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

func (m *Monitor) renderDashboard(stats []*Stats) {
	// Frame height: blank line + 2 rows per target + timestamp footer.
	frames := 2 + 2*len(m.Targets)
	fmt.Printf("\033[%dA\033[J", frames)

	fmt.Println()
	for i, ip := range m.Targets {
		st := stats[i]
		last := "--"
		if st.Last >= 0 {
			last = fmt.Sprintf("%dms", st.Last)
		}
		mn, mx := "--", "--"
		if st.Count > 0 {
			mn, mx = fmt.Sprintf("%dms", st.Min), fmt.Sprintf("%dms", st.Max)
		}
		fmt.Printf("  %-3d %s %-16s last=%-8s avg=%-5dms min=%-7s max=%-7s loss=%.0f%%  jitter=±%dms\n",
			i+1, statusIcon(st.Last), ip, last, st.avg(), mn, mx, st.lossPct(), st.jitter())

		// Small sparkline of the last 40 samples.
		n := len(st.Samples)
		if n == 0 {
			fmt.Printf("      %-16s  %s\n", "", dim("(awaiting samples…)"))
		} else {
			start := 0
			if n > 40 {
				start = n - 40
			}
			sp := make([]byte, 0, n-start)
			for _, v := range st.Samples[start:] {
				sp = append(sp, sparkChar(v))
			}
			fmt.Printf("      %-16s  %s\n", "", string(sp[:min(len(sp), 40)]))
		}
	}
	fmt.Printf("  [%s]\n", time.Now().Format("15:04:05"))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
