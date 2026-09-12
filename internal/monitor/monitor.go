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

// rttColor renders an RTT, color-coded by severity on terminals.
func rttColor(ms int) string {
	s := fmt.Sprintf("%dms", ms)
	if !outTTY {
		return s
	}
	switch {
	case ms < 200:
		return "\033[0;32m" + s + "\033[0m"
	case ms < 500:
		return "\033[1;33m" + s + "\033[0m"
	default:
		return "\033[0;31m" + s + "\033[0m"
	}
}

func badText(s string) string {
	if !outTTY {
		return s
	}
	return "\033[0;31m" + s + "\033[0m"
}

// Monitor pings Targets on Interval and reports results.
type Monitor struct {
	Targets  []string
	Interval time.Duration
	// Timeout bounds a single ping. It should cover the planned latency so a
	// slow-but-reachable target is not reported as unreachable.
	Timeout time.Duration
	Sound   bool
	Quiet   bool

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
// (or -1 on no reply). The timeout must cover the planned latency, or a slow
// but reachable target would be misread as offline.
func PingOnce(ctx context.Context, ip string, timeout time.Duration) RTT {
	secs := int(timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(secs), "-n", ip).CombinedOutput()
	if err != nil {
		return -1
	}
	s := string(out)
	i := strings.Index(s, "time=")
	if i < 0 || i+5 > len(s) {
		return -1
	}
	rest := s[i+5:]
	j := strings.IndexAny(rest, " \n\t")
	if j < 0 {
		j = len(rest)
	}
	var ms int
	if _, err := fmt.Sscanf(rest[:j], "%d", &ms); err != nil {
		return -1
	}
	return ms
}

// Run blocks until ctx is cancelled. Renders console-log history for one
// target or a live dashboard for several.
func (m *Monitor) Run(ctx context.Context) error {
	if err := m.openExport(); err != nil {
		return err
	}
	defer m.closeExport()
	if len(m.Targets) == 1 {
		return m.runSingle(ctx, m.Targets[0])
	}
	return m.runMulti(ctx)
}

// runSingle prints each sample as a permanent log line (matches the Bash
// single-target console-log style), with a summary line every 10 samples.
func (m *Monitor) runSingle(ctx context.Context, ip string) error {
	st := &Stats{Samples: []int{}}
	tick := time.NewTicker(m.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			m.singleSummary(ip, st)
			m.publish(ip, st)
			return nil
		case <-tick.C:
			rtt := PingOnce(ctx, ip, m.timeout())
			m.exportCSV(ip, rtt)
			st.Last = rtt
			if rtt < 0 {
				st.Drops++
				if !m.Quiet {
					fmt.Printf("[%s] %-16s %s\n", time.Now().Format("15:04:05"), ip, badText("unreachable"))
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
					fmt.Printf("[%s] %-16s %5s  OK\n", time.Now().Format("15:04:05"), ip, rttColor(rtt))
				}
				if m.Sound {
					sound.PingResult(rtt, true)
				}
			}
			if (st.Count+st.Drops)%10 == 0 {
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
	attempts := st.Count + st.Drops
	if attempts == 0 {
		return
	}
	loss := st.lossPct()
	fmt.Printf("   — %s summary: samples=%d min=%dms max=%dms avg=%dms loss=%.1f%%\n",
		ip, attempts, st.Min, st.Max, st.avg(), loss)
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
					rtt := PingOnce(ctx, ip, m.timeout())
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

func statusDot(v RTT) byte {
	switch {
	case v < 0:
		return 'x'
	case v <= 300:
		return 'o'
	case v <= 800:
		return '~'
	default:
		return '!'
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
		fmt.Printf("  %-3d %c  %-16s  min=%-7s max=%-7s avg=%-5dms loss=%.1f%%  last=%s\n",
			i+1, statusDot(st.Last), ip, mn, mx, st.avg(), st.lossPct(), last)

		// Small sparkline of the last 40 samples.
		n := len(st.Samples)
		if n == 0 {
			fmt.Printf("      %-16s  (awaiting samples…)\n", "")
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
