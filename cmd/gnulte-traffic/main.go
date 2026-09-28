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

// Command gnulte-traffic is a live, per-host network traffic monitor. On an
// interface it watches the wire (AF_PACKET) and repaints a small full-screen
// dashboard of each watched host's down/up speed and packet rate every second
// — a focused companion window for long gnulte sessions. It is passive: it
// captures only the counts needed for the dashboard and sends nothing.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/netutil"
	"gnulte-go/internal/probe"
	"gnulte-go/internal/settings"
	"gnulte-go/internal/traffic"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "13.1"

// pinger tracks the ping history of one watched host across ticks: the last
// RTT, running min/max/avg/loss, and the bounded sample ring that becomes the
// latency sparkline under the traffic row.
type pinger struct {
	count   int
	drops   int
	total   int64
	min     int64
	max     int64
	last    int
	samples []int
}

func (h *pinger) add(rtt int, capN int) {
	h.last = rtt
	if rtt < 0 {
		h.drops++
		return
	}
	h.count++
	h.total += int64(rtt)
	if h.min == 0 || int64(rtt) < h.min {
		h.min = int64(rtt)
	}
	if int64(rtt) > h.max {
		h.max = int64(rtt)
	}
	h.samples = append(h.samples, rtt)
	if capN > 0 && len(h.samples) > capN {
		h.samples = h.samples[len(h.samples)-capN:]
	}
}

func main() {
	var (
		iface    = flag.String("i", "", "network interface (default: auto-detect)")
		targets  = flag.String("t", "", "host IP(s) to watch, comma-separated")
		interval = flag.Int("interval", 0, "seconds between updates (0 = settings/1)")
		duration = flag.Int("duration", 0, "auto-stop after N seconds (0 = until interrupt)")
		history  = flag.Int("history", 0, "ping samples kept per host (0 = settings/60)")
		quiet    = flag.Bool("q", false, "quiet: no banner")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("GNULTE-TRAFFIC v%s (Go)\n", version)
		return
	}

	cfgLoaded := settings.Default()
	if c, err := settings.Load(); err == nil {
		cfgLoaded = c
	} else {
		fmt.Fprintf(os.Stderr, "gnulte-traffic: %v\n", err)
	}
	iv := ux.Clamp(cfgLoaded.TrafficSec, 1, 10)
	if *interval > 0 {
		iv = ux.Clamp(*interval, 1, 10)
	}
	histCap := ux.Clamp(cfgLoaded.History, 10, 240)
	if *history > 0 {
		histCap = ux.Clamp(*history, 10, 240)
	}
	timeout := time.Duration(ux.Clamp(cfgLoaded.TimeoutMs, 100, 60000)) * time.Millisecond

	// Administrator-privilege handshake: counting packets needs a raw socket.
	if os.Geteuid() != 0 && os.Getenv("GNULTE_AS_ROOT") != "1" {
		args := append([]string{"-E", os.Args[0]}, os.Args[1:]...)
		cmd := exec.Command("sudo", args...)
		cmd.Env = append(os.Environ(), "GNULTE_AS_ROOT=1")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				os.Exit(ee.ExitCode())
			}
			fatal(fmt.Errorf("failed to obtain administrator access: %w", err))
		}
		os.Exit(0)
	}

	cfg, err := netutil.DefaultRoute()
	if err != nil {
		fatal(fmt.Errorf("network detection failed: %w", err))
	}
	nic := *iface
	if nic == "" {
		nic = cfgLoaded.Interface
	}
	if nic == "" {
		nic = cfg.Interface
	}
	if nic == "" {
		fatal(fmt.Errorf("no interface to watch — pass -i"))
	}

	hosts := parseHosts(*targets)
	if len(hosts) == 0 && cfg.Gateway != "" {
		hosts = append(hosts, cfg.Gateway)
	}
	if len(hosts) == 0 {
		fatal(fmt.Errorf("no hosts to watch — pass -t with one or more IPs"))
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		sigCtx, cancel = context.WithTimeout(sigCtx, time.Duration(*duration)*time.Second)
		defer cancel()
	}

	counter, err := traffic.New(nic)
	if err != nil {
		fatal(fmt.Errorf("could not count %s traffic: %v", nic, err))
	}
	// A down interface yields a nil counter (traffic.New returns (nil, nil)):
	// the dashboard then shows every host as idle instead of panicking.
	hasCounter := counter != nil
	if hasCounter {
		counter.Snapshot() // baseline so the first second shows a real rate
	}

	leave := func() {}
	inView := false
	if !*quiet && ux.TTY() {
		var ok bool
		if leave, ok = tui.EnterView(); ok {
			inView = true
			tui.RegisterCleanup(leave) // Ctrl+C during the view restores the screen
			if hasCounter {
				tui.RegisterCleanup(counter.Close) // and never leaves the socket open
			}
		}
	}
	var once sync.Once
	safeLeave := func() { once.Do(leave) }
	defer safeLeave()
	if hasCounter {
		defer counter.Close()
	}

	tick := time.NewTicker(time.Duration(iv) * time.Second)
	defer tick.Stop()
	hist := make([]pinger, len(hosts))
	for {
		select {
		case <-sigCtx.Done():
			if inView {
				safeLeave()
			}
			return
		case <-tick.C:
			var rates map[string]traffic.Rate
			if hasCounter {
				rates = counter.Snapshot()
			}
			// One ping per host each tick (concurrently, so N hosts cost the
			// same wall time as one) — the per-IP ping history under each row.
			var wg sync.WaitGroup
			for i, ip := range hosts {
				wg.Add(1)
				go func(i int, ip string) {
					defer wg.Done()
					rctx, cancel := context.WithTimeout(sigCtx, timeout)
					defer cancel()
					rtt, _ := probe.Ping(rctx, ip, timeout)
					hist[i].add(rtt, histCap)
				}(i, ip)
			}
			wg.Wait()
			lines := render(hosts, rates, nic, iv, hist)
			if inView {
				tui.DrawFrame(os.Stdout, ux.Width(), lines)
			} else {
				for _, ln := range lines {
					fmt.Println(ln)
				}
			}
		}
	}
}

// parseHosts validates and de-duplicates the comma-separated target list.
func parseHosts(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if net.ParseIP(t) == nil {
			fatal(fmt.Errorf("invalid target IP %q", t))
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// render builds one dashboard frame from the latest per-host snapshot. Each
// watched host gets its traffic row plus a dim ping row underneath: last RTT,
// average, loss, and the block sparkline of every ping recorded (the history).
func render(hosts []string, rates map[string]traffic.Rate, nic string, iv int, hist []pinger) []string {
	out := make([]string, 0, len(hosts)*2+6)
	rule := "  ── " + nic + " " + strings.Repeat("─", 28)
	out = append(out, ux.C(ux.Cyan, rule))
	out = append(out, ux.C(ux.Header+ux.Bold, "  LIVE TRAFFIC")+
		ux.C(ux.Dim, fmt.Sprintf("  every %ds · Ctrl+C to stop", iv)))
	out = append(out, "")

	var totRX, totTX, totRXp, totTXp int64
	first := true
	for i, ip := range hosts {
		r := rates[ip]
		// Pad the plain IP before colouring: padding a string that already
		// carries ANSI escapes misaligns the columns by the escape length.
		label := ux.TruncPad(ip, 16)
		key := "  " + ux.C(ux.Yellow, label)
		if first {
			key = "▸ " + ux.C(ux.Yellow, label)
			first = false
		}
		dl := rateLine(r.RXBytes, r.RXPkts)
		ul := rateLine(r.TXBytes, r.TXPkts)
		out = append(out, fmt.Sprintf("%-18s   %s", key, ux.TruncPad(dl+"    "+ul, 40)))
		if hp := pingLine(ip, hist[i]); hp != "" {
			out = append(out, hp)
		}
		totRX += r.RXBytes
		totTX += r.TXBytes
		totRXp += r.RXPkts
		totTXp += r.TXPkts
	}
	out = append(out, "", ux.C(ux.Dim, "  "+strings.Repeat("─", 40)))
	out = append(out, fmt.Sprintf("  %-16s   %s",
		ux.C(ux.Bold, "TOTAL"), ux.TruncPad(rateLine(totRX, totRXp)+"    "+rateLine(totTX, totTXp), 40)))
	out = append(out, time.Now().Format("  [15:04:05]"))
	return out
}

// pingLine renders one host's ping history: last RTT, average, loss, and the
// latency sparkline of every ping recorded so far. Empty until the first ping.
func pingLine(ip string, h pinger) string {
	if h.count+h.drops == 0 {
		return ""
	}
	att := h.count + h.drops
	loss := float64(h.drops) * 100 / float64(att)
	avg := int64(0)
	if h.count > 0 {
		avg = h.total / int64(h.count)
	}
	last := "--"
	if h.last >= 0 {
		last = fmt.Sprintf("%dms", h.last)
	}
	head := fmt.Sprintf("ping %s · avg %dms · loss %.0f%%", last, avg, loss)
	spark := ux.SparkRTT(h.samples, 30)
	line := "  " + ux.TruncPad(ip, 16) + "  " + ux.C(ux.Dim, head)
	if spark != "" {
		line += "  " + ux.C(ux.Cyan, spark)
	}
	return line
}

// rateLine formats one direction as "↓ 1.2KB/s (12 pkt/s)", idle when quiet.
func rateLine(b, p int64) string {
	if b == 0 && p == 0 {
		return ux.C(ux.Dim, "idle")
	}
	return "↓ " + ux.HumanRate(b) + fmt.Sprintf(" (%d pkt/s)", p)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gnulte-traffic: %v\n", err)
	os.Exit(1)
}
