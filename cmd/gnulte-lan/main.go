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

// Command gnulte-lan is GNULTE's live LAN watch — the observation half of the
// toolkit. Tell it what to watch and it answers three questions live:
//
//  1. What is on the network? With no -t it discovers the whole LAN in a few
//     seconds (your host and the router are skipped), and every row is
//     labelled with the device identity the discovery engine found: MAC,
//     vendor, device type, hostname.
//  2. How are they doing? Per host it repaints down/up speed, packet rate and
//     latency every interval, with history sparklines.
//  3. Who is talking to whom? A passive per-interval flow engine lists the
//     top conversations, and lightweight rate/latency thresholds raise an
//     audible alarm when a host crosses the line.
//
// It is passive: it captures only frame counts and pings, and never shapes,
// spoofs or intercepts traffic — gnulte itself is the tool for that.
//
// The live view is interactive: arrows move the host cursor, ⏎ opens a detail
// pane, s re-sorts, t toggles the top talkers, a filters to alarming hosts,
// o opens the settings editor mid-watch, and q quits. Piped runs fall back to
// a plain per-tick transcript, and --export streams the same samples as CSV.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/probe"
	"gnulte-go/internal/reportdir"
	"gnulte-go/internal/settings"
	"gnulte-go/internal/sound"
	"gnulte-go/internal/traffic"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "13.3"

// hostInfo is the identity enrichment for one watched host.
type hostInfo struct {
	IP string
	// MAC and friends can be empty when the neighbor table has no entry.
	MAC    string
	Vendor string
	Host   string
	Type   string
}

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

func (h *pinger) avg() int64 {
	if h.count == 0 {
		return 0
	}
	return h.total / int64(h.count)
}

func (h *pinger) loss() float64 {
	att := h.count + h.drops
	if att == 0 {
		return 0
	}
	return float64(h.drops) * 100 / float64(att)
}

// hostStat is everything a watched host accumulates for the dashboard and the
// end-of-session report: rates, latency history, and totals.
type hostStat struct {
	ping pinger

	rxHist []int64 // per-tick received bytes (bounded), becomes the report sparkline
	txHist []int64
	peakRX int64
	peakTX int64
	totRX  int64
	totTX  int64

	alarm bool // currently breaching a threshold
}

func (s *hostStat) addRate(rx, tx int64, capN int) {
	s.totRX += rx
	s.totTX += tx
	if rx > s.peakRX {
		s.peakRX = rx
	}
	if tx > s.peakTX {
		s.peakTX = tx
	}
	s.rxHist = append(s.rxHist, rx)
	s.txHist = append(s.txHist, tx)
	if capN > 0 {
		for len(s.rxHist) > capN {
			s.rxHist = s.rxHist[1:]
		}
		for len(s.txHist) > capN {
			s.txHist = s.txHist[1:]
		}
	}
}

// lanSession is the snapshot of an entire watch session handed to the report
// writer.
type lanSession struct {
	iface  string
	subnet string
	start  time.Time
	end    time.Time
	ticks  int
	iv     int
	hosts  []string
	info   map[string]hostInfo
	stats  map[string]*hostStat
	flows  []traffic.Flow // cumulative conversation totals
	log    []string       // the plain (ANSI-stripped) dashboard history, bounded
}

func main() {
	var (
		iface     = flag.String("i", "", "network interface (default: auto-detect)")
		targets   = flag.String("t", "", "host IP(s) to watch, comma-separated (empty = watch the whole LAN)")
		interval  = flag.Int("interval", 0, "seconds between updates (0 = settings/1)")
		duration  = flag.Int("duration", 0, "auto-stop after N seconds (0 = until interrupt)")
		history   = flag.Int("history", 0, "rate/ping samples kept per host (0 = settings/60)")
		export    = flag.String("export", "", "append per-tick samples as CSV to FILE")
		noReport  = flag.Bool("no-report", false, "skip the end-of-session HTML report")
		alarmRate = flag.Int("alarm-rate", 0, "alarm hosts above N kbps (0 = settings)")
		alarmLat  = flag.Int("alarm-latency-ms", 0, "alarm hosts above N ms average ping (0 = settings)")
		quiet     = flag.Bool("q", false, "quiet: no banner, plain transcript")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\nUsage: gnulte-lan [flags]\n\n", purpose())
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nExamples:\n"+
			"  gnulte-lan                 watch the whole LAN (auto-discovery)\n"+
			"  gnulte-lan -t 192.168.1.20 watch one host\n"+
			"  gnulte-lan --duration 60 --export watch.csv --alarm-rate 500\n")
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("GNULTE-LAN v%s (Go)\n", version)
		return
	}

	cfgLoaded := settings.Default()
	if c, err := settings.Load(); err == nil {
		cfgLoaded = c
	} else {
		fmt.Fprintf(os.Stderr, "gnulte-lan: %v\n", err)
	}
	// Live-tunable knobs from settings plus CLI overrides, re-clamped after a
	// mid-watch edit (a nonzero flag always beats saved settings).
	iv, histCap, alarmRateKbps, alarmLatencyMs, timeout :=
		configLive(cfgLoaded, *interval, *history, *alarmRate, *alarmLat)

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

	// Watch list: explicit -t targets (as-is, router included if you name it)
	// or the whole LAN, discovered and lightly identified in one pass.
	var (
		hosts  []string
		info   map[string]hostInfo
		subnet string
	)
	if given := parseHosts(*targets); len(given) > 0 {
		hosts = given
		info = enrich(context.Background(), nic, hosts, discover.Neighbors(context.Background(), nic))
	} else {
		var err error
		hosts, info, subnet, err = lanWatch(context.Background(), cfg, cfgLoaded.ScanThreads, *quiet)
		if err != nil {
			fatal(err)
		}
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		sigCtx, cancel = context.WithTimeout(sigCtx, time.Duration(*duration)*time.Second)
		defer cancel()
	}

	hostSet := make(map[string]bool, len(hosts))
	for _, ip := range hosts {
		hostSet[ip] = true
	}
	counter, err := traffic.New(nic)
	if err != nil {
		// The packet counter is a garnish, not a dependency (see the traffic
		// package doc): without the raw socket the watch still shows latency,
		// identity and alarm history, just no speeds or talkers.
		fmt.Fprintf(os.Stderr, "gnulte-lan: traffic counter unavailable (%v) — running speeds-free\n", err)
	}
	// A down interface yields a nil counter (traffic.New returns (nil, nil)):
	// the dashboard then shows every host as idle instead of panicking.
	hasCounter := counter != nil
	if hasCounter {
		counter.Snapshot() // baseline so the first tick shows a real rate
	}

	// Banner and boot notes stay in the scrollback once the live view takes
	// over the alternate screen, exactly like the parent gnulte tool.
	if !*quiet {
		printBanner()
	}
	if *duration > 0 {
		fmt.Printf("  watching for %d seconds — Ctrl+C stops early\n", *duration)
	}
	if subnet != "" {
		fmt.Printf("  watching %d host(s) on %s (router skipped)\n", len(hosts), subnet)
	} else {
		fmt.Printf("  watching %d host(s)\n", len(hosts))
	}

	// CSV export (optional) opens before the loop and rows stream per tick.
	var exp *os.File
	if *export != "" {
		f, err := os.Create(*export)
		if err != nil {
			fatal(fmt.Errorf("could not open export file: %w", err))
		}
		fmt.Fprintln(f, "# time,host,down_bps,up_bps,down_pkts,up_pkts,rtt_ms,loss_pct")
		exp = f
	}

	// Live terminal: the raw-mode full-screen watch with arrow-key navigation.
	// Piped runs keep the plain per-tick transcript below.
	var scr *tui.Screen
	if !*quiet && ux.TTY() {
		if s, err := tui.Open(); err == nil {
			scr = s
			tui.RegisterCleanup(scr.Close) // Ctrl+C during the view restores the screen
			if hasCounter {
				tui.RegisterCleanup(counter.Close) // and never leaves the socket open
			}
		}
	}
	if hasCounter {
		defer counter.Close()
	}

	view := &viewState{showTalk: true, auto: subnet != ""}

	stats := make(map[string]*hostStat, len(hosts))
	for _, ip := range hosts {
		stats[ip] = &hostStat{}
	}
	sess := &lanSession{
		iface:  nic,
		subnet: subnet,
		start:  time.Now(),
		iv:     iv,
		hosts:  hosts,
		info:   info,
		stats:  stats,
	}

	tick := time.NewTicker(time.Duration(iv) * time.Second)
	defer tick.Stop()

	// The last tick's data, kept so keys can redraw between ticks.
	var (
		lastRates map[string]traffic.Rate
		lastFlows []traffic.Flow
		alarmOn   bool
	)

	// handleKey applies one key press to the view. ok reports whether anything
	// changed and must be repainted; quit ends the watch.
	handleKey := func(k tui.Key, r rune) (ok, quit bool) {
		switch k {
		case tui.KeyUp:
			if view.cursor > 0 {
				view.cursor--
				return true, false
			}
		case tui.KeyDown:
			if view.cursor+1 < view.count {
				view.cursor++
				return true, false
			}
		case tui.KeyEnter, tui.KeyTab:
			view.detail = !view.detail
			return true, false
		case tui.KeyEsc:
			if view.detail {
				view.detail = false
				return true, false
			}
			return true, true
		case tui.KeyRune:
			switch r {
			case 'q', 'Q':
				return true, true
			case 's', 'S':
				view.sortMode = (view.sortMode + 1) % 3
				view.scroll = 0
				return true, false
			case 't', 'T':
				view.showTalk = !view.showTalk
				return true, false
			case 'a', 'A':
				view.alarmOnly = !view.alarmOnly
				view.scroll = 0
				return true, false
			case 'h', 'H', '?':
				view.showHelp = !view.showHelp
				return true, false
			case 'o', 'O':
				if scr != nil {
					scr.Close()
					scr = nil
					updated, eerr := settings.Edit(cfgLoaded)
					if eerr == nil {
						cfgLoaded = updated
						if serr := settings.Save(cfgLoaded); serr != nil {
							fmt.Fprintf(os.Stderr, "gnulte-lan: settings: %v\n", serr)
						}
						iv, histCap, alarmRateKbps, alarmLatencyMs, timeout =
							configLive(cfgLoaded, *interval, *history, *alarmRate, *alarmLat)
						tick.Reset(time.Duration(iv) * time.Second)
					}
					if s, err := tui.Open(); err == nil {
						scr = s
						tui.RegisterCleanup(scr.Close)
					}
					return true, false
				}
			}
		}
		return false, false
	}

	finish := func() {
		if scr != nil {
			scr.Close()
			scr = nil
		}
		if exp != nil {
			exp.Close()
			exp = nil
		}
		sess.end = time.Now()
		if hasCounter {
			sess.flows = counter.FlowTotals()
		}
		if !*noReport {
			wrapUpReport(sess, cfgLoaded.HTMLReport)
		}
	}

	drawNow := func() {
		if scr == nil {
			return
		}
		scr.Draw(buildView(view, hosts, info, lastRates, lastFlows, hostSet, stats,
			nic, subnet, iv, sess.start, alarmOn, hasCounter, ux.Height()))
	}

	for {
		select {
		case <-sigCtx.Done():
			finish()
			return
		case <-tick.C:
			var rates map[string]traffic.Rate
			var flows []traffic.Flow
			if hasCounter {
				rates = counter.Snapshot()
				flows = counter.SnapshotFlows()
			}
			// One ping per host each tick (concurrently, so N hosts cost the
			// same wall time as one) — the per-IP latency history.
			var wg sync.WaitGroup
			for i, ip := range hosts {
				wg.Add(1)
				go func(i int, ip string) {
					defer wg.Done()
					rctx, cancel := context.WithTimeout(sigCtx, timeout)
					defer cancel()
					rtt, _ := probe.Ping(rctx, ip, timeout)
					stats[ip].ping.add(rtt, histCap)
				}(i, ip)
			}
			wg.Wait()

			alarmOn = false
			for _, ip := range hosts {
				st := stats[ip]
				r := rates[ip]
				st.addRate(r.RXBytes, r.TXBytes, histCap)
				st.alarm = breach(r, st, iv, alarmRateKbps, alarmLatencyMs)
				if st.alarm {
					alarmOn = true
				}
				if exp != nil {
					fmt.Fprintf(exp, "%s,%s,%d,%d,%d,%d,%d,%.1f\n",
						time.Now().Format(time.RFC3339), ip, bps(r.RXBytes, iv), bps(r.TXBytes, iv),
						r.RXPkts, r.TXPkts, st.ping.last, st.ping.loss())
				}
			}
			// One alarm chirp per tick at most — a wall of beeps is not help.
			if alarmOn && cfgLoaded.Beeps {
				sound.Beep(720, 80*time.Millisecond)
			}
			lastRates, lastFlows = rates, flows

			// The transcript (plain, ANSI-free) is what travels into the HTML
			// report and the scrollback in non-interactive runs.
			lines := buildLines(hosts, info, rates, flows, hostSet, stats, nic, iv)
			if scr != nil {
				drawNow()
			} else {
				for _, ln := range lines {
					fmt.Println(ln)
				}
			}
			sess.ticks++
			for _, ln := range lines {
				sess.log = append(sess.log, ux.StripAnsi(ln))
			}
			if capLines := 3000; len(sess.log) > capLines {
				sess.log = sess.log[len(sess.log)-capLines:]
			}
		default:
		}

		// Between ticks, fold key presses into the loop without blocking it.
		if scr != nil {
			k, r := scr.Poll(30)
			if k != tui.KeyNone {
				if ok, quit := handleKey(k, r); ok {
					drawNow()
					if quit {
						finish()
						return
					}
				}
			}
		} else {
			time.Sleep(40 * time.Millisecond)
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

// lanWatch discovers the live hosts on the LAN and enriches their identity.
// The default gateway and this machine are never watched — the router is your
// way in and out, not a dashboard entry.
func lanWatch(ctx context.Context, cfg netutil.Config, threads int, quiet bool) ([]string, map[string]hostInfo, string, error) {
	subnet := subnetCIDR(cfg.SelfIP, cfg.Netmask)
	if subnet == "" {
		return nil, nil, "", fmt.Errorf("could not derive the LAN subnet (%s/%s)", cfg.SelfIP, cfg.Netmask)
	}
	rangeSet := map[string]bool{}
	for _, ip := range rangeIPs(subnet) {
		rangeSet[ip] = true
	}
	skip := map[string]bool{cfg.SelfIP: true, cfg.Gateway: true}

	var targets []string
	for ip := range rangeSet {
		if !skip[ip] {
			targets = append(targets, ip)
		}
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return nil, nil, "", fmt.Errorf("nothing to watch on %s", subnet)
	}
	if !quiet {
		fmt.Printf("  scanning %s for live hosts…\n", subnet)
	}
	live := discover.PingSweep(ctx, targets, threads, func(done, alive int) {
		if !quiet {
			fmt.Printf("\r  ♻ %d/%d · %d alive   ", done, len(targets), alive)
		}
	})
	if !quiet {
		fmt.Println()
	}

	// Merge ARP-table neighbours the ICMP sweep missed (devices that quietly
	// ignore ping but are very much on the link).
	neigh := discover.Neighbors(ctx, cfg.Interface)
	seen := map[string]bool{}
	for _, ip := range live {
		seen[ip] = true
	}
	var extra []string
	for ip := range neigh {
		if !skip[ip] && rangeSet[ip] && !seen[ip] {
			extra = append(extra, ip)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		live = append(live, extra...)
	}
	if len(live) == 0 {
		return nil, nil, "", fmt.Errorf("no live hosts found on %s", subnet)
	}
	sort.Strings(live)
	info := enrich(ctx, cfg.Interface, live, neigh)
	if !quiet {
		fmt.Printf("  watching %d host(s) — the router %s is left out\n", len(live), cfg.Gateway)
	}
	return live, info, subnet, nil
}

// enrich fills each watched host's identity in parallel: MAC (neighbor table),
// vendor (IEEE OUI), hostname (reverse DNS + .local) and a device-type guess.
func enrich(ctx context.Context, iface string, hosts []string, neigh map[string]string) map[string]hostInfo {
	out := map[string]hostInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			mac := neigh[ip]
			vendor := discover.VendorFor(mac)
			host := discover.ResolveHost(ctx, ip)
			typ := discover.Classify(vendor, host)
			mu.Lock()
			out[ip] = hostInfo{IP: ip, MAC: mac, Vendor: vendor, Host: host, Type: typ}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

// subnetCIDR turns the route's IPv4 + netmask into a CIDR string such as
// "192.168.100.0/24".
func subnetCIDR(ip, mask string) string {
	ii := net.ParseIP(ip).To4()
	mi := net.ParseIP(mask).To4()
	if ii == nil || mi == nil {
		return ""
	}
	ones, bits := net.IPMask(mi).Size()
	if bits != 32 || ones < 0 || ones > 32 {
		return ""
	}
	n := &net.IPNet{IP: ii.Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}
	return n.String()
}

// rangeIPs lists every usable address in a CIDR (network and broadcast
// included — the sweep simply finds them dead).
func rangeIPs(cidr string) []string {
	hosts, err := netutil.HostsInCIDR(cidr)
	if err != nil {
		return nil
	}
	return hosts
}

// breach reports whether one host is over either alarm today.
func breach(r traffic.Rate, st *hostStat, iv int, rateKbps, latMs int) bool {
	if rateKbps > 0 {
		down := bps(r.RXBytes, iv) * 8 / 1000
		up := bps(r.TXBytes, iv) * 8 / 1000
		if down > int64(rateKbps) || up > int64(rateKbps) {
			return true
		}
	}
	if latMs > 0 && st.ping.count > 0 && st.ping.avg() > int64(latMs) {
		return true
	}
	return false
}

func bps(bytes int64, iv int) int64 {
	if iv <= 0 {
		return 0
	}
	return bytes / int64(iv)
}

// buildLines renders one full dashboard frame: a traffic row and identity row
// per host (compact single lines when the LAN is big), the interval's top
// talkers, then totals. Returns the lines and whether any host is alarming.
func buildLines(hosts []string, info map[string]hostInfo, rates map[string]traffic.Rate,
	flows []traffic.Flow, hostSet map[string]bool, stats map[string]*hostStat,
	nic string, iv int) []string {

	// Dense mode keeps many hosts on screen at one line each. Sparse mode
	// gives every host a full identity line and a latency sparkline.
	dense := len(hosts) > 8
	out := make([]string, 0, len(hosts)*2+10)
	rule := "  ── " + nic + " " + strings.Repeat("─", 28)
	out = append(out, ux.C(ux.Cyan, rule))
	if !dense {
		out = append(out, ux.C(ux.Header+ux.Bold, "  LIVE LAN WATCH")+
			ux.C(ux.Dim, fmt.Sprintf("  every %ds · Ctrl+C to stop", iv)))
	} else {
		out = append(out, ux.C(ux.Header+ux.Bold, "  LIVE LAN WATCH")+
			ux.C(ux.Dim, fmt.Sprintf("  every %ds · %d hosts · Ctrl+C to stop", iv, len(hosts))))
	}
	out = append(out, "")

	var totRX, totTX, totRXp, totTXp int64
	var anyAlarm bool
	first := true
	for _, ip := range hosts {
		r := rates[ip]
		st := stats[ip]
		totRX += r.RXBytes
		totTX += r.TXBytes
		totRXp += r.RXPkts
		totTXp += r.TXPkts
		if st.alarm {
			anyAlarm = true
		}
		rows := hostRowLines(ip, info[ip], r, st, iv, dense)
		if first {
			rows = cursorLines(rows)
			first = false
		}
		out = append(out, rows...)
	}

	// Top talkers of the interval, best five conversations by combined volume.
	if len(flows) > 0 {
		sort.Slice(flows, func(i, j int) bool { return flows[i].Total() > flows[j].Total() })
		out = append(out, "", ux.C(ux.Bold, "  TOP TALKERS")+ux.C(ux.Dim, "  this interval · bold = watched host"))
		n := 5
		if len(flows) < n {
			n = len(flows)
		}
		for _, f := range flows[:n] {
			out = append(out, flowLine(f, hostSet, iv))
		}
	}

	out = append(out, "", ux.C(ux.Dim, "  "+strings.Repeat("─", 40)))
	out = append(out, fmt.Sprintf("  %-16s   %s",
		ux.C(ux.Bold, "TOTAL"), ux.TruncPad(rateLine(totRX, totRXp, iv)+"    "+upRateLine(totTX, totTXp, iv), 40)))
	if anyAlarm {
		out = append(out, ux.C(ux.Red, "  ⚠ one or more hosts are over their alarm threshold"))
	}
	out = append(out, time.Now().Format("  [15:04:05]"))
	return out
}

// identityLine renders "MAC · vendor · type · hostname", gracefully dim and
// empty when nothing was resolved.
func identityLine(h hostInfo) string {
	var parts []string
	if h.MAC != "" {
		parts = append(parts, h.MAC)
	}
	if h.Vendor != "" {
		parts = append(parts, h.Vendor)
	}
	if h.Type != "" {
		parts = append(parts, h.Type)
	}
	if h.Host != "" {
		parts = append(parts, h.Host)
	}
	if len(parts) == 0 {
		return ""
	}
	return ux.C(ux.Dim, strings.Join(parts, " · "))
}

// idShort is identityLine truncated hard to one label for dense mode.
func idShort(h hostInfo) string {
	var parts []string
	if h.Type != "" {
		parts = append(parts, h.Type)
	}
	if h.Host != "" {
		parts = append(parts, h.Host)
	}
	if h.Vendor != "" {
		parts = append(parts, h.Vendor)
	}
	if h.Host == "" && h.Type == "" && h.Vendor == "" && h.MAC != "" {
		parts = append(parts, h.MAC)
	}
	if len(parts) == 0 {
		return ""
	}
	s := strings.Join(parts, "·")
	if len(s) > 24 {
		s = s[:24] + "…"
	}
	return s
}

// pingLine renders one host's latency history: last RTT, average, loss, and
// the sparkline of every ping recorded so far.
func pingLine(ip string, h pinger) string {
	if h.count+h.drops == 0 {
		return ""
	}
	last := "--"
	if h.last >= 0 {
		last = fmt.Sprintf("%dms", h.last)
	}
	head := fmt.Sprintf("ping %s · avg %dms · loss %.0f%%", last, h.avg(), h.loss())
	spark := ux.SparkRTT(h.samples, 30)
	line := "  " + ux.TruncPad(ip, 16) + "  " + ux.C(ux.Dim, head)
	if spark != "" {
		line += "  " + ux.C(ux.Cyan, spark)
	}
	return line
}

// pingShort is the dense-mode latency tail: "p 23ms · 0%".
func pingShort(st *hostStat) string {
	h := st.ping
	if h.count+h.drops == 0 {
		return ux.C(ux.Dim, "p --")
	}
	last := h.last
	if last < 0 {
		return ux.C(ux.Dim, fmt.Sprintf("p ✗ · loss %.0f%%", h.loss()))
	}
	return ux.C(ux.Dim, fmt.Sprintf("p %dms · %.0f%%", last, h.loss()))
}

// flowView turns a conversation into (localIP, peer, down, up) as seen by the
// watch list: the watched endpoint is "local" (its received bytes are down),
// A's side wins when both or neither end is being watched.
func flowView(f traffic.Flow, watched map[string]bool) (ip, peer string, down, up int64) {
	switch {
	case watched[endpointHost(f.A)] && watched[endpointHost(f.B)]:
		return endpointHost(f.A), endpointHost(f.B), f.BA, f.AB
	case watched[endpointHost(f.B)]:
		return endpointHost(f.B), endpointHost(f.A), f.AB, f.BA
	default:
		return endpointHost(f.A), endpointHost(f.B), f.BA, f.AB
	}
}

// flowLine renders one conversation as one dashboard line, bolding whichever
// endpoint is a watched host (both when the conversation is purely LAN-side)
// and showing the rates from the watched host's view (down = toward it,
// up = from it). Endpoints are padded before colouring so the ANSI escapes
// never shift the columns.
func flowLine(f traffic.Flow, watched map[string]bool, iv int) string {
	left := ux.TruncPad(f.A, 26)
	right := ux.TruncPad(f.B, 26)
	_, _, down, up := flowView(f, watched)
	aW, bW := watched[endpointHost(f.A)], watched[endpointHost(f.B)]
	switch {
	case aW && bW:
		left, right = ux.C(ux.Bold, left), ux.C(ux.Bold, right)
	case bW:
		left, right = ux.C(ux.Bold, right), left
	case aW:
		left = ux.C(ux.Bold, left)
	}
	ds := "—"
	if down > 0 {
		ds = ux.HumanRate(bps(down, iv))
	}
	us := "—"
	if up > 0 {
		us = ux.HumanRate(bps(up, iv))
	}
	dl := ux.TruncPad("↓ "+ds, 12)
	ul := ux.TruncPad("↑ "+us, 12)
	return "   " + left + " ⇄ " + right + "  " + dl + "  " + ul
}

// rateLine formats one direction as "↓ 1.2KB/s (12 pkt/s)", idle when quiet.
func rateLine(b, p int64, iv int) string { return dirLine("↓", b, p, iv) }

// upRateLine is rateLine for the away-from-host direction ("↑ …").
func upRateLine(b, p int64, iv int) string { return dirLine("↑", b, p, iv) }

func dirLine(mark string, b, p int64, iv int) string {
	if b == 0 && p == 0 {
		return ux.C(ux.Dim, "idle")
	}
	tail := ""
	if p > 0 {
		tail = fmt.Sprintf(" (%d pkt/s)", p)
	}
	return mark + " " + ux.HumanRate(bps(b, iv)) + tail
}

// wrapUpReport writes the end-of-session HTML report into the report hub,
// asking first when a human is at the keyboard.
func wrapUpReport(sess *lanSession, htmlDefault bool) {
	path := reportdir.DefaultPathCount(reportdir.GNULTELan, "gnulte-lan-report", len(sess.hosts))
	if ux.TTY() {
		defaultYes := "y"
		if !htmlDefault {
			defaultYes = "n"
		}
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\nWrite the GNULTE-LAN report to %s? [Y/n] ", path)
		ans, _ := reader.ReadString('\n')
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans == "" {
			ans = defaultYes
		}
		if ans != "y" && ans != "yes" {
			fmt.Println("Report skipped.")
			return
		}
	} else if !htmlDefault {
		return // scripted (non-TTY) runs only file a report when settings allow
	}
	if err := writeReport(path, sess); err != nil {
		fmt.Fprintf(os.Stderr, "gnulte-lan: could not write report: %v\n", err)
		return
	}
	fmt.Printf("  Report: %s\n", path)
}

// configLive clamps settings (History, TrafficSec, TimeoutMs, alarm thresholds)
// into the dashboards' operating ranges. Nonzero flag values win over the
// saved settings so --interval/--history/--alarm-* keep their documented edge.
func configLive(c settings.Config, intervalFlag, historyFlag, alarmRateFlag, alarmLatencyFlag int) (iv, histCap, alarmRateKbps, alarmLatencyMs int, timeout time.Duration) {
	iv = ux.Clamp(c.TrafficSec, 1, 10)
	if intervalFlag > 0 {
		iv = ux.Clamp(intervalFlag, 1, 10)
	}
	histCap = ux.Clamp(c.History, 10, 240)
	if historyFlag > 0 {
		histCap = ux.Clamp(historyFlag, 10, 240)
	}
	timeout = time.Duration(ux.Clamp(c.TimeoutMs, 100, 60000)) * time.Millisecond
	alarmRateKbps = ux.Clamp(c.AlarmRateKbps, 0, 1000000)
	if alarmRateFlag > 0 {
		alarmRateKbps = ux.Clamp(alarmRateFlag, 0, 1000000)
	}
	alarmLatencyMs = ux.Clamp(c.AlarmLatencyMs, 0, 60000)
	if alarmLatencyFlag > 0 {
		alarmLatencyMs = ux.Clamp(alarmLatencyFlag, 0, 60000)
	}
	return
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gnulte-lan: %v\n", err)
	os.Exit(1)
}
