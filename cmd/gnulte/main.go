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

// Command gnulte is the Go rewrite of the GNULTE traffic engine.
//
// It ARP-spoofs authorized targets, optionally shapes/impairs their traffic
// with tc, or fully blocks them, and monitors reachability while the test
// runs. Use only on networks you own or are authorized to test.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/engine"
	"gnulte-go/internal/monitor"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/safety"
)

const version = "10.0"

// profiles mirrors the Bash toolkit's presets: latency|jitter|loss|dup|reorder|bandwidth.
var profiles = map[string][6]int{
	"gaming":    {1500, 300, 2, 0, 0, 0},
	"streaming": {2500, 500, 5, 0, 0, 0},
	"voip":      {3000, 200, 0, 0, 5, 0},
	"web":       {2000, 400, 3, 0, 0, 0},
	"extreme":   {5000, 1000, 10, 5, 5, 0},
	"throttle":  {500, 200, 0, 0, 0, 512},
}

const profileNames = "gaming, streaming, voip, web, extreme, throttle"

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func main() {
	var (
		ifaceArg  = flag.String("i", "", "network interface (default: auto-detect)")
		targets   = flag.String("t", "", "target IP(s), comma-separated")
		macArg    = flag.String("m", "", "target by MAC address (resolved via ARP)")
		rangeCIDR = flag.String("r", "", "target an entire subnet CIDR (e.g. 192.168.1.0/24)")
		whitelist = flag.String("w", "", "exclude IP(s) from a range attack (comma-separated)")

		latency   = flag.Int("l", 0, "base delay in ms")
		jitter    = flag.Int("j", 0, "random variation in ms")
		loss      = flag.Int("p", 0, "packet drop percent")
		dup       = flag.Int("d", 0, "duplicate packets percent")
		reorder   = flag.Int("e", 0, "out-of-order packets percent")
		bandwidth = flag.Int("b", 0, "bandwidth cap in kbps (0 = unlimited)")

		profile     = flag.String("profile", "", "preset impairment profile (see --list-profiles)")
		listProf    = flag.Bool("list-profiles", false, "list preset profiles and exit")
		randomArg   = flag.Bool("random", false, "randomize latency/jitter/loss every second")
		exportArg   = flag.String("export", "", "stream per-second results to a CSV file")
		dupcheckArg = flag.Bool("dupcheck", false, "scan the LAN for duplicate IPs / ARP conflicts and exit")
		reportDir   = flag.String("report", "", "write a post-test report (report.txt + report.html) to DIR")

		duration   = flag.Int("duration", 0, "auto-stop after N seconds (0 = until interrupt)")
		captureArg = flag.String("c", "", "capture target traffic with tcpdump to FILE ('-' = stdout)")
		block      = flag.Bool("block", false, "fully block the target (no forwarding) instead of shaping")
		soundArg   = flag.Bool("sound", false, "beep per ping result")
		force      = flag.Bool("force", false, "skip interactive confirmations (require explicit flags)")
		noBanner   = flag.Bool("no-banner", false, "skip the banner (alias: --minimal)")
		quiet      = flag.Bool("q", false, "quiet: results only")
		showDocs   = flag.Bool("docs", false, "print the safety documents and exit")
		resetSafe  = flag.Bool("reset-safety", false, "remove the acceptance record and exit")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.StringVar(ifaceArg, "interface", "", "network interface (default: auto-detect)")
	flag.StringVar(targets, "target", "", "target IP(s), comma-separated")
	flag.StringVar(macArg, "mac", "", "target by MAC address (resolved via ARP)")
	flag.StringVar(rangeCIDR, "range", "", "target an entire subnet CIDR (e.g. 192.168.1.0/24)")
	flag.StringVar(whitelist, "whitelist", "", "exclude IP(s) from a range attack (comma-separated)")
	flag.IntVar(latency, "latency", 0, "base delay in ms")
	flag.IntVar(jitter, "jitter", 0, "random variation in ms")
	flag.IntVar(loss, "loss", 0, "packet drop percent")
	flag.IntVar(dup, "duplicate", 0, "duplicate packets percent")
	flag.IntVar(reorder, "reorder", 0, "out-of-order packets percent")
	flag.IntVar(bandwidth, "bandwidth", 0, "bandwidth cap in kbps (0 = unlimited)")
	flag.StringVar(captureArg, "capture", "", "capture target traffic with tcpdump to FILE ('-' = stdout)")
	flag.BoolVar(noBanner, "minimal", false, "skip the banner (alias: --no-banner)")
	flag.BoolVar(quiet, "quiet", false, "quiet: results only")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("GNULTE v%s (Go)\n", version)
		return
	}
	if *listProf {
		fmt.Println("Preset impairment profiles (latency|jitter|loss|dup|reorder|bandwidth-kbps):")
		for _, name := range []string{"gaming", "streaming", "voip", "web", "extreme", "throttle"} {
			p := profiles[name]
			fmt.Printf("  %-10s %4dms jitter %3dms loss %2d%% dup %d%% reorder %d%% cap %5dkbps\n",
				name, p[0], p[1], p[2], p[3], p[4], p[5])
		}
		return
	}
	if *showDocs {
		safety.ShowDocs(safety.AllDocNames())
		return
	}
	if *resetSafe {
		if err := safety.Reset(); err != nil {
			fatal(err)
		}
		return
	}
	if !*noBanner && !*quiet && os.Getenv("GNULTE_AS_ROOT") != "1" {
		printBanner()
	}
	if err := safety.EnsureAccepted(); err != nil {
		fatal(err)
	}

	// Administrator-privilege handshake. A regular user launch prints the
	// banner, shows the admin box and re-executes itself with sudo (password
	// prompted in the terminal). The elevated child skips all of that via
	// GNULTE_AS_ROOT, so the banner only ever appears once.
	if os.Geteuid() != 0 && os.Getenv("GNULTE_AS_ROOT") != "1" {
		if !stdinIsTTY() {
			fatal(fmt.Errorf("GNULTE needs root — run it from a terminal so it can request administrator access, or invoke it with sudo"))
		}
		adminBox()
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
	if os.Getenv("GNULTE_AS_ROOT") == "1" {
		fmt.Println("  " + okText("Sudo access granted — running with administrator privileges."))
		fmt.Println()
	}

	cfg, err := netutil.DefaultRoute()
	if err != nil {
		fatal(fmt.Errorf("network detection failed: %w", err))
	}
	if *ifaceArg != "" {
		cfg.Interface = *ifaceArg
	}

	if *dupcheckArg {
		runDupcheck(cfg.Interface)
		return
	}

	if !*noBanner && !*quiet {
		bootSeq(cfg)
		quickRef()
	}

	interactive := stdinIsTTY() && !*force
	scanCtx := context.Background()
	var targetsList []string
	if interactive && *targets == "" && *macArg == "" && *rangeCIDR == "" {
		targetsList = scanAndSelect(scanCtx, cfg)
	} else {
		var err error
		targetsList, err = resolveTargets(*targets, *macArg, *rangeCIDR, *whitelist, cfg)
		if err != nil {
			fatal(err)
		}
	}

	ec := engine.Config{
		Interface:     cfg.Interface,
		Gateway:       cfg.Gateway,
		Targets:       targetsList,
		Mode:          engine.ModeShape,
		LatencyMS:     *latency,
		JitterMS:      *jitter,
		LossPct:       *loss,
		DupPct:        *dup,
		ReorderPct:    *reorder,
		BandwidthKbps: *bandwidth,
		CaptureFile:   *captureArg,
		Quiet:         *quiet,
	}
	if *rangeCIDR != "" {
		ec.RangeStart = cfg.Gateway // gateway is never dropped in a range sweep
	}
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
	})
	if *profile != "" {
		p, ok := profiles[*profile]
		if !ok {
			fatal(fmt.Errorf("unknown profile %q (available: %s)", *profile, profileNames))
		}
		setParam := map[string]func(int){
			"latency":   func(v int) { ec.LatencyMS = v },
			"jitter":    func(v int) { ec.JitterMS = v },
			"loss":      func(v int) { ec.LossPct = v },
			"duplicate": func(v int) { ec.DupPct = v },
			"reorder":   func(v int) { ec.ReorderPct = v },
			"bandwidth": func(v int) { ec.BandwidthKbps = v },
		}
		fields := []string{"latency", "jitter", "loss", "duplicate", "reorder", "bandwidth"}
		for i, f := range fields {
			if !explicit[f] {
				setParam[f](p[i])
			}
		}
	}
	if *block {
		ec.Mode = engine.ModeBlock
	}
	if interactive && ec.Mode != engine.ModeBlock {
		paramsWizard(&ec, duration)
	}
	if problems := engine.DepsCheck(&ec); len(problems) > 0 {
		fatal(fmt.Errorf("%s", strings.Join(problems, "\n  • ")))
	}
	if err := ec.Validate(); err != nil {
		fatal(err)
	}

	if !*quiet {
		safetySummary(&ec, *randomArg, *profile != "")
	}
	if !*force {
		if !stdinIsTTY() {
			fatal(fmt.Errorf("this test needs interactive confirmation — run gnulte from a terminal, or pass --force with explicit flags"))
		}
		if !confirmStart() {
			fmt.Println("Aborted — nothing was started.")
			return
		}
	}

	if !*quiet {
		fmt.Println("  " + okText("Elevated session active — test operations run with root privileges."))
	}
	sess, err := engine.Start(ec)
	if err != nil {
		fatal(err)
	}
	if !*quiet {
		fmt.Println("test running — Ctrl+C to stop and restore normal connectivity")
		fmt.Println()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var monCtx context.Context
	if *duration > 0 {
		var dur CancelFunc
		monCtx, dur = context.WithTimeout(ctx, time.Duration(*duration)*time.Second)
		defer dur()
	} else {
		monCtx = ctx
	}

	mon := &monitor.Monitor{
		Targets:    targetsList,
		Interval:   time.Second,
		Sound:      *soundArg,
		Quiet:      *quiet,
		ExportFile: *exportArg,
	}
	if *randomArg && ec.Mode == engine.ModeShape {
		mon.OnTick = func() {
			// Toggle parameters mid-test as the Bash toolkit did: random walk
			// latency/jitter around the base values plus a random loss level.
			nc := ec
			nc.LatencyMS = clamp(ec.LatencyMS+rand.Intn(1000)-500, 100, 60000)
			nc.JitterMS = clamp(ec.JitterMS+rand.Intn(400)-200, 50, 60000)
			nc.LossPct = rand.Intn(10)
			_ = sess.UpdateParams(nc)
		}
	}
	startTime := time.Now()
	_ = mon.Run(monCtx)

	endTime := time.Now()
	sess.Stop()
	if *reportDir != "" {
		if err := writeReport(*reportDir, mon.Results, startTime, endTime); err != nil {
			fmt.Fprintf(os.Stderr, "gnulte: report: %v\n", err)
		} else if !*quiet {
			fmt.Printf("report written to %s\n", *reportDir)
		}
	}
	if !*quiet {
		fmt.Println("\nTest finished — normal connectivity restored.")
	}
}

type CancelFunc = context.CancelFunc

// resolveTargets combines --target/--mac/--range into a target list.
func resolveTargets(tAmt, tMac, rCIDR, wl string, cfg netutil.Config) ([]string, error) {
	var list []string
	excluded := map[string]bool{cfg.SelfIP: true}
	for _, w := range splitCSV(wl) {
		if w != "" {
			excluded[w] = true
		}
	}

	switch {
	case tAmt != "":
		for _, t := range splitCSV(tAmt) {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if net.ParseIP(t) == nil {
				return nil, fmt.Errorf("invalid target IP %q", t)
			}
			list = append(list, t)
		}
	case tMac != "":
		ip, err := ipForMAC(cfg.Interface, tMac)
		if err != nil {
			return nil, err
		}
		list = append(list, ip)
	case rCIDR != "":
		iplist, err := netutil.HostsInCIDR(rCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid range: %w", err)
		}
		// Ping sweep so the engine only spoofs devices that actually exist.
		live := discover.PingSweep(context.Background(), iplist, 64)
		for _, ip := range live {
			if !excluded[ip] {
				list = append(list, ip)
			}
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("no live hosts found in %s", rCIDR)
		}
	default:
		// Fall back to the gateway (an explicit, safe single target).
		if cfg.Gateway == "" {
			return nil, fmt.Errorf("no target given and gateway is unknown; pass -t")
		}
		list = append(list, cfg.Gateway)
	}

	uniq := make([]string, 0, len(list))
	seen := map[string]bool{}
	for _, ip := range list {
		if !seen[ip] {
			seen[ip] = true
			uniq = append(uniq, ip)
		}
	}
	return uniq, nil
}

// ipForMAC finds the IP that currently has the given MAC.
func ipForMAC(iface, mac string) (string, error) {
	neighbors := discover.Neighbors(context.Background(), iface)
	want := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
	for ip, m := range neighbors {
		if strings.ToUpper(strings.ReplaceAll(m, ":", "")) == want {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no device with MAC %s is in the ARP table; ping the LAN first", mac)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func safetySummary(c *engine.Config, randomize, profile bool) {
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Println("                    CONFIRM TEST")
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Printf("  Target(s)   : %s\n", strings.Join(c.Targets, ", "))
	fmt.Printf("  Interface   : %s\n", c.Interface)
	fmt.Printf("  Gateway     : %s\n", c.Gateway)
	if c.Mode == engine.ModeBlock {
		fmt.Println("  Mode        : 100% BLOCK — packets are NOT forwarded")
	} else {
		fmt.Printf("  Impairment  : latency=%dms jitter=%dms loss=%d%% dup=%d%% reorder=%d%% cap=%dkbps\n",
			c.LatencyMS, c.JitterMS, c.LossPct, c.DupPct, c.ReorderPct, c.BandwidthKbps)
		if randomize {
			fmt.Println("                (RANDOM mode: values are re-rolled every second)")
		}
		if profile {
			fmt.Println("                (profile preset applied — explicit flags override)")
		}
	}
	if c.CaptureFile != "" {
		fmt.Printf("  Capture     : %s (may store UNENCRYPTED data — treat as a secret)\n", c.CaptureFile)
	}
	fmt.Println("  Warning     : this disrupts the target's connectivity and sees its traffic.")
	fmt.Println("  Use only where you are authorized and the activity is lawful.")
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Println()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gnulte: %v\n", err)
	os.Exit(1)
}

func runDupcheck(iface string) {
	neighbors := discover.Neighbors(context.Background(), iface)
	if len(neighbors) == 0 {
		fmt.Println("ARP table is empty; ping the LAN first, or run as root for arp-scan boost.")
		return
	}
	type entry struct{ ips []string }
	macMap := map[string][]string{}
	for ip, mac := range neighbors {
		macMap[mac] = append(macMap[mac], ip)
	}
	var dupCount int
	ips := make([]string, 0, len(neighbors))
	for ip := range neighbors {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	fmt.Println("Duplicate-IP / ARP-conflict scan:")
	for _, ip := range ips {
		mac := neighbors[ip]
		peers := macMap[mac]
		if len(peers) > 1 {
			dupCount++
			fmt.Printf("  CONFLICT  %-16s  MAC %-18s  also used by %s\n",
				ip, mac, strings.Join(peers, ", "))
		}
	}
	if dupCount == 0 {
		fmt.Println("  No duplicate-IP or ARP conflicts detected.")
	} else {
		fmt.Printf("\n%d conflict(s) found — investigate before trusting the network.\n", dupCount)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `GNULTE v%s (Go) — authorized network testing only

Usage:
  gnulte [options]        (prompts for sudo on first launch)
  sudo gnulte [options]

Targeting:
  -t, --target IP       target IP(s), comma-separated
  -m, --mac MAC         target by MAC address
  -r, --range CIDR      target an entire subnet (e.g. 192.168.1.0/24)
  -w, --whitelist IP    exclude IP(s) from a range (comma-separated)

Parameters:
  -l, --latency MS      base delay in ms
  -j, --jitter MS       random variation in ms
  -p, --loss %%          packet drop %%
  -d, --duplicate %%    duplicate packets %%
  -e, --reorder %%      out-of-order packets %%
  -b, --bandwidth KBPS  bandwidth cap in kbps (0 = unlimited)

Profiles:
      --profile NAME      apply a preset (gaming|streaming|voip|web|extreme|throttle)
      --list-profiles     list the preset profiles and exit
      --random            re-roll latency/jitter/loss every second

Advanced:
      --duration SECONDS  auto-stop after N seconds
  -c, --capture FILE      capture target traffic with tcpdump ('.'- = stdout)
      --block             fully block the target (no forwarding)
      --sound             beep per ping result
      --export FILE       stream per-second results to a CSV file
      --report DIR         write a post-test report (report.txt + report.html)
      --force             skip interactive confirmations
      --no-banner         skip the banner (alias: --minimal)
  -q, --quiet             results only
      --dupcheck          scan LAN for duplicate IPs / ARP conflicts and exit
      --docs              print the safety documents and exit
      --reset-safety      remove the acceptance record and exit
      --version           print version and exit
  -h, --help              show this help
`, version)
}
