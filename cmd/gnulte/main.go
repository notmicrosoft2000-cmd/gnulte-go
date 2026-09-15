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
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/engine"
	"gnulte-go/internal/monitor"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/settings"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "11.0"

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
		targets   = flag.String("t", "", "target IP(s), comma-separated (hostnames and .local names resolve automatically)")
		macArg    = flag.String("m", "", "target by MAC address (resolved via ARP)")
		rangeCIDR = flag.String("r", "", "target an entire subnet CIDR (e.g. 192.168.1.0/24)")
		whitelist = flag.String("w", "", "exclude IP(s) from a range attack (comma-separated)")
		devTypes  = flag.String("device-type", "", "target every LAN device of these kinds (comma-separated, e.g. phone,router)")
		vendors   = flag.String("vendor", "", "target every LAN device with a matching vendor name (substring, e.g. Xiaomi)")

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
		reportFile  = flag.String("report", "", "write the post-test HTML report (full log history) to FILE")
		noReport    = flag.Bool("no-report", false, "skip writing the post-test HTML report")
		probePorts  = flag.String("probe-ports", "", "TCP fallback probe ports for ICMP-filtered targets, e.g. 443,80,53")

		duration    = flag.Int("duration", 0, "auto-stop after N seconds (0 = until interrupt)")
		captureArg  = flag.String("c", "", "capture target traffic with tcpdump to FILE ('-' = stdout)")
		block       = flag.Bool("block", false, "fully block the target (no forwarding) instead of shaping")
		soundArg    = flag.Bool("sound", true, "beep per ping result, pitch scaled by latency (default: on)")
		noSound     = flag.Bool("no-sound", false, "disable the per-ping beeps")
		interval    = flag.Int("interval", 1, "seconds between pings (1-60)")
		force       = flag.Bool("force", false, "skip interactive confirmations (require explicit flags)")
		noBanner    = flag.Bool("no-banner", false, "skip the banner (alias: --minimal)")
		quiet       = flag.Bool("q", false, "quiet: results only")
		showDocs    = flag.Bool("docs", false, "print the safety documents and exit")
		resetSafe   = flag.Bool("reset-safety", false, "remove the acceptance record and exit")
		showVer     = flag.Bool("version", false, "print version and exit")
		settingsArg = flag.Bool("settings", false, "open the settings editor (saved defaults) and exit")
		trafficWin  = flag.Bool("traffic-window", false, "with 2+ targets, open the traffic & speed monitor in a separate terminal window")
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

	// Which flags the operator typed (settings defaults only fill the rest).
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
	})
	// Canonical aliases: -l, -j, -p, -d, -e, -b are the short forms of
	// the impairment fields; mark their long names as "explicit" when the
	// short form was typed, so profile presets don't silently override them.
	if explicit["l"] {
		explicit["latency"] = true
	}
	if explicit["j"] {
		explicit["jitter"] = true
	}
	if explicit["p"] {
		explicit["loss"] = true
	}
	if explicit["d"] {
		explicit["duplicate"] = true
	}
	if explicit["e"] {
		explicit["reorder"] = true
	}
	if explicit["b"] {
		explicit["bandwidth"] = true
	}

	// Persisted defaults are read once, up front, so every default decision
	// below (interface, interval, beeps, report) can consult them.
	prefs, err := settings.Load()
	if err != nil {
		fatal(fmt.Errorf("settings: %v", err))
	}

	// The settings editor is a full-screen terminal TU/t and writes straight
	// back to the config file, then hands control back to the shell.
	if *settingsArg {
		if !stdinIsTTY() {
			fatal(fmt.Errorf("the settings editor needs a real terminal"))
		}
		updated, err := settings.Edit(prefs)
		if err != nil {
			if err == tui.ErrNotTerminal {
				fatal(fmt.Errorf("the settings editor needs a real terminal"))
			}
			fatal(err)
		}
		if err := settings.Save(updated); err != nil {
			fatal(fmt.Errorf("settings: %v", err))
		}
		fmt.Printf("settings saved to %s\n", settings.Path())
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

	// Interrupt handling. A single Ctrl+C cancels the running session and
	// triggers a full state restore; a second one exits immediately, because a
	// stuck child must never leave the network half-shaped.
	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()
	go func() {
		<-sigCtx.Done()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		select {
		case <-ch:
			fmt.Fprintln(os.Stderr, "\ngnulte: forced exit on second interrupt — state restore interrupted.")
			os.Exit(130)
		case <-time.After(8 * time.Second):
		}
	}()

	cfg, err := netutil.DefaultRoute()
	if err != nil {
		fatal(fmt.Errorf("network detection failed: %w", err))
	}
	if *ifaceArg != "" {
		cfg.Interface = *ifaceArg
	} else if prefs.Interface != "" {
		cfg.Interface = prefs.Interface
	}

	if *dupcheckArg {
		runDupcheck(cfg.Interface)
		return
	}

	interactive := stdinIsTTY() && !*force
	if !*noBanner && !*quiet {
		bootSeq(cfg)
		if !interactive {
			quickRef()
		}
	}

	scanCtx := sigCtx
	var targetsList []string
	switch {
	case *devTypes != "" || *vendors != "":
		var err error
		targetsList, err = matchDevices(scanCtx, cfg, *devTypes, *vendors, *quiet)
		if err != nil {
			fatal(err)
		}
	case interactive && *targets == "" && *macArg == "" && *rangeCIDR == "":
		targetsList = scanAndSelect(scanCtx, cfg)
	default:
		var err error
		targetsList, err = resolveTargets(sigCtx, *targets, *macArg, *rangeCIDR, *whitelist, cfg)
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
	// Beeps are on by default; the saved settings, an explicit flag, or the
	// wizard can turn them off.
	beep := *soundArg && !*noSound
	if !explicit["sound"] && !explicit["no-sound"] {
		beep = prefs.Beeps
	}
	if interactive && ec.Mode != engine.ModeBlock {
		paramsWizard(&ec, duration, &beep, interval)
	}
	// A stray Ctrl-D anywhere in the wizard is an abort, not a "keep every
	// default" walk-through: get out before anything is started.
	if promptEOF {
		fmt.Println("Aborted — nothing was started.")
		os.Exit(2)
	}
	if !explicit["interval"] && prefs.IntervalSec >= 1 {
		*interval = prefs.IntervalSec
	}
	iv := time.Second
	if *interval >= 1 {
		iv = time.Duration(*interval) * time.Second
	}
	if problems := engine.DepsCheck(&ec); len(problems) > 0 {
		fatal(fmt.Errorf("%s", strings.Join(problems, "\n  • ")))
	}
	if err := ec.Validate(); err != nil {
		fatal(err)
	}

	if !*quiet {
		safetySummary(&ec, *randomArg, *profile != "", beep, iv)
	}
	if !*force {
		if !stdinIsTTY() {
			fatal(fmt.Errorf("this test needs interactive confirmation — run gnulte from a terminal, or pass --force with explicit flags"))
		}
		if !confirmStart() {
			fmt.Println("Aborted — nothing was started.")
			os.Exit(2)
		}
	}

	// With two or more targets the operator can watch them two ways: the
	// console dashboard (default) or a dedicated traffic & speed monitor in
	// its own terminal window, so the two stay side by side.
	openTraffic := *trafficWin
	if !openTraffic && len(targetsList) >= 2 && interactive && !*quiet {
		openTraffic = trafficWindowChoice()
	}
	if openTraffic {
		launchTrafficWindow(prefs.TrafficSec, cfg.Interface, targetsList)
	}

	monCtx := sigCtx
	if *duration > 0 {
		var dur context.CancelFunc
		monCtx, dur = context.WithTimeout(sigCtx, time.Duration(*duration)*time.Second)
		defer dur()
	}

	if !*quiet {
		fmt.Println("  " + okText("Elevated session active — test operations run with root privileges."))
	}
	sess, err := engine.Start(monCtx, ec)
	if err != nil {
		fatal(err)
	}
	if !*quiet {
		fmt.Println("  " + okText("Session armed — pinging "+strings.Join(targetsList, ", ")))
		fmt.Println(c(cDim, "  Ctrl+C stops the test and restores normal connectivity"))
		fmt.Println()
	}

	mon := &monitor.Monitor{
		Targets:    targetsList,
		Interval:   iv,
		Sound:      beep,
		Quiet:      *quiet,
		ExportFile: *exportArg,
		Iface:      cfg.Interface,
		Impairment: impairmentString(&ec, *profile),
		TCPPorts:   ux.SplitPorts(*probePorts),
	}
	// The per-ping timeout must exceed the planned latency, or a degraded but
	// reachable target (e.g. the 3000ms voip profile) would read as offline.
	mon.Timeout = time.Duration(ec.LatencyMS+ec.JitterMS+2000) * time.Millisecond
	if *randomArg && ec.Mode == engine.ModeShape {
		mon.OnTick = func() {
			// Toggle parameters mid-test as the Bash toolkit did: random walk
			// latency/jitter around the base values plus a random loss level.
			nc := ec
			nc.LatencyMS = clamp(ec.LatencyMS+rand.Intn(1000)-500, 100, 60000)
			nc.JitterMS = clamp(ec.JitterMS+rand.Intn(400)-200, 50, 60000)
			nc.LossPct = rand.Intn(10)
			if err := sess.UpdateParams(nc); err != nil && !*quiet {
				// A failed tc change must not kill the test, but the operator
				// should hear that RANDOM mode has stopped re-rolling.
				fmt.Fprintln(os.Stderr, "gnulte: random update failed:", err)
			}
		}
	}
	startTime := time.Now()
	if err := mon.Run(monCtx); err != nil && !*quiet {
		fmt.Fprintf(os.Stderr, "gnulte: monitor: %v\n", err)
	}

	endTime := time.Now()
	sess.Stop()
	if probs := sess.RestoreProblems(); len(probs) > 0 {
		fmt.Fprintln(os.Stderr, "gnulte: warning: some network state could not be restored automatically:")
		for _, p := range probs {
			fmt.Fprintln(os.Stderr, "  • "+p)
		}
		fmt.Fprintln(os.Stderr, "  inspect `tc qdisc show` and `iptables -L FORWARD` and clean up by hand if needed.")
	}
	if !explicit["no-report"] && !explicit["report"] && !prefs.HTMLReport {
		*noReport = true
	}
	if !*noReport {
		path := *reportFile
		if path == "" {
			path = defaultSessionPath()
		}
		if err := writeSessionReport(path, mon.Log, mon.Results, startTime, endTime); err != nil {
			fmt.Fprintf(os.Stderr, "gnulte: report: %v\n", err)
		} else if !*quiet {
			fmt.Printf("session report written to %s\n", path)
		}
	}
	if !*quiet {
		fmt.Println("\nTest finished — normal connectivity restored.")
	}
}

// resolveTargets combines --target/--mac/--range into a target list.
func resolveTargets(ctx context.Context, tAmt, tMac, rCIDR, wl string, cfg netutil.Config) ([]string, error) {
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
				ip, err := resolveTargetName(ctx, cfg, t)
				if err != nil {
					return nil, err
				}
				t = ip
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
		live := discover.PingSweep(ctx, iplist, 64)
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

// resolveTargetName resolves a friendly name — an mDNS ".local" record, a DNS
// name, a bare hostname, or the display name of a live device (the same names
// the device scanner shows) — to a LAN IPv4 address. The system resolver and
// avahi are tried first (bounded); if neither answers, the device table is
// matched by hostname, so name targeting works even without a mDNS daemon.
func resolveTargetName(ctx context.Context, cfg netutil.Config, name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if net.ParseIP(name) != nil {
		return name, nil
	}
	try := func(n string) string {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(rctx, n)
		if err != nil {
			return ""
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				return ip.String()
			}
		}
		return ""
	}
	candidates := []string{name}
	if !strings.HasSuffix(name, ".local") {
		candidates = append(candidates, name+".local")
	}
	for _, c := range candidates {
		if ip := try(c); ip != "" {
			return ip, nil
		}
	}
	for _, c := range candidates {
		if !strings.HasSuffix(c, ".local") {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(rctx, "avahi-resolve", "-4", "-n", c).Output()
		if err != nil {
			continue
		}
		f := strings.Fields(string(out))
		if len(f) >= 2 && net.ParseIP(f[1]) != nil {
			return f[1], nil
		}
	}
	if ip := nameOnLAN(ctx, cfg, name); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("could not resolve target %q to a LAN address (tried DNS, %q, avahi mDNS and the device list)", name, name+".local")
}

// nameOnLAN finds the IP of a live device whose hostname — the same name the
// device scanner displays, e.g. "Android-3.local" — matches name. Neighbor
// hostnames are resolved in parallel, each bounded, so no mDNS daemon is
// required and nothing waits longer than the overall budget.
func nameOnLAN(ctx context.Context, cfg netutil.Config, name string) string {
	rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	neighbors := discover.Neighbors(rctx, cfg.Interface)
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".local"))
	var (
		mu    sync.Mutex
		found string
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 12)
	)
	for ip := range neighbors {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-rctx.Done():
				return
			}
			defer func() { <-sem }()
			host := discover.ResolveHost(rctx, ip)
			h := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(host, "."), ".local"))
			if h == want {
				mu.Lock()
				if found == "" {
					found = ip
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return found
}

// matchDevices targets every live device on the subnet whose enriched type and
// vendor name match the filters. Type/vendor values are case-insensitive
// substrings accepting comma-separated alternatives; both filters combine as
// AND. The gateway and this host are never added (the engine never shapes its
// own link or the router).
func matchDevices(ctx context.Context, cfg netutil.Config, wantTypes, wantVendors string, quiet bool) ([]string, error) {
	subnet := subnetCIDR(cfg.SelfIP, cfg.Netmask)
	hosts, err := netutil.HostsInCIDR(subnet)
	if err != nil || len(hosts) == 0 {
		return nil, fmt.Errorf("could not enumerate %s (%v)", subnet, err)
	}
	live := discover.PingSweep(ctx, hosts, 96)
	if len(live) == 0 {
		return nil, fmt.Errorf("no live devices found on %s", subnet)
	}
	rows := rowsFromScan(cfg, live)
	types := splitCSV(wantTypes)
	vendors := splitCSV(wantVendors)

	var out []string
	for _, r := range rows {
		if r.IsSelf || r.IP == cfg.Gateway {
			continue
		}
		if matchAny(r.Type, types) && matchAny(r.Vendor, vendors) {
			out = append(out, r.IP)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no device matches --device-type %q / --vendor %q on %s", wantTypes, wantVendors, subnet)
	}
	if !quiet {
		fmt.Println("  " + okText(fmt.Sprintf("Targeting %d device(s):", len(out))))
		for _, r := range rows {
			for _, ip := range out {
				if r.IP == ip {
					ipc := c(ux.DeviceIPCode(r.IsSelf, r.Type), fmt.Sprintf("%-15s", r.IP))
					typc := c(ux.TypeColor(r.Type), fmt.Sprintf("%-12s", truncate(r.Type, 12)))
					fmt.Printf("    %s %-16s %s %s\n", ipc, truncate(r.Hostname, 16), typc, truncate(r.Vendor, 20))
				}
			}
		}
	}
	return out, nil
}

// matchAny reports whether actual contains any of the case-insensitive
// substring filters. An empty filter list matches everything.
func matchAny(actual string, want []string) bool {
	if len(want) == 0 {
		return true
	}
	a := strings.ToLower(actual)
	for _, w := range want {
		if w != "" && strings.Contains(a, strings.ToLower(w)) {
			return true
		}
	}
	return false
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

// impairmentString summarises the shaping recipe for the live console header.
func impairmentString(c *engine.Config, prof string) string {
	if c.Mode == engine.ModeBlock {
		return "100% BLOCK — no forwarding"
	}
	parts := []string{
		fmt.Sprintf("latency %dms", c.LatencyMS),
		fmt.Sprintf("jitter %dms", c.JitterMS),
		fmt.Sprintf("loss %d%%", c.LossPct),
		fmt.Sprintf("dup %d%%", c.DupPct),
		fmt.Sprintf("reorder %d%%", c.ReorderPct),
	}
	if c.BandwidthKbps > 0 {
		parts = append(parts, fmt.Sprintf("cap %dkbps", c.BandwidthKbps))
	} else {
		parts = append(parts, "unlimited")
	}
	if prof != "" {
		parts = append(parts, "profile "+prof)
	}
	return strings.Join(parts, " · ")
}

func safetySummary(c *engine.Config, randomize, profile, beep bool, iv time.Duration) {
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
	fmt.Printf("  Monitor     : ping every %ds, beeps %s\n", int(iv/time.Second), onOff(beep))
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
  -t, --target IP       target IP(s), comma-separated (hostnames and .local
                        names resolve automatically)
  -m, --mac MAC         target by MAC address
  -r, --range CIDR      target an entire subnet (e.g. 192.168.1.0/24)
  -w, --whitelist IP    exclude IP(s) from a range (comma-separated)
      --device-type KINDS  target every LAN device of these kinds
                        (comma-separated, e.g. phone,router,printer)
      --vendor NAMES    target every LAN device by vendor name (substring)

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

Watch:
      --traffic-window    with 2+ targets, open the traffic & speed monitor
                          in a separate terminal window
  -q, --quiet             results only

Advanced:
      --duration SECONDS  auto-stop after N seconds
      --interval SECONDS  ping every N seconds (default 1)
  -c, --capture FILE      capture target traffic with tcpdump ('.'- = stdout)
      --block             fully block the target (no forwarding)
      --sound             beep per ping result, pitch scales with latency (default: on)
      --no-sound          disable the per-ping beeps
      --export FILE       stream per-second results to a CSV file
      --report FILE       write the post-test HTML report (full log history)
      --no-report         skip writing the post-test HTML report (written by default)
      --probe-ports PORTS TCP fallback probe ports when ICMP is filtered (default 443,80,53)
      --force             skip interactive confirmations
      --no-banner         skip the banner (alias: --minimal)
      --dupcheck          scan LAN for duplicate IPs / ARP conflicts and exit
      --settings          open the settings editor (saved defaults) and exit
      --docs              print the safety documents and exit
      --reset-safety      remove the acceptance record and exit
      --version           print version and exit
  -h, --help              show this help
`, version)
}
