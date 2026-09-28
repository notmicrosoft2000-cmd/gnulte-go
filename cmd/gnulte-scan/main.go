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

// Command gnulte-scan is the Go rewrite of the GNULTE LAN scanner.
//
// It discovers live hosts on the local network, identifies NIC vendors,
// resolves hostnames, classifies devices, and can export JSON/YAML/CSV. The
// live console is terminal-width aware (the bar, table, and banner adapt to
// the window), animations are spinner/loading-bar based (no flashing text),
// and every session ends with a self-contained HTML report of the whole log.
// Only scan networks you own or are authorized to test.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/ident"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/out"
	"gnulte-go/internal/reportdir"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/scanner"
	"gnulte-go/internal/settings"
	"gnulte-go/internal/sound"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "13.3"

// scanPrefs holds the technical-tuning settings so deepScan and buildRows can
// honor the SCANLTE knobs (probe retries, uptime, rogue flag, confidence,
// ARP sweep, wifi tuning).
var scanPrefs settings.Config = settings.Default()

// session collects the permanent console lines so the final HTML report can
// reproduce the entire log history of the run.
type session struct {
	log []string
}

var sess session

// pl prints the display line to the console writer and records a plain-text
// twin for the report. The console writer points at stderr during exports so
// the data stream (stdout) stays machine-parseable.
func (s *session) pl(display, plain string) {
	fmt.Fprintln(ux.Out, display)
	if plain != "" {
		s.log = append(s.log, plain)
	}
}

func main() {
	var (
		iface       = flag.String("i", "", "network interface (default: auto-detect)")
		cidr        = flag.String("C", "", "CIDR to scan (default: from interface)")
		threads     = flag.Int("t", 64, "parallel ping workers")
		deep        = flag.Bool("d", false, "deep scan alive hosts with the in-Go port scanner")
		interactive = flag.Bool("T", false, "interactive full-screen device table (needs a terminal)")
		asJSON      = flag.Bool("j", false, "output JSON")
		asYAML      = flag.Bool("y", false, "output YAML")
		asCSV       = flag.Bool("c", false, "output CSV")
		quiet       = flag.Bool("q", false, "quiet: results only")
		useSound    = flag.Bool("sound", false, "play a tone per result")
		arpArg      = flag.Bool("arp", false, "also sweep by ARP (auto when root; catches hosts that block ping)")
		noArp       = flag.Bool("no-arp", false, "disable the automatic ARP sweep")
		reportArg   = flag.String("report", "", "write the post-test HTML report (full log history) to FILE")
		noReport    = flag.Bool("no-report", false, "skip writing the post-test HTML report")
		showDocs    = flag.Bool("docs", false, "print the safety documents and exit")
		resetSafe   = flag.Bool("reset-safety", false, "remove the acceptance record and exit")
		showVer     = flag.Bool("version", false, "print version and exit")
		settingsArg = flag.Bool("settings", false, "open the settings editor (saved defaults) and exit")
	)
	flag.StringVar(iface, "interface", "", "network interface (default: auto-detect)")
	flag.StringVar(cidr, "cidr", "", "CIDR to scan (default: from interface)")
	flag.IntVar(threads, "threads", 64, "parallel ping workers")
	flag.BoolVar(deep, "deep", false, "deep scan alive hosts with the in-Go port scanner")
	flag.BoolVar(interactive, "interactive", false, "interactive full-screen device table (needs a terminal)")
	flag.BoolVar(asJSON, "json", false, "output JSON")
	flag.BoolVar(asYAML, "yaml", false, "output YAML")
	flag.BoolVar(asCSV, "csv", false, "output CSV")
	flag.BoolVar(quiet, "quiet", false, "quiet: results only")
	flag.Usage = usage
	flag.Parse()

	// Machine formats own stdout: the human console narrative moves to stderr
	// so `gnulte-scan --json | jq` sees nothing but JSON. Live tools keep the
	// whole console on stdout.
	exporting := *asJSON || *asYAML || *asCSV
	showUI := !*quiet
	if exporting {
		ux.Out = os.Stderr
	}

	// Terminal metrics are captured once, before any output redirection, so the
	// banner, bar, and table all size themselves against the real window.
	cols := ux.Width()

	if *showVer {
		fmt.Printf("SCANLTE (gnulte-scan) v%s — side tool for GNULTE\n", version)
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

	// Which flags the operator typed (saved settings only fill the rest).
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
		if f.Name == "t" {
			explicit["threads"] = true
		}
		if f.Name == "i" {
			explicit["interface"] = true
		}
	})

	prefs, err := settings.Load()
	if err != nil {
		fatal(fmt.Errorf("settings: %v", err))
	}
	scanPrefs = prefs
	if *settingsArg {
		if !ux.TTY() || !tui.StdinTTY() {
			fatal(fmt.Errorf("the settings editor needs a real terminal"))
		}
		updated, err := settings.Edit(prefs)
		if err != nil {
			fatal(err)
		}
		if err := settings.Save(updated); err != nil {
			fatal(fmt.Errorf("settings: %v", err))
		}
		fmt.Printf("settings saved to %s\n", settings.Path())
		return
	}
	if !explicit["threads"] && prefs.ScanThreads >= 1 {
		*threads = prefs.ScanThreads
	}
	if !explicit["i"] && !explicit["interface"] && prefs.Interface != "" {
		*iface = prefs.Interface
	}
	if !explicit["report"] && !explicit["no-report"] && !prefs.HTMLReport {
		*noReport = true
	}

	if err := safety.EnsureAccepted(); err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := netutil.DefaultRoute()
	if err != nil {
		fatal(fmt.Errorf("network detection failed: %w", err))
	}
	if *iface != "" {
		cfg.Interface = *iface
	}
	if cfg.Interface == "" {
		fatal(fmt.Errorf("could not determine a network interface; pass -i"))
	}

	targets, err := resolveTargets(*cidr, cfg)
	if err != nil {
		fatal(err)
	}
	subnet := subnetString(cfg)

	if !*quiet {
		banner(cols)
		sess.pl(fmt.Sprintf("  interface   %s  %s", cfg.Interface, orUnknown(cfg.SelfIP)),
			fmt.Sprintf("  interface   %s  %s", cfg.Interface, orUnknown(cfg.SelfIP)))
		sess.pl(fmt.Sprintf("  gateway     %s", orUnknown(cfg.Gateway)),
			fmt.Sprintf("  gateway     %s", orUnknown(cfg.Gateway)))
		sess.pl(fmt.Sprintf("  scope       %s  ·  %d addresses · %d workers", orUnknown(subnet), len(targets), *threads),
			fmt.Sprintf("  scope       %s  ·  %d addresses · %d workers", orUnknown(subnet), len(targets), *threads))
		fmt.Fprintln(ux.Out)
	}

	// Scan phase: spinner + width-aware loading bar (no flashing).
	var bar *ux.Bar
	if showUI {
		bar = ux.NewBar("scanning "+orUnknown(subnet)+" for live hosts", len(targets))
	}
	live := discover.PingSweep(ctx, targets, *threads, func(done, alive int) {
		if bar != nil {
			bar.Update(done, alive)
		}
	})
	if bar != nil {
		bar.Finish(len(targets), len(live))
	}

	// ARP sweep (v13): hosts that filter ICMP but answer ARP appear too. It
	// needs raw sockets, so it runs automatically under root and is skipped
	// (with a hint) otherwise. --arp forces it, --no-arp disables it.
	useArp := scanPrefs.ArpSweep
	if *arpArg {
		useArp = true
	}
	if *noArp {
		useArp = false
	}
	var arpLive []string
	if useArp {
		if discover.Privileged() {
			arpBar := ux.NewBar("ARP sweep "+orUnknown(subnet)+" (hosts that block ping)", len(targets))
			arpLive = discover.ARPSweep(ctx, targets, cfg.Interface, *threads, func(done, alive int) {
				arpBar.Update(done, alive)
			})
			arpBar.Finish(len(targets), len(arpLive))
			if len(arpLive) > 0 && !*quiet {
				sess.pl(fmt.Sprintf("  ARP sweep found %d host(s) answering ARP", len(arpLive)),
					fmt.Sprintf("  ARP sweep found %d host(s) answering ARP", len(arpLive)))
			}
		} else if !*quiet && !exporting {
			sess.pl(ux.C(ux.Dim, "  ARP sweep skipped (needs sudo) — run `sudo gnulte-scan` to also catch ping-blocking hosts"),
				"  ARP sweep skipped (needs root)")
		}
	}

	// Merge ARP-only hosts into the live set before identification.
	if len(arpLive) > 0 {
		seen := make(map[string]bool, len(live)+len(arpLive))
		merged := make([]string, 0, len(live)+len(arpLive))
		for _, ip := range append(append([]string{}, live...), arpLive...) {
			if !seen[ip] {
				seen[ip] = true
				merged = append(merged, ip)
			}
		}
		sort.Strings(merged)
		live = merged
	}

	// Lease ICMP-filters respect ARP: neighbors who ignore echo still appear.
	if showUI {
		busy := ux.NewBusy(fmt.Sprintf("resolving %d host(s)", len(live)))
		resCh := make(chan []discover.Row, 1)
		go func() {
			resCh <- buildRows(ctx, live, discover.Neighbors(context.Background(), cfg.Interface), cfg)
		}()
		for {
			select {
			case rows = <-resCh:
				busy.Done(fmt.Sprintf("%d device(s) identified", len(rows)))
			case <-time.After(60 * time.Millisecond):
				busy.Spin()
				continue
			}
			break
		}
	} else {
		rows = buildRows(ctx, live, discover.Neighbors(context.Background(), cfg.Interface), cfg)
	}
	discover.EnrichHostnames(ctx, rows)

	// mDNS/DNS-SD service discovery (Avahi-style): what each device offers.
	if scanPrefs.ServiceDiscovery {
		sdBusy := ux.NewBusy("asking mDNS/DNS-SD responders what each device offers")
		done := make(chan struct{})
		go func() {
			defer close(done)
			discover.EnrichServices(ctx, rows, true)
		}()
		for {
			select {
			case <-done:
				total := 0
				for _, r := range rows {
					total += len(r.Services)
				}
				sdBusy.Done(fmt.Sprintf("%d advertised service(s) found", total))
			case <-time.After(60 * time.Millisecond):
				sdBusy.Spin()
				continue
			}
			break
		}
	}

	if *deep {
		deepBusy := ux.NewBusy(fmt.Sprintf("deep-scanning %d host(s): common ports, services, banners", len(rows)))
		done := make(chan struct{})
		go func() {
			defer close(done)
			deepScan(ctx, rows, *threads)
		}()
		for {
			select {
			case <-done:
				deepBusy.Done("deep scan complete")
			case <-time.After(60 * time.Millisecond):
				deepBusy.Spin()
				continue
			}
			break
		}
	}
	out.SortByIP(rows)

	// Interactive full-screen device table: replaces the classic table on a
	// live terminal. On exit its (filtered, sorted) snapshot is logged for the
	// report, and the plain table below is skipped to avoid a duplicate.
	interactiveQuit := false
	if *interactive && !exporting {
		if ux.TTY() && tui.StdinTTY() {
			final, quit := interactiveTable(rows, sess.log)
			interactiveQuit = quit
			rows = final
			for _, line := range rawTableLines(rows) {
				sess.log = append(sess.log, line)
			}
		} else {
			fmt.Fprintf(os.Stderr, "gnulte-scan: -T needs a real terminal; falling back to the plain table\n")
		}
	}

	exported := false
	switch {
	case *asJSON:
		err = out.JSON(os.Stdout, rows)
		exported = true
	case *asYAML:
		err = out.YAML(os.Stdout, rows)
		exported = true
	case *asCSV:
		err = out.CSV(os.Stdout, rows)
		exported = true
	default:
		if !interactiveQuit {
			renderTable(&sess, rows, cols)
		}
	}
	if err != nil {
		fatal(err)
	}

	if !*quiet {
		if exported {
			sess.pl(fmt.Sprintf("exported %d host(s) — %s", len(rows), exportKind(*asJSON, *asYAML, *asCSV)),
				fmt.Sprintf("exported %d host(s)", len(rows)))
			fmt.Fprintln(ux.Out)
		}
		sess.pl(fmt.Sprintf("scan complete — %d host(s) responded · %s", len(rows), time.Now().Format("15:04:05")),
			fmt.Sprintf("scan complete — %d host(s) responded · %s", len(rows), time.Now().Format("15:04:05")))
	}
	if *useSound {
		if len(rows) == 0 {
			sound.Empty()
		} else {
			sound.Found()
		}
	}

	if !*noReport {
		path := *reportArg
		autoPath := path == ""
		if autoPath {
			path = reportdir.DefaultPath(reportdir.GnulteScan, "gnulte-scan-report")
		}
		// Interactive (-T) terminals are asked before a report lands in the
		// hub; explicit --report and piped runs always write.
		if autoPath && *interactive && !*quiet && ux.TTY() {
			fmt.Fprint(ux.Out, "Generate HTML report? (y/N): ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if s := strings.ToLower(strings.TrimSpace(line)); s != "y" && s != "yes" {
				sess.pl(ux.C(ux.Dim, "  HTML report skipped"), "  HTML report skipped")
				path = ""
			}
		}
		if path != "" {
			meta := scanMeta{Interface: cfg.Interface, SelfIP: cfg.SelfIP, Gateway: cfg.Gateway, Subnet: subnet}
			if err := writeScanReport(path, sess.log, rows, meta); err != nil {
				fmt.Fprintf(os.Stderr, "gnulte-scan: report: %v\n", err)
			} else if !*quiet {
				fmt.Fprintf(ux.Out, "HTML report written to %s\n", path)
			}
		}
	}
}

// rows holds the discovered devices; kept package-scope so the busy spinner
// goroutine can hand it over without an awkward type dance in main.
var rows []discover.Row

func exportKind(j, y, c bool) string {
	switch {
	case j:
		return "JSON"
	case y:
		return "YAML"
	case c:
		return "CSV"
	}
	return ""
}

// scanlteLogo is the SCANLTE wordmark: a clean six-line block logo in the
// same vein as the GNULTE banner, readable on any terminal.
const scanlteLogo = `    ███████╗ ██████╗ █████╗ ███╗   ██╗██╗     ████████╗███████╗
    ██╔════╝██╔════╝██╔══██╗████╗  ██║██║     ╚══██╔══╝██╔════╝
    ███████╗██║     ███████║██╔██╗ ██║██║        ██║   █████╗
    ╚════██║██║     ██╔══██║██║╚██╗██║██║        ██║   ██╔══╝
    ███████║╚██████╗██║  ██║██║ ╚████║███████╗   ██║   ███████╗
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝`

// banner draws the SCANLTE wordmark and a width-aware title bar (static
// styling, no animation).
func banner(cols int) {
	w := ux.Clamp(cols-2, 24, 78)
	line := "  " + strings.Repeat("═", w)
	sess.pl(ux.C(ux.Dim, line), line)
	for _, r := range strings.Split(scanlteLogo, "\n") {
		sess.pl(ux.C(ux.Header, r), r)
	}
	sess.pl("  "+ux.C(ux.Cyan, "SCANLTE v"+version)+"   "+ux.C(ux.Dim, "side tool for GNULTE · LAN discovery"),
		"  SCANLTE v"+version+"   side tool for GNULTE · LAN discovery")
	sess.pl("  "+ux.C(ux.Dim, "authorized network testing only"), "  authorized network testing only")
	sess.pl(ux.C(ux.Dim, line), line)
	fmt.Fprintln(ux.Out)
}

// subnetString renders the derived subnet CIDR for the header and report.
func subnetString(cfg netutil.Config) string {
	if cfg.SelfIP == "" || cfg.Netmask == "" {
		return ""
	}
	ip := net.ParseIP(cfg.SelfIP).To4()
	mask := net.ParseIP(cfg.Netmask).To4()
	if ip == nil || mask == nil {
		return ""
	}
	net := net.IPNet{IP: ip.Mask(net.IPMask(mask)), Mask: net.IPMask(mask)}
	return net.String()
}

func buildRows(ctx context.Context, live []string, neighbors map[string]string, cfg netutil.Config) []discover.Row {
	rows := make([]discover.Row, 0, len(live))
	for _, ip := range live {
		mac := neighbors[ip]
		vendor := discover.VendorFor(mac)
		host := discover.ResolveHost(ctx, ip)
		row := discover.Row{
			IP:       ip,
			MAC:      mac,
			Vendor:   vendor,
			Hostname: host,
			Type:     discover.Classify(vendor, host),
			IsSelf:   ip == cfg.SelfIP,
		}
		if ip == cfg.Gateway {
			row.Type = "Router/Gateway"
			if row.Vendor == "" {
				row.Vendor = "(gateway)"
			}
		}
		if row.IsSelf {
			if row.Type == "" {
				row.Type = "This host"
			}
		}
		// Rogue-host flag (v12): the host answers ICMP but has no ARP record, so
		// it is not a normal member of this L2 segment and may be spoofing.
		if scanPrefs.RogueFlag && mac == "" && !row.IsSelf {
			row.ScanNote = "rogue? alive but no ARP record"
		}
		rows = append(rows, row)
	}
	return rows
}

func deepScan(ctx context.Context, rows []discover.Row, threads int) {
	if threads > 16 {
		threads = 16
	}
	if threads < 1 {
		threads = 1
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range rows {
		wg.Add(1)
		sem <- struct{}{}
		go func(r *discover.Row) {
			defer wg.Done()
			defer func() { <-sem }()
			res := scanner.DeepScanConfig(ctx, r.IP, scanner.Config{
				Retries: scanPrefs.ProbeRetries,
				Uptime:  scanPrefs.UptimeGuess,
			})
			var ports string
			if len(res.Ports) == 0 {
				ports = "(no open ports in common range)"
			} else {
				parts := make([]string, 0, len(res.Ports))
				for _, p := range res.Ports {
					s := fmt.Sprintf("%d/open/tcp", p.Port)
					if p.Service != "" {
						s += "/" + p.Service
					}
					parts = append(parts, s)
				}
				ports = strings.Join(parts, ", ")
			}
			var banners []string
			for _, p := range res.Ports {
				if p.Banner != "" {
					svc := p.Service
					if svc == "" {
						svc = fmt.Sprintf("%d", p.Port)
					}
					banners = append(banners, fmt.Sprintf("%d (%s): %s", p.Port, svc, p.Banner))
				}
			}
			mu.Lock()
			r.Ports = ports
			r.Banners = banners
			if r.ScanNote != "" && res.Note != "" {
				r.ScanNote += " · " + res.Note
			} else if res.Note != "" {
				r.ScanNote = res.Note
			}
			if t := ident.DeviceType(r.Vendor, r.Hostname, ports, banners); t != "" {
				r.Type = t
			}
			r.OS, r.OSConf = scanner.FingerprintOSConf(res.TTL, res.Ports, r.Vendor, r.Type)
			if scanPrefs.OSConfidence && r.OSConf > 0 && r.OS != "" {
				r.OS = fmt.Sprintf("%s (%d%%)", r.OS, r.OSConf)
			}
			r.Uptime = res.Uptime
			mu.Unlock()
		}(&rows[i])
	}
	wg.Wait()
}

// resolveTargets expands -C/--cidr or derives the subnet from the interface.
func resolveTargets(cidr string, cfg netutil.Config) ([]string, error) {
	if cidr != "" {
		return capTargets(netutil.HostsInCIDR(cidr))
	}
	if cfg.SelfIP == "" || cfg.Netmask == "" {
		return nil, fmt.Errorf("cannot derive subnet; pass -C <cidr>")
	}
	ip := net.ParseIP(cfg.SelfIP).To4()
	mask := net.ParseIP(cfg.Netmask).To4()
	if ip == nil || mask == nil {
		return nil, fmt.Errorf("invalid interface address; pass -C <cidr>")
	}
	network := net.IPNet{IP: ip.Mask(net.IPMask(mask)), Mask: net.IPMask(mask)}
	list, err := netutil.HostsInCIDR(network.String())
	if err != nil {
		return nil, err
	}
	return capTargets(list, nil)
}

func capTargets(list []string, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	if len(list) > 4096 {
		return nil, fmt.Errorf("CIDR covers %d addresses (limit 4096); use a smaller range", len(list))
	}
	return list, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gnulte-scan: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `SCANLTE (gnulte-scan) v%s — side tool for GNULTE, authorized network testing only

Usage:
  gnulte-scan [options]

Options:
  -i, --interface IFACE   network interface (default: auto-detect)
  -C, --cidr CIDR         subnet to scan (default: from interface)
  -t, --threads N         parallel ping workers (default: 64)
  -d, --deep              deep scan alive hosts (in-Go port scanner)
  -T, --interactive       interactive full-screen monitor with windows
                          (Devices/Log/Summary tabs, o = settings page; live terminal)
  -j, --json              output JSON
  -y, --yaml              output YAML
  -c, --csv               output CSV
  -q, --quiet             results only, no header/summary
      --sound             play a tone for the result
      --report FILE       write the post-test HTML report (full log history)
      --no-report         skip writing the HTML report (written by default)
      --settings          open the settings editor (saved defaults) and exit
      --docs              print the safety documents and exit
      --reset-safety      remove the acceptance record and exit
      --version           print version and exit
  -h, --help              show this help
`, version)
}
