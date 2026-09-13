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
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/out"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/sound"
	"gnulte-go/internal/ux"
)

const version = "10.0"

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
		iface     = flag.String("i", "", "network interface (default: auto-detect)")
		cidr      = flag.String("C", "", "CIDR to scan (default: from interface)")
		threads   = flag.Int("t", 64, "parallel ping workers")
		deep      = flag.Bool("d", false, "deep scan alive hosts with the in-Go port scanner")
		asJSON    = flag.Bool("j", false, "output JSON")
		asYAML    = flag.Bool("y", false, "output YAML")
		asCSV     = flag.Bool("c", false, "output CSV")
		quiet     = flag.Bool("q", false, "quiet: results only")
		useSound  = flag.Bool("sound", false, "play a tone per result")
		reportArg = flag.String("report", "", "write the post-test HTML report (full log history) to FILE")
		noReport  = flag.Bool("no-report", false, "skip writing the post-test HTML report")
		showDocs  = flag.Bool("docs", false, "print the safety documents and exit")
		resetSafe = flag.Bool("reset-safety", false, "remove the acceptance record and exit")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.StringVar(iface, "interface", "", "network interface (default: auto-detect)")
	flag.StringVar(cidr, "cidr", "", "CIDR to scan (default: from interface)")
	flag.IntVar(threads, "threads", 64, "parallel ping workers")
	flag.BoolVar(deep, "deep", false, "deep scan alive hosts with the in-Go port scanner")
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
		fmt.Printf("gnulte-scan (Go) v%s\n", version)
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
		renderTable(&sess, rows, cols)
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
		if path == "" {
			path = fmt.Sprintf("gnulte-scan-report-%s.html", time.Now().Format("20060102-150405"))
		}
		meta := scanMeta{Interface: cfg.Interface, SelfIP: cfg.SelfIP, Gateway: cfg.Gateway, Subnet: subnet}
		if err := writeScanReport(path, sess.log, rows, meta); err != nil {
			fmt.Fprintf(os.Stderr, "gnulte-scan: report: %v\n", err)
		} else if !*quiet {
			fmt.Fprintf(ux.Out, "HTML report written to %s\n", path)
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

// banner draws a width-aware title bar with static styling (no animation).
func banner(cols int) {
	w := ux.Clamp(cols-2, 24, 78)
	line := "  " + strings.Repeat("═", w)
	sess.pl(ux.C(ux.Dim, line), line)
	sess.pl("  "+ux.C(ux.Header, "GNULTE SCAN")+"   "+ux.C(ux.Cyan, "v"+version)+"   "+ux.C(ux.Dim, "LAN discovery"),
		"  GNULTE SCAN   v"+version+"   LAN discovery")
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
			ports, osName, banners, note := discover.DeepScan(ctx, r.IP)
			mu.Lock()
			r.Ports = ports
			r.OS = osName
			r.Banners = banners
			r.ScanNote = note
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
	fmt.Fprintf(os.Stderr, `gnulte-scan (Go) v%s — authorized network testing only

Usage:
  gnulte-scan [options]

Options:
  -i, --interface IFACE   network interface (default: auto-detect)
  -C, --cidr CIDR         subnet to scan (default: from interface)
  -t, --threads N         parallel ping workers (default: 64)
  -d, --deep              deep scan alive hosts (in-Go port scanner)
  -j, --json              output JSON
  -y, --yaml              output YAML
  -c, --csv               output CSV
  -q, --quiet             results only, no header/summary
      --sound             play a tone for the result
      --report FILE       write the post-test HTML report (full log history)
      --no-report         skip writing the HTML report (written by default)
      --docs              print the safety documents and exit
      --reset-safety      remove the acceptance record and exit
      --version           print version and exit
  -h, --help              show this help
`, version)
}
