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
// resolves hostnames, classifies devices, and can export JSON/YAML/CSV.
// Only scan networks you own or are authorized to test.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/out"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/sound"
)

const version = "10.0"

func main() {
	var (
		iface     = flag.String("i", "", "network interface (default: auto-detect)")
		cidr      = flag.String("C", "", "CIDR to scan (default: from interface)")
		threads   = flag.Int("t", 64, "parallel ping workers")
		deep      = flag.Bool("d", false, "deep scan alive hosts with nmap")
		asJSON    = flag.Bool("j", false, "output JSON")
		asYAML    = flag.Bool("y", false, "output YAML")
		asCSV     = flag.Bool("c", false, "output CSV")
		quiet     = flag.Bool("q", false, "quiet: results only")
		useSound  = flag.Bool("sound", false, "play a tone per result")
		showDocs  = flag.Bool("docs", false, "print the safety documents and exit")
		resetSafe = flag.Bool("reset-safety", false, "remove the acceptance record and exit")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.StringVar(iface, "interface", "", "network interface (default: auto-detect)")
	flag.StringVar(cidr, "cidr", "", "CIDR to scan (default: from interface)")
	flag.IntVar(threads, "threads", 64, "parallel ping workers")
	flag.BoolVar(deep, "deep", false, "deep scan alive hosts with nmap")
	flag.BoolVar(asJSON, "json", false, "output JSON")
	flag.BoolVar(asYAML, "yaml", false, "output YAML")
	flag.BoolVar(asCSV, "csv", false, "output CSV")
	flag.BoolVar(quiet, "quiet", false, "quiet: results only")
	flag.Usage = usage
	flag.Parse()

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

	if !*quiet {
		fmt.Printf("gnulte-scan (Go) v%s  —  authorized testing only\n", version)
		fmt.Printf("Interface : %s\n", cfg.Interface)
		fmt.Printf("This host : %s\n", orUnknown(cfg.SelfIP))
		fmt.Printf("Gateway   : %s\n", orUnknown(cfg.Gateway))
		fmt.Printf("Scanning  : %d addresses with %d workers\n\n", len(targets), *threads)
	}

	live := discover.PingSweep(ctx, targets, *threads)
	neighbors := discover.Neighbors(ctx, cfg.Interface)

	rows := buildRows(ctx, live, neighbors, cfg)
	if *deep {
		deepScan(ctx, rows, *threads)
	}
	out.SortByIP(rows)

	switch {
	case *asJSON:
		err = out.JSON(os.Stdout, rows)
	case *asYAML:
		err = out.YAML(os.Stdout, rows)
	case *asCSV:
		err = out.CSV(os.Stdout, rows)
	default:
		out.Table(os.Stdout, rows)
	}
	if err != nil {
		fatal(err)
	}

	if !*quiet {
		fmt.Printf("\nScan complete: %d host(s) responded — %s\n", len(rows), time.Now().Format("15:04:05"))
	}
	if *useSound {
		if len(rows) == 0 {
			sound.Empty()
		} else {
			sound.Found()
		}
	}
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
			ports, osName, _ := discover.DeepScan(ctx, r.IP)
			mu.Lock()
			r.Ports = ports
			r.OS = osName
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
  -d, --deep              run nmap against alive hosts
  -j, --json              output JSON
  -y, --yaml              output YAML
  -c, --csv               output CSV
  -q, --quiet             results only, no header/summary
      --sound             play a tone for the result
      --docs              print the safety documents and exit
      --reset-safety      remove the acceptance record and exit
      --version           print version and exit
  -h, --help              show this help
`, version)
}
