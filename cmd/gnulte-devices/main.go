package main

import (
	"context"
	"flag"
	"fmt"
	"html"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/out"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/ux"
)

const version = "13.5"

func main() {
	var (
		iface      = flag.String("i", "", "network interface (default: auto-detect)")
		doScan     = flag.Bool("s", false, "also ping-sweep the subnet (default: ARP table only)")
		threads    = flag.Int("t", 64, "parallel ping workers when scanning")
		noHosts    = flag.Bool("n", false, "skip hostname resolution (fast)")
		asJSON     = flag.Bool("j", false, "output JSON")
		asYAML     = flag.Bool("y", false, "output YAML")
		asCSV      = flag.Bool("c", false, "output CSV")
		outFile    = flag.String("o", "", "write the table to a file")
		htmlReport = flag.String("H", "", "write an HTML report to this file")
		quiet      = flag.Bool("q", false, "quiet: no banner, no status lines")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.BoolVar(doScan, "scan", false, "also ping-sweep the subnet (default: ARP table only)")
	flag.BoolVar(noHosts, "no-hostnames", false, "skip hostname resolution (fast)")
	flag.BoolVar(asJSON, "json", false, "output JSON")
	flag.BoolVar(asYAML, "yaml", false, "output YAML")
	flag.BoolVar(asCSV, "csv", false, "output CSV")
	flag.BoolVar(showVer, "v", false, "print version and exit")
	flag.StringVar(iface, "interface", "", "network interface (default: auto-detect)")
	flag.StringVar(outFile, "output", "", "write the table to a file")
	flag.StringVar(htmlReport, "html", "", "write an HTML report to this file")
	flag.BoolVar(quiet, "quiet", false, "quiet: no banner, no status lines")
	flag.Parse()

	if *showVer {
		fmt.Printf("gnulte-devices (Go) v%s\n", version)
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

	exported := *asJSON || *asYAML || *asCSV
	table := ux.Out
	var tableFile *os.File
	if *outFile != "" {
		tableFile, err = os.Create(*outFile)
		if err != nil {
			fatal(fmt.Errorf("cannot write %s: %w", *outFile, err))
		}
		defer tableFile.Close()
		table = tableFile
	}
	if !*quiet {
		banner()
		fmt.Fprintln(ux.Out)
	}

	neighbors := discover.Neighbors(ctx, cfg.Interface)

	var live []string
	if *doScan {
		cidr := subnetString(cfg)
		targets, err := netutil.HostsInCIDR(cidr)
		if err != nil || len(targets) == 0 {
			fatal(fmt.Errorf("cannot build a target list for %s", cidr))
		}
		var bar *ux.Bar
		if !exported && *outFile == "" && !*quiet {
			bar = ux.NewBar("sweeping "+cidr+" for devices", len(targets))
		}
		live = discover.PingSweep(ctx, targets, *threads, func(done, alive int) {
			if bar != nil {
				bar.Update(done, alive)
			}
		})
		if bar != nil {
			bar.Finish(len(targets), len(live))
			fmt.Fprintln(ux.Out)
		}
	} else {
		for ip := range neighbors {
			live = append(live, ip)
		}
		sort.Strings(live)
	}

	rows := buildRows(ctx, live, neighbors, cfg, *noHosts)
	out.SortByIP(rows)

	switch {
	case exported:
		var err error
		switch {
		case *asJSON:
			err = out.JSON(os.Stdout, rows)
		case *asYAML:
			err = out.YAML(os.Stdout, rows)
		case *asCSV:
			err = out.CSV(os.Stdout, rows)
		}
		if err != nil {
			fatal(err)
		}
	default:
		out.Table(table, rows)
	}

	if !*quiet {
		suffix := ""
		if *doScan {
			suffix = fmt.Sprintf(" · %d live", len(live))
		}
		fmt.Fprintf(ux.Out, "devices found — %d%s\n", len(rows), suffix)
	}

	if *htmlReport != "" {
		if err := writeHTML(*htmlReport, rows, cfg, *doScan); err != nil {
			fmt.Fprintf(os.Stderr, "gnulte-devices: html: %v\n", err)
		} else if !*quiet {
			fmt.Fprintf(ux.Out, "HTML report written to %s\n", *htmlReport)
		}
	}
}

func buildRows(ctx context.Context, live []string, neighbors map[string]string, cfg netutil.Config, noHosts bool) []discover.Row {
	seen := map[string]bool{}
	var rows []discover.Row
	var mu sync.Mutex
	add := func(ip, mac string) {
		if seen[ip] {
			return
		}
		seen[ip] = true
		vendor := discover.VendorFor(mac)
		var host string
		if !noHosts {
			host = discover.ResolveHost(ctx, ip)
		}
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
		mu.Lock()
		rows = append(rows, row)
		mu.Unlock()
	}

	// ARP neighbours who never answer ICMP still show up.
	for ip, mac := range neighbors {
		add(ip, mac)
	}
	// Live sweep results fill in MAC-less addresses and surface new devices.
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, 8)
	for _, ip := range live {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			add(ip, neighbors[ip])
		}(ip)
	}
	wg.Wait()
	discover.EnrichHostnames(ctx, rows)
	return rows
}

// subnetString derives the /CIDR to sweep from the interface address. Only 24,
// 16, and 8 boundaries are guessed at; finer masks fall back to /24.
func subnetString(cfg netutil.Config) string {
	cidr := "24"
	switch {
	case strings.HasPrefix(cfg.SelfIP, "10."):
		cidr = "16"
	case strings.HasPrefix(cfg.SelfIP, "172."):
		cidr = "16"
	case strings.HasPrefix(cfg.SelfIP, "192.168.") || strings.HasPrefix(cfg.SelfIP, "169.254."):
		cidr = "24"
	}
	if cfg.SelfIP == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s", cfg.SelfIP, cidr)
}

// banner draws a width-aware title bar with static styling (no animation).
func banner() {
	w := ux.Clamp(ux.Width()-2, 24, 78)
	line := "  " + strings.Repeat("═", w)
	fmt.Fprintln(ux.Out, ux.C(ux.Dim, line))
	fmt.Fprintln(ux.Out, "  "+ux.C(ux.Header, "GNULTE DEVICES")+"   "+ux.C(ux.Cyan, "v"+version)+"   "+ux.C(ux.Dim, "LAN inventory"))
	fmt.Fprintln(ux.Out, "  "+ux.C(ux.Dim, "authorized network testing only"))
	fmt.Fprintln(ux.Out, ux.C(ux.Dim, line))
}

// writeHTML renders a minimal, dependency-free report of the findings.
func writeHTML(path string, rows []discover.Row, cfg netutil.Config, swept bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	b.WriteString("<title>GNULTE devices</title>")
	b.WriteString("<style>body{font-family:ui-monospace,Menlo,monospace;margin:2rem;color:#222}")
	b.WriteString("table{border-collapse:collapse;margin-top:1rem;width:100%}")
	b.WriteString("th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9em}")
	b.WriteString("th{background:#f4f4f4}td.ip{font-weight:bold}</style></head><body>")
	fmt.Fprintf(&b, "<h1>GNULTE devices <span style=\"color:#999;font-weight:normal\">v%s</span></h1>", version)
	fmt.Fprintf(&b, "<p>interface <b>%s</b> · this host <b>%s</b> · gateway <b>%s</b>", html.EscapeString(cfg.Interface), html.EscapeString(cfg.SelfIP), html.EscapeString(cfg.Gateway))
	if swept {
		b.WriteString(" · subnet swept")
	}
	fmt.Fprintf(&b, " · generated %s</p>", time.Now().Format("2006-01-02 15:04:05"))
	b.WriteString("<table><thead><tr><th>IP</th><th>MAC</th><th>VENDOR</th><th>HOSTNAME</th><th>TYPE</th></tr></thead><tbody>")
	for _, r := range rows {
		b.WriteString("<tr>")
		if r.IsSelf {
			fmt.Fprintf(&b, "<td class=\"ip\" style=\"background:#eef\">%s</td>", html.EscapeString(orDash(r.IP)))
		} else {
			fmt.Fprintf(&b, "<td class=\"ip\">%s</td>", html.EscapeString(orDash(r.IP)))
		}
		fmt.Fprintf(&b, "<td>%s</td><td>%s</td><td>%s</td><td>%s</td>",
			html.EscapeString(orDash(r.MAC)),
			html.EscapeString(orDash(r.Vendor)),
			html.EscapeString(orDash(r.Hostname)),
			html.EscapeString(orDash(r.Type)))
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></body></html>")
	_, err = f.WriteString(b.String())
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gnulte-devices: %v\n", err)
	os.Exit(1)
}
