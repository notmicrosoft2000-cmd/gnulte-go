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

// Command gnulte-top is a live per-host and per-conversation bandwidth view.
// It reads the interface with the same in-process AF_PACKET counter the LAN
// watch uses (internal/traffic), ranks the talkers (internal/toptalk), and can
// hand back CSV or JSON instead of painting the screen. No iptables, no top(1).
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gnulte-go/internal/netutil"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/toptalk"
	"gnulte-go/internal/traffic"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "16.13"

func main() {
	var (
		interval = flag.Int("i", 1, "sampling interval in seconds")
		samples  = flag.Int("n", 0, "number of intervals to sample (0 = until quit)")
		asJSON   = flag.Bool("json", false, "print one sample as JSON and exit")
		asCSV    = flag.Bool("csv", false, "print one sample as CSV and exit")
		flows    = flag.Bool("flows", false, "show conversations instead of hosts")
		hostFilt = flag.String("host", "", "only show hosts whose address contains this text")
		iface    = flag.String("iface", "", "interface to watch (default: the default-route interface)")
		quiet    = flag.Bool("q", false, "quiet: no banner")
		showVer  = flag.Bool("v", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("gnulte-top (Go) v%s\n", version)
		return
	}
	if *asJSON && *asCSV {
		fatal(errors.New("choose either --json or --csv, not both"))
	}
	if *interval < 1 {
		fatal(errors.New("interval must be at least 1 second"))
	}

	// The AF_PACKET counter needs root; re-exec through sudo once, like the
	// other root tools.
	elevate()

	if err := safety.EnsureAccepted(); err != nil {
		fatal(err)
	}

	nic, err := pickInterface(*iface)
	if err != nil {
		fatal(err)
	}
	counter, err := traffic.New(nic)
	if err != nil {
		// The counter is a garnish: without the raw socket we still run and
		// simply report no rates, so the view and its keys keep working.
		fmt.Fprintf(os.Stderr, "gnulte-top: traffic counter unavailable (%v) — no rates to show\n", err)
	}
	if counter != nil {
		counter.Snapshot() // baseline so the first interval is a real delta
		defer counter.Close()
	}

	var match func(string) bool
	if *hostFilt != "" {
		filter := *hostFilt
		match = func(s string) bool { return strings.Contains(s, filter) }
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	iv := time.Duration(*interval) * time.Second

	if *asJSON || *asCSV {
		if err := runExport(ctx, counter, nic, iv, *samples, match, *flows, *asJSON); err != nil {
			fatal(err)
		}
		return
	}
	if !*quiet && ux.TTY() {
		banner(nic)
	}
	if scr, e := tui.Open(); e == nil {
		runLive(ctx, scr, counter, nic, iv, *samples, match, *flows)
		scr.Close()
		return
	}
	if err := runPlain(ctx, counter, nic, iv, *samples, match, *flows); err != nil {
		fatal(err)
	}
}

// elevate re-runs the tool through sudo when a plain user asked for it. The
// child is tagged with GNULTE_AS_ROOT so the prompt happens once.
func elevate() {
	if os.Geteuid() == 0 || os.Getenv("GNULTE_AS_ROOT") == "1" {
		return
	}
	if !tui.StdinTTY() {
		fatal(errors.New("gnulte-top needs root for the AF_PACKET counter — run it from a terminal or with sudo"))
	}
	fmt.Fprintln(os.Stderr, "GNULTE TOP needs root for the AF_PACKET counter; requesting administrator access…")
	args := append([]string{"-E", os.Args[0]}, os.Args[1:]...)
	cmd := exec.Command("sudo", args...)
	cmd.Env = append(os.Environ(), "GNULTE_AS_ROOT=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fatal(err)
	}
	os.Exit(0)
}

// pickInterface returns the explicitly requested interface, or the one that
// carries the default route.
func pickInterface(override string) (string, error) {
	if override != "" {
		if _, err := net.InterfaceByName(override); err != nil {
			return "", fmt.Errorf("no such interface %q: %w", override, err)
		}
		return override, nil
	}
	cfg, err := netutil.DefaultRoute()
	if err != nil {
		return "", err
	}
	return cfg.Interface, nil
}

// sample is one interval's worth of ranked rows plus the host totals.
type sample struct {
	rows      []toptalk.Row
	flows     []toptalk.Flow
	totalDown int64
	totalUp   int64
}

// takeSample reads the counter and ranks what it saw. A nil counter (no root,
// or a down interface) yields an empty sample rather than an error.
func takeSample(c *traffic.Counter, seconds float64, match func(string) bool, flowsMode bool) sample {
	if c == nil {
		return sample{}
	}
	rates := c.Snapshot()
	rawFlows := c.SnapshotFlows()
	if flowsMode {
		return sample{flows: toptalk.FlowRows(rawFlows, seconds, match)}
	}
	rows := toptalk.Rows(rates, seconds, match)
	peers := toptalk.Peers(rawFlows)
	var down, up int64
	for i := range rows {
		rows[i].Peers = peers[rows[i].Host]
		down += rows[i].Down
		up += rows[i].Up
	}
	return sample{rows: rows, totalDown: down, totalUp: up}
}

// runLive paints the full-screen table, resampling every interval. It stops on
// q/Esc/Enter, on ctx cancellation, or after n intervals when n > 0.
func runLive(ctx context.Context, scr *tui.Screen, c *traffic.Counter, iface string, interval time.Duration, n int, match func(string) bool, flowsMode bool) {
	scr.Draw(placeholder(iface, flowsMode))
	tick := time.NewTicker(interval)
	defer tick.Stop()
	drawn := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s := takeSample(c, interval.Seconds(), match, flowsMode)
			scr.Draw(sampleLines(iface, s, flowsMode))
			drawn++
			if n > 0 && drawn >= n {
				return
			}
		default:
		}
		if k, r := scr.Poll(100); isQuitKey(k, r) {
			return
		}
	}
}

// runPlain is the non-terminal path: one ranked table per interval, appended to
// the transcript.
func runPlain(ctx context.Context, c *traffic.Counter, iface string, interval time.Duration, n int, match func(string) bool, flowsMode bool) error {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	drawn := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			s := takeSample(c, interval.Seconds(), match, flowsMode)
			for _, ln := range sampleLines(iface, s, flowsMode) {
				fmt.Fprintln(ux.Out, ln)
			}
			fmt.Fprintln(ux.Out)
			drawn++
			if n > 0 && drawn >= n {
				return nil
			}
		}
	}
}

// runExport waits out n intervals (default 1), takes a single sample across the
// whole window, and writes it as JSON or CSV.
func runExport(ctx context.Context, c *traffic.Counter, iface string, interval time.Duration, n int, match func(string) bool, flowsMode, jsonMode bool) error {
	if n <= 0 {
		n = 1
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	seconds := float64(n) * interval.Seconds()
	s := takeSample(c, seconds, match, flowsMode)
	if jsonMode {
		return writeJSON(os.Stdout, buildDoc(iface, seconds, flowsMode, s))
	}
	return writeCSV(os.Stdout, s, flowsMode)
}

// sampleLines renders one interval as a list of screen lines.
func sampleLines(iface string, s sample, flowsMode bool) []string {
	lines := []string{titleLine(iface), ""}
	if flowsMode {
		lines = append(lines, fmt.Sprintf("  %-3s %-22s %-22s %-11s %-11s %s",
			"#", "a", "b", "a→b", "b→a", "activity"))
		max := maxFlow(s.flows)
		for i, f := range s.flows {
			lines = append(lines, fmt.Sprintf("  %-3d %-22s %-22s %-11s %-11s %s",
				i+1, f.A, f.B, toptalk.HumanRate(f.AB), toptalk.HumanRate(f.BA), toptalk.Bar(f.Total(), max, 12)))
		}
		if len(s.flows) == 0 {
			lines = append(lines, "  "+ux.C(ux.Dim, "no conversations in this interval"))
		}
		return lines
	}

	lines = append(lines,
		fmt.Sprintf("  %s   %s", ux.C(ux.Green, "↓ "+toptalk.HumanRate(s.totalDown)), ux.C(ux.Yellow, "↑ "+toptalk.HumanRate(s.totalUp))),
		"",
		fmt.Sprintf("  %-3s %-11s %-11s %-5s %-20s %s", "#", "down/s", "up/s", "peers", "host", "activity"))
	max := maxRow(s.rows)
	for i, r := range s.rows {
		lines = append(lines, fmt.Sprintf("  %-3d %-11s %-11s %-5d %-20s %s",
			i+1, toptalk.HumanRate(r.Down), toptalk.HumanRate(r.Up), r.Peers, r.Host, toptalk.Bar(r.Total(), max, 16)))
	}
	if len(s.rows) == 0 {
		lines = append(lines, "  "+ux.C(ux.Dim, "no host traffic in this interval"))
	}
	return lines
}

// placeholder is the first frame, drawn before the first interval elapses.
func placeholder(iface string, flowsMode bool) []string {
	what := "hosts"
	if flowsMode {
		what = "conversations"
	}
	return []string{titleLine(iface), "", "  " + ux.C(ux.Dim, "measuring "+what+"… (q to stop)")}
}

func titleLine(iface string) string {
	return "  " + ux.C(ux.Header, "GNULTE TOP") + "   " + ux.C(ux.Cyan, "v"+version) + "   " + ux.C(ux.Dim, iface)
}

// maxRow/maxFlow find the largest combined rate for bar scaling (never 0, to
// avoid a division by zero).
func maxRow(rows []toptalk.Row) int64 {
	max := int64(1)
	for _, r := range rows {
		if r.Total() > max {
			max = r.Total()
		}
	}
	return max
}

func maxFlow(flows []toptalk.Flow) int64 {
	max := int64(1)
	for _, f := range flows {
		if f.Total() > max {
			max = f.Total()
		}
	}
	return max
}

// jsonHost / jsonFlow / jsonDoc are the stable --json contract.
type jsonHost struct {
	Host     string `json:"host"`
	DownBps  int64  `json:"down_bps"`
	UpBps    int64  `json:"up_bps"`
	DownPkts int64  `json:"down_pkts"`
	UpPkts   int64  `json:"up_pkts"`
	Peers    int    `json:"peers"`
	TotalBps int64  `json:"total_bps"`
}

type jsonFlow struct {
	A        string `json:"a"`
	B        string `json:"b"`
	ABps     int64  `json:"a_to_b_bps"`
	BAps     int64  `json:"b_to_a_bps"`
	TotalBps int64  `json:"total_bps"`
}

type jsonDoc struct {
	Interface       string     `json:"interface"`
	Mode            string     `json:"mode"`
	IntervalSeconds float64    `json:"interval_seconds"`
	TotalDownBps    int64      `json:"total_down_bps"`
	TotalUpBps      int64      `json:"total_up_bps"`
	Hosts           []jsonHost `json:"hosts,omitempty"`
	Flows           []jsonFlow `json:"flows,omitempty"`
}

// buildDoc turns one sample into the JSON/CSV document.
func buildDoc(iface string, seconds float64, flowsMode bool, s sample) jsonDoc {
	doc := jsonDoc{
		Interface:       iface,
		Mode:            "hosts",
		IntervalSeconds: seconds,
		TotalDownBps:    s.totalDown,
		TotalUpBps:      s.totalUp,
	}
	if flowsMode {
		doc.Mode = "flows"
		doc.Flows = make([]jsonFlow, 0, len(s.flows))
		for _, f := range s.flows {
			doc.Flows = append(doc.Flows, jsonFlow{A: f.A, B: f.B, ABps: f.AB, BAps: f.BA, TotalBps: f.Total()})
		}
		return doc
	}
	doc.Hosts = make([]jsonHost, 0, len(s.rows))
	for _, r := range s.rows {
		doc.Hosts = append(doc.Hosts, jsonHost{
			Host: r.Host, DownBps: r.Down, UpBps: r.Up,
			DownPkts: r.DownPkts, UpPkts: r.UpPkts, Peers: r.Peers, TotalBps: r.Total(),
		})
	}
	return doc
}

// writeJSON emits the document with two-space indentation.
func writeJSON(w io.Writer, doc jsonDoc) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// writeCSV emits one header row and one row per host or conversation, using
// per-second byte rates so the output is interval-independent.
func writeCSV(w io.Writer, s sample, flowsMode bool) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if flowsMode {
		if err := cw.Write([]string{"a", "b", "a_to_b_bps", "b_to_a_bps", "total_bps"}); err != nil {
			return err
		}
		for _, f := range s.flows {
			if err := cw.Write([]string{
				f.A, f.B, strconv.FormatInt(f.AB, 10), strconv.FormatInt(f.BA, 10), strconv.FormatInt(f.Total(), 10),
			}); err != nil {
				return err
			}
		}
		return cw.Error()
	}
	if err := cw.Write([]string{"host", "down_bps", "up_bps", "down_pkts", "up_pkts", "peers", "total_bps"}); err != nil {
		return err
	}
	for _, r := range s.rows {
		if err := cw.Write([]string{
			r.Host,
			strconv.FormatInt(r.Down, 10), strconv.FormatInt(r.Up, 10),
			strconv.FormatInt(r.DownPkts, 10), strconv.FormatInt(r.UpPkts, 10),
			strconv.Itoa(r.Peers), strconv.FormatInt(r.Total(), 10),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func isQuitKey(k tui.Key, r rune) bool {
	switch k {
	case tui.KeyEsc, tui.KeyEnter:
		return true
	case tui.KeyRune:
		return r == 'q' || r == 'Q'
	}
	return false
}

func banner(iface string) {
	fmt.Fprintln(ux.Out)
	fmt.Fprintln(ux.Out, "  "+ux.C(ux.Header, "GNULTE TOP")+"   "+ux.C(ux.Cyan, "v"+version)+"   "+ux.C(ux.Dim, "live bandwidth by host")+"   "+ux.C(ux.Target, iface))
	fmt.Fprintln(ux.Out)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gnulte-top: "+err.Error())
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `gnulte-top v%s — live per-host and per-conversation bandwidth.

Usage:
  gnulte-top [flags]

Flags:
  -i N          sampling interval in seconds (default 1)
  -n N          number of intervals to sample (0 = until quit)
  --flows       show conversations instead of hosts
  --host TEXT   only show hosts whose address contains TEXT
  --iface NAME  interface to watch (default: the default-route interface)
  --json        print one sample as JSON and exit
  --csv         print one sample as CSV and exit
  -q            quiet: no banner
  -v            print version and exit

Rates are per second, measured with an in-process AF_PACKET counter (root
required). Press q, Esc or Enter to stop the live view.

Examples:
  sudo gnulte-top
  sudo gnulte-top --flows -i 2
  sudo gnulte-top --host 192.168.1 --csv > talkers.csv
`, version)
}
