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

// Command gnulte-trace is an mtr-style path probe. It walks the route to a
// host one TTL at a time with in-process ICMP echo (internal/icmp), shows the
// live table while it runs, and can hand back a machine-readable JSON document
// or a self-contained HTML report. There is no traceroute(8) subprocess.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/icmp"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/trace"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "16.12"

func main() {
	var (
		maxHops  = flag.Int("m", 30, "maximum number of hops")
		probes   = flag.Int("c", 3, "probes per hop")
		timeout  = flag.Int("t", 1000, "per-probe timeout in milliseconds")
		interval = flag.Int("i", 200, "pause between the probes of a hop, in milliseconds")
		asJSON   = flag.Bool("json", false, "print the result as JSON")
		report   = flag.String("html", "", "also write a self-contained HTML report to FILE")
		quiet    = flag.Bool("q", false, "quiet: no live view, print the final table only")
		showVer  = flag.Bool("v", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("gnulte-trace (Go) v%s\n", version)
		return
	}
	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	// Raw ICMP needs root. The parent process re-executes itself through sudo
	// and gets out of the way; the elevated child does the work.
	elevate()

	if err := safety.EnsureAccepted(); err != nil {
		fatal(err)
	}

	target, err := resolveTarget(flag.Arg(0))
	if err != nil {
		fatal(err)
	}

	opts := trace.Options{
		MaxHops:  *maxHops,
		Probes:   *probes,
		Timeout:  time.Duration(*timeout) * time.Millisecond,
		Interval: time.Duration(*interval) * time.Millisecond,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	started := time.Now()

	if !*asJSON && !*quiet && ux.TTY() {
		banner()
	}

	var res trace.Result
	live := false
	switch {
	case *asJSON:
		res, err = trace.Walk(ctx, target, opts, icmp.TraceProbe, nil)
	case *quiet || !ux.TTY():
		res, err = runPlain(ctx, target, opts)
	default:
		if scr, e := tui.Open(); e == nil {
			live = true
			var aborted bool
			res, aborted, err = runLive(ctx, scr, target, opts)
			scr.Close()
			if aborted {
				fmt.Fprintln(ux.Out, ux.C(ux.Dim, "  stopped."))
			}
		} else {
			res, err = runPlain(ctx, target, opts)
		}
	}
	if err != nil {
		fatal(privilegeHint(err))
	}

	if *asJSON {
		emitJSON(os.Stdout, res, opts, started)
		return
	}
	if live {
		printTable(ux.Out, res)
	}
	printSummary(ux.Out, res, started)
	if *report != "" {
		if err := writeHTML(*report, res, opts, started); err != nil {
			fatal(err)
		}
		fmt.Fprintf(ux.Out, "\n  report: %s\n", *report)
	}
}

// elevate re-runs the tool through sudo when a plain user asked for it, so the
// raw socket can be opened. It mirrors the other root tools: the child is
// tagged with GNULTE_AS_ROOT so the prompt happens once.
func elevate() {
	if os.Geteuid() == 0 || os.Getenv("GNULTE_AS_ROOT") == "1" {
		return
	}
	if !tui.StdinTTY() {
		fatal(errors.New("gnulte-trace needs root for raw ICMP sockets — run it from a terminal or with sudo"))
	}
	fmt.Fprintln(os.Stderr, "GNULTE TRACE needs root for raw ICMP sockets; requesting administrator access…")
	args := append([]string{"-E", os.Args[0]}, os.Args[1:]...)
	cmd := exec.Command("sudo", args...)
	cmd.Env = append(os.Environ(), "GNULTE_AS_ROOT=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fatal(err)
	}
	os.Exit(0)
}

// privilegeHint turns the kernel's EPERM into advice, because that is the one
// error a user is most likely to hit.
func privilegeHint(err error) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%w — raw ICMP sockets need root, run gnulte-trace with sudo", err)
	}
	return err
}

// resolveTarget accepts an IPv4 literal or a hostname and returns the IPv4
// address to trace. IPv6 is refused with a clear message rather than a DNS
// failure.
func resolveTarget(t string) (string, error) {
	if ip := net.ParseIP(t); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("%s is IPv6; this traceroute speaks ICMPv4", t)
		}
		return ip.String(), nil
	}
	addr, err := net.ResolveIPAddr("ip4", t)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", t, err)
	}
	return addr.IP.String(), nil
}

// runPlain walks the path and prints each hop the moment it is complete. It is
// the mode used when stdout is not a terminal, and the fallback when the
// full-screen view cannot open.
func runPlain(ctx context.Context, ip string, opts trace.Options) (trace.Result, error) {
	fmt.Fprintf(ux.Out, "\n  %s  %s\n\n", ux.C(ux.Header, "GNULTE TRACE"), ux.C(ux.Target, ip))
	fmt.Fprintln(ux.Out, tableHeader())
	res, err := trace.Walk(ctx, ip, opts, icmp.TraceProbe, func(h trace.Hop) {
		fmt.Fprintln(ux.Out, hopRow(h))
	})
	return res, err
}

// runLive drives the full-screen table: the walk runs in a goroutine and hands
// each finished hop back under a mutex, while this loop redraws and watches the
// keyboard. It reports whether the user quit early.
func runLive(ctx context.Context, scr *tui.Screen, ip string, opts trace.Options) (trace.Result, bool, error) {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu   sync.Mutex
		hops []trace.Hop
	)
	done := make(chan struct{})
	var (
		res     trace.Result
		walkErr error
	)
	go func() {
		defer close(done)
		r, err := trace.Walk(wctx, ip, opts, icmp.TraceProbe, func(h trace.Hop) {
			mu.Lock()
			hops = append(hops, h)
			mu.Unlock()
		})
		res, walkErr = r, err
	}()

	started := time.Now()
	frame := 0
	for {
		scr.Draw(liveLines(ip, snapshot(&mu, &hops), started, frame))
		frame++

		select {
		case <-done:
			// One last frame carries every hop gathered after the previous draw.
			scr.Draw(liveLines(ip, snapshot(&mu, &hops), started, frame))
			return res, false, walkErr
		default:
		}

		if k, r := scr.Poll(150); isQuitKey(k, r) {
			cancel()
			<-done
			return res, true, walkErr
		}
	}
}

// snapshot copies the hops gathered so far for a redraw.
func snapshot(mu *sync.Mutex, hops *[]trace.Hop) []trace.Hop {
	mu.Lock()
	defer mu.Unlock()
	return append([]trace.Hop(nil), *hops...)
}

// isQuitKey decides whether a key press ends the live view.
func isQuitKey(k tui.Key, r rune) bool {
	switch k {
	case tui.KeyEsc, tui.KeyEnter:
		return true
	case tui.KeyRune:
		return r == 'q' || r == 'Q'
	}
	return false
}

var spinner = []string{"|", "/", "-", "\\"}

// liveLines builds the full-screen frame: a title, the column header, one row
// per completed hop, and an animated footer.
func liveLines(ip string, hops []trace.Hop, started time.Time, frame int) []string {
	lines := []string{
		ux.C(ux.Header, "GNULTE TRACE") + "   " + ux.C(ux.Cyan, "v"+version) + "   " + ux.C(ux.Target, ip),
		"",
		tableHeader(),
	}
	for _, h := range hops {
		lines = append(lines, hopRow(h))
	}
	lines = append(lines, "", "  "+ux.C(ux.Dim, fmt.Sprintf("%s tracing… %ds elapsed · q to stop",
		spinner[frame%len(spinner)], int(time.Since(started).Seconds()))))
	return lines
}

// tableHeader is the shared column header for the live view, the plain view and
// the post-run table.
func tableHeader() string {
	return fmt.Sprintf("  %3s  %-20s %5s %5s %7s %7s %7s %7s",
		"hop", "host", "loss", "sent", "last", "avg", "best", "worst")
}

// hopRow renders one hop's address and timing statistics.
func hopRow(h trace.Hop) string {
	addr := h.Addr
	if addr == "" {
		addr = "*"
	}
	last := -1
	for i := len(h.RTTs) - 1; i >= 0; i-- {
		if h.RTTs[i] >= 0 {
			last = h.RTTs[i]
			break
		}
	}
	return fmt.Sprintf("  %3d  %-20s %4d%% %5d %7s %7s %7s %7s",
		h.TTL, addr, h.Loss(), h.Sent(), ms(last), ms(h.Avg()), ms(h.Min()), ms(h.Max()))
}

// ms formats a millisecond reading; a negative value is a missing sample.
func ms(v int) string {
	if v < 0 {
		return "*"
	}
	return fmt.Sprintf("%dms", v)
}

// printTable writes the finished table to the primary screen after the
// full-screen view closes, so it stays in the scrollback.
func printTable(w io.Writer, res trace.Result) {
	fmt.Fprintf(w, "\n  %s  %s\n\n", ux.C(ux.Header, "GNULTE TRACE"), ux.C(ux.Target, res.Target))
	fmt.Fprintln(w, tableHeader())
	for _, h := range res.Hops {
		fmt.Fprintln(w, hopRow(h))
	}
}

// printSummary states the verdict: reached, unreachable, or no answer.
func printSummary(w io.Writer, res trace.Result, started time.Time) {
	fmt.Fprintln(w)
	elapsed := time.Since(started).Seconds()
	switch {
	case res.Reached:
		fmt.Fprintf(w, "  %s  %s reached in %d hop(s) · %.1fs\n",
			ux.C(ux.Green, "REACHED"), res.Target, len(res.Hops), elapsed)
	case res.Unreachable:
		fmt.Fprintf(w, "  %s  %s is unreachable (stopped at hop %d)\n",
			ux.C(ux.Yellow, "UNREACHABLE"), res.Target, len(res.Hops))
	default:
		fmt.Fprintf(w, "  %s  no answer from %s within %d hop(s)\n",
			ux.C(ux.Red, "INCOMPLETE"), res.Target, len(res.Hops))
	}
}

// jsonHop / jsonResult are the stable --json contract; a script can rely on
// these field names even if the internal Hop changes.
type jsonHop struct {
	TTL  int    `json:"ttl"`
	Addr string `json:"addr,omitempty"`
	Kind string `json:"kind"`
	Sent int    `json:"sent"`
	Recv int    `json:"recv"`
	Loss int    `json:"loss_percent"`
	Min  int    `json:"min_ms"`
	Avg  int    `json:"avg_ms"`
	Max  int    `json:"max_ms"`
}

type jsonResult struct {
	Target      string    `json:"target"`
	Reached     bool      `json:"reached"`
	Unreachable bool      `json:"unreachable,omitempty"`
	Probes      int       `json:"probes_per_hop"`
	MaxHops     int       `json:"max_hops"`
	ElapsedMs   int64     `json:"elapsed_ms"`
	Hops        []jsonHop `json:"hops"`
}

// emitJSON writes the machine-readable result.
func emitJSON(w io.Writer, res trace.Result, opts trace.Options, started time.Time) {
	out := jsonResult{
		Target:      res.Target,
		Reached:     res.Reached,
		Unreachable: res.Unreachable,
		Probes:      opts.Probes,
		MaxHops:     opts.MaxHops,
		ElapsedMs:   time.Since(started).Milliseconds(),
		Hops:        make([]jsonHop, 0, len(res.Hops)),
	}
	for _, h := range res.Hops {
		out.Hops = append(out.Hops, jsonHop{
			TTL:  h.TTL,
			Addr: h.Addr,
			Kind: h.Kind.String(),
			Sent: h.Sent(),
			Recv: h.Recv(),
			Loss: h.Loss(),
			Min:  h.Min(),
			Avg:  h.Avg(),
			Max:  h.Max(),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal(err)
	}
}

// writeHTML renders a single self-contained report next to the run.
func writeHTML(path string, res trace.Result, opts trace.Options, started time.Time) error {
	var b strings.Builder
	title := "GNULTE trace — " + res.Target
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>" + html.EscapeString(title) + "</title>\n")
	b.WriteString("<style>\n" +
		"body{font:14px/1.5 system-ui,sans-serif;margin:2rem;background:#0f1115;color:#e6e6e6}\n" +
		"h1{font-size:1.2rem;margin:0 0 .2rem}\n" +
		".meta{color:#9aa4b2;margin-bottom:1rem}\n" +
		"table{border-collapse:collapse;min-width:640px}\n" +
		"th,td{padding:.35rem .7rem;text-align:right;border-bottom:1px solid #23262e}\n" +
		"th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}\n" +
		"thead th{color:#9aa4b2;font-weight:600}\n" +
		".hop{color:#7cc4ff}\n" +
		".timeout{color:#8b93a1}\n" +
		".ok{color:#5ed38b}.bad{color:#ff7a7a}\n" +
		"footer{margin-top:1.5rem;color:#9aa4b2}\n" +
		"</style>\n</head>\n<body>\n")
	b.WriteString("<h1>" + html.EscapeString(title) + "</h1>\n")
	b.WriteString(fmt.Sprintf("<div class=\"meta\">%d probes/hop · max %d hops · %.1fs · %s</div>\n",
		opts.Probes, opts.MaxHops, time.Since(started).Seconds(), started.Format(time.RFC3339)))
	b.WriteString("<table>\n<thead><tr><th>#</th><th>host</th><th>loss</th><th>sent</th><th>last</th><th>avg</th><th>best</th><th>worst</th></tr></thead>\n<tbody>\n")
	for _, h := range res.Hops {
		addr := h.Addr
		if addr == "" {
			addr = "*"
		}
		last := -1
		for i := len(h.RTTs) - 1; i >= 0; i-- {
			if h.RTTs[i] >= 0 {
				last = h.RTTs[i]
				break
			}
		}
		cls := "hop"
		switch h.Kind {
		case icmp.TargetReply:
			cls = "ok"
		case icmp.NoReply:
			cls = "timeout"
		}
		fmt.Fprintf(&b, "<tr class=\"%s\"><td>%d</td><td>%s</td><td>%d%%</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			cls, h.TTL, html.EscapeString(addr), h.Loss(), h.Sent(), ms(last), ms(h.Avg()), ms(h.Min()), ms(h.Max()))
	}
	b.WriteString("</tbody>\n</table>\n")
	verdict := "no answer"
	cls := "bad"
	if res.Reached {
		verdict, cls = "reached", "ok"
	} else if res.Unreachable {
		verdict, cls = "unreachable", "hop"
	}
	fmt.Fprintf(&b, "<footer>%s: <span class=\"%s\">%s</span> · generated by GNULTE trace v%s</footer>\n",
		html.EscapeString(res.Target), cls, verdict, version)
	b.WriteString("</body>\n</html>\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func banner() {
	fmt.Fprintln(ux.Out)
	fmt.Fprintln(ux.Out, "  "+ux.C(ux.Header, "GNULTE TRACE")+"   "+ux.C(ux.Cyan, "v"+version)+"   "+ux.C(ux.Dim, "hop-by-hop path probe"))
	fmt.Fprintln(ux.Out)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gnulte-trace: "+err.Error())
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `gnulte-trace v%s — hop-by-hop path probe (mtr-style), no traceroute(8).

Usage:
  gnulte-trace [flags] HOST

Flags:
  -m N          maximum number of hops (default 30)
  -c N          probes per hop (default 3)
  -t MS         per-probe timeout in milliseconds (default 1000)
  -i MS         pause between the probes of a hop, in milliseconds (default 200)
  --json        print the result as JSON
  --html FILE   also write a self-contained HTML report to FILE
  -q            quiet: no live view, print the final table only
  -v            print version and exit

HOST is an IPv4 address or a hostname. Raw ICMP sockets require root, so a
regular user is re-executed through sudo (once).

Examples:
  sudo gnulte-trace 1.1.1.1
  gnulte-trace --json --html trace.html example.com
`, version)
}
