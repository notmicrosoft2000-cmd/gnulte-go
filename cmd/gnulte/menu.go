// GNULTE-GO — network testing toolkit.
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

package main

// Interactive start: banner art, a real-checks boot sequence, a live device
// scan with spinner, a numbered target menu and the impairment wizard. These
// run when gnulte is launched from a terminal (mirroring the Bash toolkit).

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/engine"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/out"
)

var ansi = outTTY()

// sin is the single shared stdin scanner: one Scanner for the whole process so
// an early buffer never swallows the answers to later prompts.
var (
	sinOnce sync.Once
	sin     *bufio.Scanner
)

func stdinReader() *bufio.Scanner {
	sinOnce.Do(func() {
		sin = bufio.NewScanner(os.Stdin)
	})
	return sin
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[0;31m"
	cGreen  = "\033[0;32m"
	cYellow = "\033[1;33m"
	cCyan   = "\033[0;36m"
	cHeader = "\033[1;36m"
	cTarget = "\033[0;33m"
)

func c(code, s string) string {
	if !ansi {
		return s
	}
	return code + s + cReset
}

func outTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// printBanner draws the ASCII logo and tagline.
func printBanner() {
	fmt.Println(c(cHeader, `  ██████╗ ███╗   ██╗██╗   ██╗██╗  ████████╗███████╗`))
	fmt.Println(c(cHeader, ` ██╔════╝ ████╗  ██║██║   ██║██║  ╚══██╔══╝██╔════╝`))
	fmt.Println(c(cHeader, ` ██║  ███╗██╔██╗ ██║██║   ██║██║     ██║   █████╗  `))
	fmt.Println(c(cHeader, ` ██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██╔══╝  `))
	fmt.Println(c(cHeader, ` ╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ███████╗`))
	fmt.Println(c(cHeader, `  ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝`))
	fmt.Println("  " + c(cCyan+cBold, "GNU LAN Network Testing Environment"))
	fmt.Println("  " + c(cDim, "Version "+version+" • Authorised testing on networks you own"))
	fmt.Println()
}

// bootSeq runs the real startup checks (nothing simulated, no fake pauses).
func bootSeq(cfg netutil.Config) {
	fmt.Println(c(cCyan+cBold, "  GNULTE-GO v"+version+" — Initialising"))
	fmt.Println("  " + c(cDim, "Real checks only — nothing here is simulated or delayed."))
	fmt.Println()

	fmt.Println("  ● Loading configuration...")
	fmt.Println("    " + okText("flags + built-in defaults in use"))

	fmt.Println("  ● Calibrating network interfaces...")
	fmt.Printf("    %s interface %s (%s)\n", okText(""), cfg.Interface, cfg.SelfIP)

	fmt.Println("  ● Verifying utilities...")
	for _, ut := range []string{"arpspoof", "tc", "ping", "arping"} {
		if _, err := exec.LookPath(ut); err == nil {
			fmt.Printf("    %s %s\n", okText(""), ut)
		} else {
			fmt.Printf("    %s %s (missing)\n", warnText(""), ut)
		}
	}

	fmt.Println("  ● Preparing traffic engine...")
	if fwd, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		fmt.Printf("    %s ip_forward=%s (toggled only during a test)\n", okText(""), strings.TrimSpace(string(fwd)))
	}
	fmt.Println()
}

func okText(s string) string {
	return c(cGreen, "[✓] "+s)
}

func warnText(s string) string {
	return c(cYellow, "[!] "+s)
}

// quickRef shows the main examples, mirroring the Bash startup reference.
func quickRef() {
	fmt.Println(c(cDim, "  ─────────────────────────────────────────────────"))
	fmt.Println("  " + c(cBold+cHeader, "QUICK REFERENCE") + "  " + c(cDim, "(full list: -h)"))
	fmt.Println("    gnulte -t 192.168.1.20 --profile voip --duration 300")
	fmt.Println("    gnulte -r 192.168.1.0/24 -w 192.168.1.100       range attack")
	fmt.Println("    gnulte -t 192.168.1.20 --block                   100% block")
	fmt.Println("    gnulte -t 192.168.1.20 --sound --random           ping beeps + random walk")
	fmt.Println("    gnulte --scan / --dupcheck                       discovery tools")
	fmt.Println("  " + c(cDim, "  With no targeting flags, gnulte opens the guided menu below."))
	fmt.Println(c(cDim, "  ─────────────────────────────────────────────────"))
	fmt.Println()
}

// spinnerMsg animates a spinner until done is closed, then prints a check mark.
func spinnerMsg(msg string, done <-chan struct{}) {
	if !ansi {
		<-done
		fmt.Printf("%s %s\n", okText(""), msg)
		return
	}
	spin := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	i := 0
	t := time.NewTicker(80 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-done:
			fmt.Printf("\r%s %s                    \n", okText(""), msg)
			return
		case <-t.C:
			fmt.Printf("\r[%c] %s ", spin[i%len(spin)], msg)
			i++
		}
	}
}

// scanAndSelect probes the local subnet, shows a numbered table and returns
// the operator's selection (or the full list when 'r' is chosen).
func scanAndSelect(ctx context.Context, cfg netutil.Config) []string {
	subnet := subnetCIDR(cfg.SelfIP, cfg.Netmask)
	hosts, err := netutil.HostsInCIDR(subnet)
	if err != nil || len(hosts) == 0 {
		fatal(fmt.Errorf("could not enumerate %s (%v)", subnet, err))
	}

	var rows []discover.Row
	workDone := make(chan struct{})
	go func() {
		defer close(workDone)
		rows = rowsFromScan(cfg, discover.PingSweep(ctx, hosts, 128))
	}()
	spinnerMsg("Probing "+subnet+" for live devices...", workDone)

	if len(rows) == 0 {
		fatal(fmt.Errorf("no other devices found on the network"))
	}
	out.SortByIP(rows)

	fmt.Println(c(cBold, "Device List:"))
	fmt.Println(c(cDim, "  #  IP Address        Hostname         Type         Vendor"))
	fmt.Println("  ──────────────────────────────────────────────────────────────────")
	for i, r := range rows {
		mark := " "
		if r.IsSelf {
			mark = "S"
		} else if r.IP == cfg.Gateway {
			mark = "G"
		}
		num := c(cYellow, fmt.Sprintf("%-2d%s", i+1, mark))
		ipc := c(cTarget, fmt.Sprintf("%-16s", r.IP))
		hostc := c(cDim, fmt.Sprintf("%-16s", truncate(r.Hostname, 16)))
		fmt.Printf("  %s %s %s %-12s %s\n", num, ipc, hostc, truncate(r.Type, 12), truncate(r.Vendor, 18))
	}
	fmt.Println("  ──────────────────────────────────────────────────────────────────")
	fmt.Println("  " + c(cDim, "G = gateway | S = this host | r/a = all devices | 0 = exit | Example: '1,2,3'"))
	fmt.Println()

	for {
		fmt.Print(c(cDim, "Enter device number(s) (comma-separated) or 'r' for all: "))
		if !stdinReader().Scan() {
			return nil
		}
		sel := strings.TrimSpace(stdinReader().Text())
		if sel == "0" {
			fmt.Println("Exiting.")
			os.Exit(0)
		}
		var chosen []string
		valid := true
		if sel == "r" || sel == "a" || sel == "R" || sel == "A" {
			for _, r := range rows {
				if !r.IsSelf {
					chosen = append(chosen, r.IP)
				}
			}
		} else {
			for _, part := range strings.Split(sel, ",") {
				part = strings.TrimSpace(part)
				n, err := strconv.Atoi(part)
				if err != nil || n < 1 || n > len(rows) {
					fmt.Printf("  %s invalid selection: %s\n", warnText(""), part)
					valid = false
					break
				}
				chosen = append(chosen, rows[n-1].IP)
			}
		}
		if !valid || len(chosen) == 0 {
			continue
		}
		uniq := []string{}
		seen := map[string]bool{}
		for _, ip := range chosen {
			if !seen[ip] {
				seen[ip] = true
				uniq = append(uniq, ip)
			}
		}
		fmt.Println()
		fmt.Printf("  %s selected %d device(s): %s\n\n", okText(""), len(uniq), strings.Join(uniq, ", "))
		return uniq
	}
}

func truncate(s string, n int) string {
	if len([]rune(s)) > n {
		return string([]rune(s)[:n])
	}
	return s
}

// rowsFromScan builds device rows from live ping results plus any extra
// neighbours in the ARP table (quiet hosts that ignore ICMP).
func rowsFromScan(cfg netutil.Config, live []string) []discover.Row {
	neighbors := discover.Neighbors(context.Background(), cfg.Interface)
	seen := map[string]bool{}
	var rows []discover.Row
	add := func(ip, mac string) {
		if ip == cfg.SelfIP || seen[ip] {
			return
		}
		seen[ip] = true
		vendor := discover.VendorFor(mac)
		host := discover.ResolveHost(context.Background(), ip)
		rows = append(rows, discover.Row{
			IP:       ip,
			MAC:      mac,
			Vendor:   vendor,
			Hostname: host,
			Type:     discover.Classify(vendor, host),
			IsSelf:   ip == cfg.SelfIP,
		})
	}
	for _, ip := range live {
		add(ip, neighbors[ip])
	}
	for ip, mac := range neighbors {
		add(ip, mac)
	}
	return rows
}

// subnetCIDR derives a /CIDR from the interface IP and dotted netmask.
func subnetCIDR(ip, mask string) string {
	ip4 := strings.Split(mask, ".")
	ones := 0
	for _, o := range ip4 {
		if o == "255" {
			ones += 8
		}
	}
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, ones))
	if err != nil {
		return fmt.Sprintf("%s/24", ip)
	}
	return ipnet.String()
}

func prompt(promptFmt string, args ...any) string {
	fmt.Printf(promptFmt, args...)
	if !stdinReader().Scan() {
		return ""
	}
	return strings.TrimSpace(stdinReader().Text())
}

// paramsWizard interactively configures latency/jitter/loss/dup/reorder/
// bandwidth/duration. Defaults prefill from the current config (already
// influenced by any flags or profile); Enter keeps a value.
func paramsWizard(ec *engine.Config, duration *int) {
	fmt.Println()
	fmt.Println("  " + c(cBold+cCyan, "Parameter Configuration:") + "  " + c(cDim, "Enter keeps current values."))
	fmt.Println()
	fmt.Println("  " + c(cDim, "Profiles: gaming | streaming | voip | web | extreme | throttle (or 'manual')"))
	prof := prompt("  Profile [manual]: ")

	if prof != "" && prof != "manual" {
		p, ok := profiles[prof]
		if ok {
			ec.LatencyMS, ec.JitterMS, ec.LossPct, ec.DupPct, ec.ReorderPct, ec.BandwidthKbps = p[0], p[1], p[2], p[3], p[4], p[5]
			fmt.Println("  " + okText("using profile: "+prof))
		} else {
			fmt.Println("  " + warnText("unknown profile — proceeding with manual configuration"))
		}
		fmt.Println()
	}
	promptInt := func(name, hint, def string, dst *int) {
		fmt.Println("  " + c(cDim, hint))
		ans := prompt("  %s [%s]: ", name, def)
		if ans == "" {
			return
		}
		if v, err := strconv.Atoi(ans); err == nil {
			*dst = v
		} else {
			fmt.Println("  " + warnText("ignoring non-numeric value"))
		}
		fmt.Println()
	}

	promptInt("Latency (ms)", "  Base delay added to every packet. 500=noticeable | 2000=significant | 5000=breakdown.", fmt.Sprintf("%d", ec.LatencyMS), &ec.LatencyMS)
	promptInt("Jitter (ms)", "  Random variation in delay. 100=stable | 500=stuttering | 1000=chaotic.", fmt.Sprintf("%d", ec.JitterMS), &ec.JitterMS)
	promptInt("Loss (%)", "  Percentage of packets dropped. 1-2=retransmits | 5-10=disconnects | 15+=offline.", fmt.Sprintf("%d", ec.LossPct), &ec.LossPct)
	promptInt("Duplicate (%)", "  Duplicate packets (confuses TCP).", fmt.Sprintf("%d", ec.DupPct), &ec.DupPct)
	promptInt("Reorder (%)", "  Out-of-order packets (breaks TCP flow).", fmt.Sprintf("%d", ec.ReorderPct), &ec.ReorderPct)
	promptInt("Bandwidth (kbps)", "  Limit in kbps, 0 = unlimited. 2048=2Mbps | 512 | 128 | 64.", fmt.Sprintf("%d", ec.BandwidthKbps), &ec.BandwidthKbps)
	promptInt("Duration (s)", "  Auto-stop after N seconds (0 = until Ctrl+C).", fmt.Sprintf("%d", *duration), duration)

	fmt.Println("  Configuration:")
	fmt.Printf("    %s latency=%dms jitter=%dms loss=%d%% dup=%d%% reorder=%d%% cap=%dkbps\n",
		okText(""), ec.LatencyMS, ec.JitterMS, ec.LossPct, ec.DupPct, ec.ReorderPct, ec.BandwidthKbps)
	if *duration > 0 {
		fmt.Printf("    duration=%ds\n", *duration)
	}
	fmt.Println()
}

// confirmStart mirrors the Bash "Begin test? (y/N)" prompt.
func confirmStart() bool {
	ans := prompt("Begin test? (y/N): ")
	if ans == "" {
		return false
	}
	a := strings.ToLower(ans)
	return a == "y" || a == "yes"
}
