// GNULTE — network testing toolkit (Go).
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

// The GNULTE front end: animated banner, administrator-privilege handshake,
// live boot checks, spinner scans, a guided device menu and the impairment
// wizard — the same experience the shop version shipped, now in Go.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/engine"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/out"
	"gnulte-go/internal/ux"
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
	cTarget = "\033[1;33m"
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

func okText(s string) string {
	return c(cGreen+cBold, "[✓]") + " " + s
}

func warnText(s string) string {
	return c(cYellow+cBold, "[!]") + " " + s
}

// printBanner draws the ASCII logo and tagline with a pulse on the subtitle.
func printBanner() {
	fmt.Println(c(cHeader, `  ██████╗ ███╗   ██╗██╗   ██╗██╗  ████████╗███████╗`))
	fmt.Println(c(cHeader, ` ██╔════╝ ████╗  ██║██║   ██║██║  ╚══██╔══╝██╔════╝`))
	fmt.Println(c(cHeader, ` ██║  ███╗██╔██╗ ██║██║   ██║██║     ██║   █████╗     /████╗ /████╗ ██╗`))
	fmt.Println(c(cHeader, ` ██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██╔══╝    /██╔══╝/██╔═██╗██║`))
	fmt.Println(c(cHeader, ` ╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ███████╗  ██║  ██╗██║  ██║╚═╝`))
	fmt.Println(c(cHeader, `  ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝  ╚█████╔╝╚█████╔╝██╗`))
	fmt.Println()
	fmt.Println("  " + c(cCyan+cBold, "GNU LAN Network Testing Environment"))
	pulseLine("  Version "+version+" — the original toolkit, now in Go", cCyan, cDim)
	fmt.Println("  " + c(cDim, "Authorised testing on networks you own."))
	fmt.Println()
}

// pulseLine blinks a line between bright and dim before leaving it resolved.
func pulseLine(text, bright, dim string) {
	if !ansi {
		fmt.Println("  " + text)
		return
	}
	for i := 0; i < 2; i++ {
		fmt.Printf("\r" + c(bright+cBold, text))
		time.Sleep(90 * time.Millisecond)
		fmt.Printf("\r" + c(dim, text))
		time.Sleep(90 * time.Millisecond)
	}
	fmt.Printf("\r" + c(bright+cBold, text) + "\n")
}

// adminBox mirrors the toolkit's "Administrator Privileges Required" handshake
// shown before the password prompt.
func adminBox() {
	fmt.Println()
	fmt.Println(c(cYellow, "════════════════════════════════════════════════════════════════════"))
	fmt.Println(c(cYellow+cBold, "          ADMINISTRATOR PRIVILEGES REQUIRED"))
	fmt.Println(c(cYellow, "════════════════════════════════════════════════════════════════════"))
	fmt.Println()
	fmt.Println("GNULTE needs sudo (root) access for the following reasons:")
	fmt.Println()
	fmt.Println("  • arp-scan  – raw sockets to scan the network")
	fmt.Println("  • arpspoof  – raw sockets to send ARP packets")
	fmt.Println("  • tc        – kernel-level control of packet flow")
	fmt.Println("  • sysctl    – enable IP forwarding for MITM operation")
	fmt.Println("  • iptables  – forward/DROP rules for block mode")
	fmt.Println()
	fmt.Println("Without sudo, these cannot function. GNULTE will now request")
	fmt.Println("your password and run the test session with the privileges it needs.")
	fmt.Println()
	fmt.Println(c(cYellow, "════════════════════════════════════════════════════════════════════"))
	fmt.Println()
}

// bootSeq runs the startup checks step by step: each phase animates while its
// real check runs, then resolves to a check mark.
func bootSeq(cfg netutil.Config) {
	fmt.Println("  " + c(cCyan+cBold, " GNULTE v"+version+" — Initialising"))
	fmt.Println("  " + c(cDim, " Real checks only — every ✓ below is a live result."))
	fmt.Println()

	bootPhase("Loading configuration")
	bootResult("flags + built-in defaults in use", false)

	bootPhase("Calibrating network interfaces")
	bootResult(fmt.Sprintf("interface %s (%s)", cfg.Interface, cfg.SelfIP), false)

	bootPhase("Verifying utilities")
	for _, ut := range []string{"arpspoof", "tc", "ping", "arping", "iptables"} {
		_, err := exec.LookPath(ut)
		if err != nil {
			bootResult(ut+" (MISSING — install it for full function)", true)
		} else {
			bootResult(ut, false)
		}
	}

	bootPhase("Preparing traffic engine")
	if fwd, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		bootResult("ip_forward="+strings.TrimSpace(string(fwd))+" (toggled only during a test)", false)
	} else {
		bootResult("could not read ip_forward", true)
	}

	fmt.Println()
	pulseLine("▸ GNULTE v"+version+" ready — building your session below", cTarget, cDim)
	fmt.Println()
}

// bootPhase animates a spinner on a phase line, then leaves the title behind.
func bootPhase(title string) {
	fmt.Printf("  ● %s...", title)
	if ansi {
		spin := []rune("⠋⠙⠹")
		for i := 0; i < 3; i++ {
			fmt.Printf("\r  ● %s %c ", title, spin[i])
			time.Sleep(60 * time.Millisecond)
		}
	}
	fmt.Printf("\r  ● %s...\n", title)
}

func bootResult(detail string, warn bool) {
	if warn {
		fmt.Println("    " + warnText(detail))
		return
	}
	fmt.Println("    " + okText(detail))
}

// quickRef shows the main examples.
func quickRef() {
	fmt.Println(c(cDim, "  ─────────────────────────────────────────────────"))
	fmt.Println("  " + c(cBold+cHeader, "QUICK REFERENCE") + "  " + c(cDim, "(full list: -h)"))
	fmt.Println("    gnulte -t 192.168.1.20 --profile voip --duration 300")
	fmt.Println("    gnulte -t android-3 --interval 1                  target by hostname")
	fmt.Println("    gnulte --device-type phone --profile gaming        target every phone")
	fmt.Println("    gnulte --vendor Xiaomi                            target by maker")
	fmt.Println("    gnulte -r 192.168.1.0/24 -w 192.168.1.100        range attack")
	fmt.Println("    gnulte -t 192.168.1.20 --block                    100% block")
	fmt.Println("    gnulte -t 192.168.1.20 --random                     beeps + random walk")
	fmt.Println("    gnulte -t 192.168.1.20 --interval 2                  ping every 2s")
	fmt.Println("    gnulte --no-sound                                   silence the ping beeps")
	fmt.Println("    gnulte --scan / --dupcheck                          discovery tools")
	fmt.Println("    gnulte --settings                                 edit saved defaults")
	fmt.Println("    gnulte-traffic -i wlan0 -t 192.168.1.1,192.168.1.50   live per-host speed")
	fmt.Println("  " + c(cDim, "  With no targeting flags, the guided menu opens below."))
	fmt.Println(c(cDim, "  ─────────────────────────────────────────────────"))
	fmt.Println()
}

// progressBar draws a compact bar driven by real work progress, then inks
// over it with a check mark. total is the number of probes; prog streams
// (completed, alive) counts. Falls back to a plain log line when piped.
func progressBar(msg string, total int, done <-chan struct{}, prog <-chan [2]int) {
	const width = 18
	if !ansi {
		<-done
		fmt.Println(okText(msg))
		return
	}
	seg := 0
	for {
		select {
		case <-done:
			fill := strings.Repeat("█", width)
			fmt.Printf("\r  [%s] %s %s\n", c(cGreen, fill), msg, okText(""))
			return
		case p, ok := <-prog:
			if !ok {
				prog = nil
				continue
			}
			if total > 0 {
				seg = p[0] * width / total
			}
			fill := strings.Repeat("█", seg) + strings.Repeat("░", width-seg)
			fmt.Printf("\r  [%s] %s %d/%d · %d live", fill, msg, p[0], total, p[1])
		}
	}
}

// manualTargetPrompt asks, before the whole subnet is swept for the device
// table, whether the operator would rather type an IP (or hostname) by hand.
// The sweep stays the default on a bare Enter, so the guided flow never stalls;
// a resolved single target skips the sweep entirely. Ctrl-D aborts as usual.
func manualTargetPrompt(ctx context.Context, cfg netutil.Config) (target string, manual bool) {
	fmt.Println()
	fmt.Println("  " + c(cBold+cCyan, "Target setup:") + "  " + c(cDim, "type an IP by hand, or sweep the subnet?"))
	fmt.Println("   1) type an IP (or hostname) manually")
	fmt.Println("   2) sweep " + subnetCIDR(cfg.SelfIP, cfg.Netmask) + " and pick from the device list")
	if strings.TrimSpace(prompt("  choice [2]: ")) != "1" {
		return "", false
	}
	for {
		t := strings.TrimSpace(prompt("  Target IP or hostname: "))
		if t == "" {
			if promptEOF {
				return "", false
			}
			fmt.Println("  " + warnText("empty target — type an IP or hostname, or Ctrl-C to stop"))
			continue
		}
		if net.ParseIP(t) == nil {
			ip, err := resolveTargetName(ctx, cfg, t)
			if err != nil {
				fmt.Printf("  %s could not resolve %q (%v)\n", warnText(""), t, err)
				continue
			}
			t = ip
		}
		fmt.Println("  " + okText("target: "+t))
		return t, true
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
	if len(hosts) > 1024 {
		fmt.Printf("  %s subnet %s has %d addresses — the sweep may take a while\n", warnText(""), subnet, len(hosts))
	}

	var rows []discover.Row
	workDone := make(chan struct{})
	progCh := make(chan [2]int, 8)
	go func() {
		defer close(workDone)
		live := discover.PingSweep(ctx, hosts, 128, func(done, alive int) {
			select {
			case progCh <- [2]int{done, alive}:
			default:
			}
		})
		close(progCh)
		rows = rowsFromScan(cfg, live)
	}()
	progressBar("scanning "+subnet+" for live devices", len(hosts), workDone, progCh)

	if len(rows) == 0 {
		fatal(fmt.Errorf("no other devices found on the network"))
	}
	out.SortByIP(rows)

	fmt.Println(c(cBold, "Device List:"))
	fmt.Println(c(cDim, "  #  IP Address        Hostname         Type         Vendor"))
	fmt.Println("  ──────────────────────────────────────────────────────────────────")
	for i, r := range rows {
		mark := " "
		numCol := cYellow
		if r.IsSelf {
			mark = "S"
			numCol = cHeader
		} else if r.IP == cfg.Gateway {
			mark = "G"
			numCol = cTarget
		}
		num := c(numCol, fmt.Sprintf("%-2d%s", i+1, mark))
		ipc := c(ux.DeviceIPCode(r.IsSelf, r.Type), fmt.Sprintf("%-16s", r.IP))
		hostc := c(cDim, fmt.Sprintf("%-16s", truncate(r.Hostname, 16)))
		typc := c(ux.TypeColor(r.Type), fmt.Sprintf("%-12s", truncate(r.Type, 12)))
		fmt.Printf("  %s %s %s %s %s\n", num, ipc, hostc, typc, truncate(r.Vendor, 18))
	}
	fmt.Println("  ──────────────────────────────────────────────────────────────────")
	fmt.Println("  " + c(cDim, "colours by type · bright = this host · yellow = gateway | 'r' = all · 0 = exit"))
	fmt.Println("  " + c(cDim, "For deeper identification — vendors, types, mDNS services, port scans — run"))
	fmt.Println("  " + c(cDim, "gnulte-scan (SCANLTE: 'gnulte-scan -T') or investigate the network yourself."))
	fmt.Println()

	for {
		fmt.Print(c(cDim, "Enter device number(s) (comma-separated) or 'r' for all: "))
		if !stdinReader().Scan() {
			promptEOF = true // Ctrl-D on an empty line aborts instead of looping
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
				// The router is your way in and out of the network, not a
				// test target: sweeping it would shape your own uplink.
				if !r.IsSelf && r.IP != cfg.Gateway {
					chosen = append(chosen, r.IP)
				}
			}
			if cfg.Gateway != "" {
				fmt.Println("  " + c(cDim, fmt.Sprintf("(gateway %s left out of the sweep — it is not a test target)", cfg.Gateway)))
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
	discover.EnrichHostnames(context.Background(), rows)
	return rows
}

// subnetCIDR derives a /CIDR from the interface IP and dotted netmask. The
// prefix length comes from the mask's leading 1-bits — counting octets equal
// to "255" wrongly turned 255.255.254.0 into /16 and 255.255.255.128 into /24.
func subnetCIDR(ip, mask string) string {
	m := net.ParseIP(mask)
	if m == nil {
		return fmt.Sprintf("%s/24", ip)
	}
	ones, bits := net.IPMask(m.To4()).Size()
	if bits == 0 || ones == 0 { // non-contiguous or zero mask: keep it simple
		return fmt.Sprintf("%s/24", ip)
	}
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, ones))
	if err != nil {
		return fmt.Sprintf("%s/24", ip)
	}
	return ipnet.String()
}

// promptEOF is set when stdin hit end-of-input (Ctrl-D or a closed pipe):
// callers then treat the reply as "abort" instead of "keep the default", so a
// stray Ctrl-D cannot silently walk the whole wizard with defaults.
var promptEOF bool

func prompt(promptFmt string, args ...any) string {
	fmt.Printf(promptFmt, args...)
	if !stdinReader().Scan() {
		promptEOF = true
		return ""
	}
	return strings.TrimSpace(stdinReader().Text())
}

// paramsWizard interactively configures latency/jitter/loss/dup/reorder/
// bandwidth/duration/sound/interval. Defaults prefill from the current config
// (already influenced by any flags or profile); Enter keeps a value.
func paramsWizard(ec *engine.Config, duration *int, beep *bool, interval *int) {
	fmt.Println()
	fmt.Println("  " + c(cBold+cCyan, "Parameter Configuration:") + "  " + c(cDim, "Enter keeps current values."))
	fmt.Println()
	fmt.Println("  " + c(cBold, "Preset profiles:") + "  " + c(cDim, "pick a number or name · Enter = manual (no typing needed)"))
	var profHelp []string
	for i, name := range profileOrder {
		profHelp = append(profHelp, fmt.Sprintf("%2d %s", i+1, name))
	}
	for i := 0; i < len(profHelp); i += 2 {
		line := "  " + profHelp[i]
		if i+1 < len(profHelp) {
			line += "   " + profHelp[i+1]
		}
		fmt.Println(c(cDim, line))
	}
	prof := strings.TrimSpace(prompt("  Profile [Enter=manual]: "))

	if prof != "" && prof != "manual" {
		if n, err := strconv.Atoi(prof); err == nil && n >= 1 && n <= len(profileOrder) {
			prof = profileOrder[n-1]
		}
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
	if *duration == 0 {
		promptInt("Duration (s)", "  Auto-stop after N seconds (0 = until Ctrl+C).", "0", duration)
	} else {
		promptInt("Duration (s)", "  Auto-stop after N seconds (0 = until Ctrl+C).", fmt.Sprintf("%d", *duration), duration)
	}

	fmt.Println("  " + c(cDim, "Sounds: a short tone per ping — higher pitch = faster reply."))
	soundCur := "y"
	if !*beep {
		soundCur = "n"
	}
	if ans := prompt("  Beep per ping result? (y/N) [%s]: ", soundCur); ans != "" {
		*beep = strings.HasPrefix(strings.ToLower(ans), "y")
	}
	if ans := prompt("  Ping every N seconds [%d]: ", *interval); ans != "" {
		if v, err := strconv.Atoi(ans); err == nil && v >= 1 {
			*interval = v
		} else {
			fmt.Println("  " + warnText(fmt.Sprintf("ignoring non-numeric interval (kept %ds)", *interval)))
		}
	}

	fmt.Println("  Configuration:")
	fmt.Printf("    %s latency=%dms jitter=%dms loss=%d%% dup=%d%% reorder=%d%% cap=%dkbps\n",
		okText(""), ec.LatencyMS, ec.JitterMS, ec.LossPct, ec.DupPct, ec.ReorderPct, ec.BandwidthKbps)
	if *duration > 0 {
		fmt.Printf("    duration=%ds\n", *duration)
	}
	fmt.Printf("    beeps=%s interval=%d%s\n", onOff(*beep), *interval, c(cDim, "s"))
	fmt.Println()
}

// onOff returns a compact yes/no label.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// confirmStart mirrors the toolkit's "Begin test? (y/N)" prompt.
func confirmStart() bool {
	ans := prompt("Begin test? (y/N): ")
	if ans == "" {
		return false
	}
	a := strings.ToLower(ans)
	return a == "y" || a == "yes"
}

// watchMode selects how a multi-target test is displayed.
type watchMode int

const (
	watchDashboard watchMode = iota
	watchOneWindow
	watchWindows
)

// trafficWindowChoice asks how to watch multiple targets: the combined console
// dashboard, one traffic & speed monitor window, or one separate window per
// target (tabs in terminal emulators that support them).
func trafficWindowChoice() watchMode {
	fmt.Println()
	fmt.Println(c(cCyan+cBold, " Two or more targets selected — how do you want to watch them?"))
	fmt.Println("   1) all targets in this console dashboard (default)")
	fmt.Println("   2) traffic & speed monitor in one separate window")
	fmt.Println("   3) one separate window per target (tabs)")
	sel := strings.TrimSpace(prompt("   choice [1/2/3]: "))
	fmt.Println()
	switch sel {
	case "2":
		return watchOneWindow
	case "3":
		return watchWindows
	default:
		return watchDashboard
	}
}

// launchTrafficWindow detaches a gnulte-traffic window for the watched targets
// so the two views can be compared side by side. It warns rather than failing
// when no terminal emulator is available.
func launchTrafficWindow(interval int, iface string, targets []string) {
	bin := trafficBinary()
	if bin == "" {
		fmt.Println("  " + warnText("gnulte-traffic is not installed — run the traffic monitor separately (gnulte-traffic -i ... -t ...)"))
		return
	}
	args := []string{bin, "-i", iface, "-t", strings.Join(targets, ",")}
	if interval > 0 {
		args = append(args, "--interval", strconv.Itoa(interval))
	}
	started, err := ux.LaunchTerminal(args...)
	if err != nil {
		fmt.Printf("  %s could not open a terminal window: %v\n", warnText(""), err)
		return
	}
	if !started {
		fmt.Println("  " + warnText("no terminal emulator found — add $TERMINAL (e.g. export TERMINAL='xterm -e') to enable the separate window"))
		return
	}
	fmt.Println("  " + okText("Traffic monitor opened in a separate window — "+strings.Join(targets, ", ")))
}

// launchTrafficWindows detaches one gnulte-traffic terminal window per target,
// so each target gets a focused monitor of its own (tabs where the terminal
// emulator supports them). Warns rather than failing mid-way.
func launchTrafficWindows(interval int, iface string, targets []string) {
	bin := trafficBinary()
	if bin == "" {
		fmt.Println("  " + warnText("gnulte-traffic is not installed — run the traffic monitor separately (gnulte-traffic -i ... -t ...)"))
		return
	}
	startedAny := false
	for _, t := range targets {
		args := []string{bin, "-i", iface, "-t", t}
		if interval > 0 {
			args = append(args, "--interval", strconv.Itoa(interval))
		}
		started, err := ux.LaunchTerminal(args...)
		if err != nil {
			fmt.Printf("  %s could not open a terminal window for %s: %v\n", warnText(""), t, err)
			continue
		}
		if !started {
			fmt.Println("  " + warnText("no terminal emulator found — add $TERMINAL (e.g. export TERMINAL='xterm -e') to enable separate windows"))
			return
		}
		startedAny = true
	}
	if startedAny {
		fmt.Println("  " + okText(fmt.Sprintf("One traffic monitor window per target opened (%d/%d) — Ctrl+C in any window closes it.",
			len(targets), len(targets))))
	}
}

// trafficBinary locates the installed gnulte-traffic binary (directly beside
// the running gnulte or in PATH).
func trafficBinary() string {
	if p, err := exec.LookPath("gnulte-traffic"); err == nil {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "gnulte-traffic")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
