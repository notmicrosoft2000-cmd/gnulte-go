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

// Command gnulte-hub is the front door for the toolkit: one plain-language
// menu that finds and runs the other binaries. It does no network work itself
// and needs no privileges; each child asks for root only when it needs it.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gnulte-go/internal/settings"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "17.0"

// Exact copy for the contextual hub screens. Keeping it in constants makes
// the plain-menu fallback and the full-screen frames say the same thing.
const (
	h1Title   = "GNULTE — what do you want to do?"
	h1Context = "Nothing starts until you choose. Tools run in this terminal and ask for root only when they need it."
	h1Note    = "Detailed controls are available on the next step. Direct values never require them."
	h1Foot    = "↑/↓ choose   Enter run   number jump   q quit"

	h2Title = "Detailed controls?"
	h2Help  = "Detailed adds session controls. It does not hide direct value entry."
	h2Foot  = "↑/↓ choose   Enter continue   number jump   Esc back"

	h3Title = "How slow should it feel?"
	h3Help  = "Presets set latency, jitter, loss, duplication, reorder and bandwidth."
	h3Foot  = "↑/↓ choose   Enter continue   number jump   Esc back"
)

// shapingValues mirrors the seven numeric fields of gnulte's paramsWizard.
// The hub collects them locally so the child never reopens the wizard.
type shapingValues struct {
	latency   int
	jitter    int
	loss      int
	duplicate int
	reorder   int
	bandwidth int
	duration  int
}

// sessionControls are launch-only overrides from the Detailed step. None of
// these values are written back to the settings file.
type sessionControls struct {
	beep     bool
	interval int
	echo     bool
}

// action is one menu row. An empty Binary marks the quit row.
type action struct {
	Label  string
	Detail string
	Binary string
	Args   []string
}

func actions() []action {
	return []action{
		{Label: "Test a connection", Detail: "pick a device, then shape its traffic", Binary: "gnulte"},
		{Label: "Check this machine", Detail: "is everything ready?", Binary: "gnulte-quicksum"},
		{Label: "Find devices", Detail: "sweep the network", Binary: "gnulte-scan"},
		{Label: "See connected devices", Detail: "saved inventory", Binary: "gnulte-inventory"},
		{Label: "Watch live traffic", Detail: "seven-screen live monitor", Binary: "gnulte-watch"},
		{Label: "Wi-Fi tools", Detail: "authorised deauth testing", Binary: "gnulte-wifi"},
		{Label: "Open reports", Detail: "list, merge and compare", Binary: "gnulte-report"},
		{Label: "Read the safety rules", Detail: "before you begin", Binary: "gnulte", Args: []string{"--docs"}},
		{Label: "Quit", Detail: ""},
	}
}

// findBinary looks beside the launcher first so a folder copied to a USB
// stick works, then falls back to PATH. exeDir is passed in so tests can use
// a temporary directory.
func findBinary(exeDir, name string) string {
	if name == "" {
		return ""
	}
	if exeDir != "" {
		path := filepath.Join(exeDir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return path
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return ""
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

func menuItems(list []action, available []bool) []tui.MenuItem {
	items := make([]tui.MenuItem, len(list))
	for i, a := range list {
		detail := a.Detail
		if a.Binary != "" && !available[i] {
			detail = "not installed"
		}
		items[i] = tui.MenuItem{Label: a.Label, Detail: detail}
	}
	return items
}

// detailedItems and shapingItems mirror the exact rows of H2 and H3 in the
// hub spec; the child's plain-language menus are a different main package and
// cannot be imported here.
func detailedItems() []tui.MenuItem {
	return []tui.MenuItem{
		{Label: "Standard", Detail: "presets and direct values"},
		{Label: "Detailed", Detail: "extra session controls"},
	}
}

func detailedOptions(preselect bool) tui.MenuOptions {
	sel := 0
	if preselect {
		sel = 1
	}
	return tui.MenuOptions{Note: h2Help, Footer: h2Foot, Selected: sel}
}

func chooseDetailed(preselect bool) (int, bool) {
	return tui.MenuWith(h2Title, detailedItems(), detailedOptions(preselect))
}

func shapingItems() []tui.MenuItem {
	return []tui.MenuItem{
		{Label: "A little laggy", Detail: "small stutter, still usable"},
		{Label: "Video calls break up", Detail: "choppy voice and picture"},
		{Label: "Web pages crawl", Detail: "slow browsing"},
		{Label: "Almost offline", Detail: "very hard to use"},
		{Label: "Let me choose numbers", Detail: "set exact values"},
	}
}

func shapingOptions() tui.MenuOptions {
	return tui.MenuOptions{Note: h3Help, Footer: h3Foot}
}

func chooseShaping() (int, bool) {
	return tui.MenuWith(h3Title, shapingItems(), shapingOptions())
}

// profileForShapingIndex maps the four preset rows to gnulte's built-in
// profiles. The last row returns "" and means direct numeric entry.
func profileForShapingIndex(idx int) string {
	switch idx {
	case 0:
		return "cellular"
	case 1:
		return "voip"
	case 2:
		return "web"
	case 3:
		return "extreme"
	default:
		return ""
	}
}

// promptValue prints a prompt and reads one line, one byte at a time so no
// buffered reader can swallow a key meant for the next prompt or child. EOF
// (Ctrl-D on an empty line) reports abort so nothing is launched by accident.
func promptValue(in io.Reader, format string, args ...any) (string, bool) {
	fmt.Printf(format, args...)
	var line strings.Builder
	var b [1]byte
	for {
		n, err := in.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimSpace(line.String()), true
			}
			line.WriteByte(b[0])
		}
		if err != nil {
			if line.Len() > 0 {
				return strings.TrimSpace(line.String()), true
			}
			return "", false
		}
	}
}

// directParams is the hub-local H4: the same fields, defaults and validation
// message as gnulte's paramsWizard, without its profile sub-prompt.
func directParams(r io.Reader) (shapingValues, bool) {
	var v shapingValues
	fmt.Println()
	fmt.Println("  Parameter Configuration:  Enter keeps current values.")
	fmt.Println()
	for _, f := range []struct {
		label string
		dst   *int
	}{
		{"Latency (ms)", &v.latency},
		{"Jitter (ms)", &v.jitter},
		{"Loss (%)", &v.loss},
		{"Duplicate (%)", &v.duplicate},
		{"Reorder (%)", &v.reorder},
		{"Bandwidth (kbps)", &v.bandwidth},
		{"Duration (s)", &v.duration},
	} {
		answer, ok := promptValue(r, "  %s [0]: ", f.label)
		if !ok {
			return v, false
		}
		if answer == "" {
			continue // blank keeps the default
		}
		n, err := strconv.Atoi(answer)
		if err != nil {
			fmt.Println("  ignoring non-numeric value")
			continue
		}
		*f.dst = n
	}
	return v, true
}

func parseOnOff(answer string, current bool) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes", "on", "1":
		return true
	case "n", "no", "off", "0":
		return false
	default:
		return current
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// collectSessionControls is the compact Detailed step for action 1. It shows
// the saved values as defaults and only changes this launch; settings.Save is
// never called from the hub.
func collectSessionControls(cfg settings.Config) (sessionControls, bool) {
	c := sessionControls{beep: cfg.Beeps, interval: cfg.IntervalSec, echo: cfg.Advanced}
	fmt.Println()
	fmt.Println("  Session controls (Detailed):")
	for _, ask := range []func() bool{
		func() bool {
			answer, ok := promptValue(os.Stdin, "  beeps [%s] (y/N): ", onOff(c.beep))
			if !ok || strings.EqualFold(answer, "q") || strings.EqualFold(answer, "quit") {
				return false
			}
			if answer != "" {
				c.beep = parseOnOff(answer, c.beep)
			}
			return true
		},
		func() bool {
			answer, ok := promptValue(os.Stdin, "  ping interval [%ds]: ", c.interval)
			if !ok || strings.EqualFold(answer, "q") || strings.EqualFold(answer, "quit") {
				return false
			}
			if answer == "" {
				return true
			}
			n, err := strconv.Atoi(answer)
			if err != nil || n < 1 {
				fmt.Printf("  ignoring non-numeric interval (kept %ds)\n", c.interval)
				return true
			}
			c.interval = n
			return true
		},
		func() bool {
			answer, ok := promptValue(os.Stdin, "  echo commands in sessions [%s] (y/N): ", onOff(c.echo))
			if !ok || strings.EqualFold(answer, "q") || strings.EqualFold(answer, "quit") {
				return false
			}
			if answer != "" {
				c.echo = parseOnOff(answer, c.echo)
			}
			return true
		},
	} {
		if !ask() {
			return c, false
		}
	}
	return c, true
}

func directShapingFlags(v shapingValues) []string {
	return []string{
		"--latency", strconv.Itoa(v.latency),
		"--jitter", strconv.Itoa(v.jitter),
		"--loss", strconv.Itoa(v.loss),
		"--duplicate", strconv.Itoa(v.duplicate),
		"--reorder", strconv.Itoa(v.reorder),
		"--bandwidth", strconv.Itoa(v.bandwidth),
		"--duration", strconv.Itoa(v.duration),
	}
}

func controlFlags(c sessionControls) []string {
	args := []string{"--interval", strconv.Itoa(c.interval)}
	if c.beep {
		args = append(args, "--sound")
	} else {
		args = append(args, "--no-sound")
	}
	if c.echo {
		args = append(args, "--echo-commands")
	} else {
		args = append(args, "--no-echo-commands")
	}
	return args
}

// shapingLaunchArgs builds the child's command line. Presets keep the compact
// --profile form; direct numbers are passed explicitly. A Detailed choice
// adds the launch-only session controls. Every path gets --from-hub so the
// child never opens its own plain-language front end.
func shapingLaunchArgs(idx int, v shapingValues, ctrl *sessionControls, cfg settings.Config) []string {
	var args []string
	if profile := profileForShapingIndex(idx); profile != "" {
		args = append(args, "--profile", profile)
	} else {
		args = append(args, directShapingFlags(v)...)
	}
	if ctrl != nil {
		args = append(args, controlFlags(*ctrl)...)
	} else if profileForShapingIndex(idx) == "" {
		// Standard direct entry has no beep prompt of its own, so honour
		// the saved setting for this launch.
		sound := "--no-sound"
		if cfg.Beeps {
			sound = "--sound"
		}
		args = append(args, "--interval", strconv.Itoa(cfg.IntervalSec), sound)
	}
	return append(args, "--from-hub")
}

func runAction(path string, args []string) error {
	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func pause() {
	if !ux.TTY() || !tui.StdinTTY() {
		return
	}
	fmt.Print("\n  Press Enter to return to the menu...")
	var discard string
	_, _ = fmt.Fscanln(os.Stdin, &discard)
}

func usage() {
	fmt.Printf(`gnulte-hub v%s — friendly launcher for the GNULTE toolkit

Usage:
  gnulte-hub              open the menu
  gnulte-hub --version    print version and exit

Pick an action with the arrow keys or its number. The hub finds the other
tools next to itself or on PATH and runs them in this terminal. Each tool
asks for administrator access only when it needs it.
`, version)
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(showVersion, "v", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()
	if *showVersion {
		fmt.Printf("gnulte-hub (Go) v%s\n", version)
		return
	}

	// tui's signal cleanup waits for a graceful shutdown before exiting, which
	// is right for a shaping session but too slow for a menu with nothing to
	// restore. Put the screen back and leave as soon as the operator quits.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		tui.RunCleanups()
		fmt.Println()
		os.Exit(130)
	}()

	list := actions()
	dir := exeDir()
	available := make([]bool, len(list))
	for i, a := range list {
		available[i] = findBinary(dir, a.Binary) != ""
	}

	// The saved value only preselects H2. The hub never writes this file.
	prefs, err := settings.Load()
	if err != nil {
		prefs = settings.Default()
	}

	for {
		idx, ok := tui.MenuWith(h1Title, menuItems(list, available), tui.MenuOptions{
			Context: []string{h1Context},
			Note:    h1Note,
			Footer:  h1Foot,
		})
		tui.RunCleanups()
		tui.FlushPending()
		if !ok {
			fmt.Println("Bye.")
			return
		}
		a := list[idx]
		if a.Binary == "" {
			fmt.Println("Bye.")
			return
		}
		path := findBinary(dir, a.Binary)
		if path == "" {
			fmt.Printf("\n  %s is not installed. Put it next to gnulte-hub or on your PATH.\n", a.Binary)
			tui.FlushPending()
			pause()
			continue
		}

		args := append([]string(nil), a.Args...)
		// Actions 1–7 get the Detailed step; 8–9 keep their old behaviour.
		if idx <= 6 {
			dIdx, dOK := chooseDetailed(prefs.HubDetailed)
			tui.RunCleanups()
			tui.FlushPending()
			if !dOK {
				continue
			}
			if idx == 0 {
				sIdx, sOK := chooseShaping()
				tui.RunCleanups()
				tui.FlushPending()
				if !sOK {
					continue
				}
				var values shapingValues
				if profileForShapingIndex(sIdx) == "" {
					var vOK bool
					values, vOK = directParams(os.Stdin)
					tui.FlushPending()
					if !vOK {
						continue
					}
				}
				var ctrl *sessionControls
				if dIdx == 1 {
					c, cOK := collectSessionControls(prefs)
					tui.FlushPending()
					if !cOK {
						continue
					}
					ctrl = &c
				}
				args = append(args, shapingLaunchArgs(sIdx, values, ctrl, prefs)...)
			}
		}

		tui.FlushPending()
		fmt.Printf("\n  Starting %s...\n\n", a.Binary)
		err := runAction(path, args)
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 0 {
				fmt.Printf("\n  %s exited with status %d.\n", a.Binary, ee.ExitCode())
			} else {
				fmt.Printf("\n  Could not run %s: %v\n", a.Binary, err)
			}
		}
		tui.FlushPending()
		pause()
	}
}
