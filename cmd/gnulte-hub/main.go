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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const version = "17.0"

// action is one menu row. An empty Binary marks the quit row.
type action struct {
	Label  string
	Detail string
	Binary string
	Args   []string
}

func actions() []action {
	return []action{
		{Label: "Test a connection", Detail: "guided test on a device you own", Binary: "gnulte"},
		{Label: "Check this machine", Detail: "is everything ready?", Binary: "gnulte-quicksum"},
		{Label: "Find devices", Detail: "sweep the network", Binary: "gnulte-scan"},
		{Label: "See connected devices", Detail: "saved inventory", Binary: "gnulte-inventory"},
		{Label: "Watch live traffic", Detail: "six-screen live monitor", Binary: "gnulte-watch"},
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

	for {
		idx, ok := tui.Menu("GNULTE — pick what you want to do", menuItems(list, available))
		tui.RunCleanups()
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
			pause()
			continue
		}
		fmt.Printf("\n  Starting %s...\n\n", a.Binary)
		err := runAction(path, a.Args)
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 0 {
				fmt.Printf("\n  %s exited with status %d.\n", a.Binary, ee.ExitCode())
			} else {
				fmt.Printf("\n  Could not run %s: %v\n", a.Binary, err)
			}
		}
		pause()
	}
}
