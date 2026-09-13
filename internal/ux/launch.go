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

package ux

import (
	"os"
	"os/exec"
	"strings"
)

// terminalPrefixes lists every terminal emulator we can open as a detached
// window, along with the flag each one wants before the child command line.
// Order matters: $TERMINAL is honoured first, then the most common emulators.
func terminalPrefixes() [][]string {
	prefixes := [][]string{
		{"x-terminal-emulator", "-e"},
		{"gnome-terminal", "--"},
		{"konsole", "-e"},
		{"xfce4-terminal", "-x"},
		{"kitty"},
		{"alacritty", "-e"},
		{"tilix", "-e"},
		{"terminator", "-x"},
		{"xterm", "-e"},
		{"rxvt", "-e"},
		{"urxvt", "-e"},
	}
	if t := os.Getenv("TERMINAL"); strings.TrimSpace(t) != "" {
		return append([][]string{strings.Fields(t)}, prefixes...)
	}
	return prefixes
}

// LaunchTerminal detaches a fresh terminal window running the given command
// line and returns immediately. It reports whether a window was started and
// an error when an emulator was found but failed to launch.
func LaunchTerminal(args ...string) (bool, error) {
	for _, prefix := range terminalPrefixes() {
		name := prefix[0]
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		full := append(append([]string{}, prefix[1:]...), args...)
		cmd := exec.Command(path, full...)
		cmd.Env = os.Environ()
		if err := cmd.Start(); err != nil {
			return false, err
		}
		// Detach: the launched window is not waited on.
		go cmd.Wait()
		return true, nil
	}
	return false, nil
}
