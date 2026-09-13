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

// Package ux holds small shared terminal helpers for the GNULTE tools:
// live-terminal detection, ANSI colouring that degrades cleanly when piped,
// width-aware progress bars with a spinner, and a line capture that builds an
// HTML-friendly transcript of a session.
package ux

import (
	"io"
	"os"
	"strings"
)

// ANSI palettes shared across the tools.
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Red    = "\033[0;31m"
	Green  = "\033[0;32m"
	Yellow = "\033[1;33m"
	Cyan   = "\033[0;36m"
	Header = "\033[1;36m"
	Target = "\033[1;33m"
)

// Out is the console writer used by Bar and Busy. Export commands point it at
// stderr so their data stream stays clean on stdout; live console tools leave
// it on stdout.
var Out io.Writer = os.Stdout

// TTY reports whether the process is driving a real terminal (enables the
// spinner, progress bar, and colours). Piped output stays plain and parseable.
func TTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// C wraps s in an ANSI code when the output is a live terminal, otherwise
// returns s untouched so redirected output stays parseable.
func C(code, s string) string {
	if !tty {
		return s
	}
	return code + s + Reset
}

var tty = TTY()

// Clamp rounds a value into [lo, hi].
func Clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// RuneLen counts runes, so wide CJK glyphs and ANSI codes are measured the way
// a terminal counts them (approximately).
func RuneLen(s string) int {
	return len([]rune(s))
}

// Trunc ellipsizes s at n runes.
func Trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// SplitHostPorts parses "443,80,53" into a port list, skipping garbage.
func SplitPorts(s string) []int {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		var n int
		ok := true
		for _, c := range p {
			if c < '0' || c > '9' {
				ok = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if !ok || n < 1 || n > 65535 {
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
