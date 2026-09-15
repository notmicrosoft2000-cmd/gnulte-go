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
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI palettes shared across the tools.
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[0;31m"
	Green   = "\033[0;32m"
	Yellow  = "\033[1;33m"
	Blue    = "\033[0;34m"
	Magenta = "\033[0;35m"
	Cyan    = "\033[0;36m"
	Header  = "\033[1;36m"
	Target  = "\033[1;33m"
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

// TruncPad lays s onto exactly width cells without ever wrapping: ANSI escape
// sequences do not count toward the width, over-long visible text is truncated
// (re-applying a colour reset so the next frame does not inherit a tint), and
// short text is padded with trailing spaces to the full width. This is what
// keeps full-frame redraws exactly one line tall per row.
func TruncPad(s string, width int) string {
	if width <= 0 {
		return s
	}
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s) + 4)
	w := 0
	i := 0
	sawESC := false
	for i < len(runes) {
		if runes[i] == 0x1b {
			start := i
			i++
			for i < len(runes) && !('@' <= runes[i] && runes[i] <= '~') {
				i++
			}
			if i < len(runes) {
				i++ // final byte of the CSI/OSC sequence
			}
			b.WriteString(string(runes[start:i]))
			sawESC = true
			continue
		}
		if w >= width {
			break
		}
		b.WriteRune(runes[i])
		w++
		i++
	}
	if sawESC && i < len(runes) {
		b.WriteString(Reset) // truncation cut into live colour
	}
	for pad := width - w; pad > 0; pad-- {
		b.WriteByte(' ')
	}
	return b.String()
}

// TypeColor returns the ANSI hue a device type is rendered in, so a given kind
// is recognisable by colour in every table. Unknown kinds stay dim.
func TypeColor(typ string) string {
	t := strings.ToLower(typ)
	switch {
	case strings.Contains(t, "router"), strings.Contains(t, "gateway"):
		return Yellow
	case strings.Contains(t, "mobile"), strings.Contains(t, "phone"), strings.Contains(t, "tablet"):
		return Magenta
	case strings.Contains(t, "computer"), strings.Contains(t, "desktop"), strings.Contains(t, "laptop"),
		strings.Contains(t, "workstation"), strings.Contains(t, "server"), strings.Contains(t, "nas"):
		return Blue
	case strings.Contains(t, "printer"), strings.Contains(t, "scanner"):
		return Green
	case strings.Contains(t, "apple"), strings.Contains(t, "iphone"), strings.Contains(t, "mac"),
		strings.Contains(t, "ipad"), strings.Contains(t, "homepod"), strings.Contains(t, "airplay"):
		return Cyan
	case strings.Contains(t, "pi"), strings.Contains(t, "raspberry"), strings.Contains(t, "maker"):
		return Green
	case strings.Contains(t, "cast"), strings.Contains(t, "roku"), strings.Contains(t, "tv"),
		strings.Contains(t, "sound"), strings.Contains(t, "media"), strings.Contains(t, "iot"),
		strings.Contains(t, "cam"), strings.Contains(t, "echo"), strings.Contains(t, "speaker"):
		return Red
	case strings.Contains(t, "unknown"), strings.Contains(t, "device"):
		return Dim
	}
	return Dim
}

// DeviceIPCode picks the colour for a host's IP address in a device table:
// the machine running the scan gets its own bright hue, the gateway another
// (matches the G marker), and everything else follows its device type.
func DeviceIPCode(isSelf bool, typ string) string {
	if isSelf {
		return Header
	}
	if strings.Contains(strings.ToLower(typ), "router") ||
		strings.Contains(strings.ToLower(typ), "gateway") {
		return Target
	}
	return TypeColor(typ)
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

// HumanRate renders a byte count as a size-suffixed rate per second, e.g.
// "1.2KB/s" or "98B/s", shared by the monitor and traffic dashboards.
func HumanRate(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%dB/s", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB/s", float64(b)/1024)
	default:
		return fmt.Sprintf("%.1fMB/s", float64(b)/(1024*1024))
	}
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
