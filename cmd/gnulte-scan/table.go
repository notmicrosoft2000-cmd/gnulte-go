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

package main

import (
	"fmt"
	"strconv"
	"strings"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/ux"
)

// cdef describes one table column and how to render it.
type cdef struct {
	header string
	min    int
	get    func(r discover.Row) string
	color  func(r discover.Row, d string) string
}

func noColor(r discover.Row, d string) string { return d }

func dimc(r discover.Row, d string) string { return ux.C(ux.Dim, d) }

func statusValue(r discover.Row) string {
	switch {
	case r.IsSelf:
		return "S"
	case r.Type == "Router/Gateway":
		return "G"
	default:
		return "•"
	}
}

func statusColor(r discover.Row, d string) string {
	marker := strings.TrimSpace(strings.TrimLeft(d, "0123456789"))
	if len(marker) == 0 {
		return ux.C(ux.Green, d)
	}
	switch string([]rune(marker)[len([]rune(marker))-1]) {
	case "G":
		return ux.C(ux.Yellow, d)
	case "S":
		return ux.C(ux.Header, d)
	default:
		return ux.C(ux.Green, d)
	}
}

// ipColor tintes the address by what the device is: the running host and the
// gateway get their own hues, everything else follows its device type (so the
// shot of a phone is magenta, a computer blue, and so on).
func ipColor(r discover.Row, d string) string {
	return ux.C(ux.DeviceIPCode(r.IsSelf, r.Type), d)
}

// typeColor renders the type label in the same hue its address wears.
func typeColor(r discover.Row, d string) string {
	return ux.C(ux.TypeColor(d), d)
}

// hasColumn reports whether any row carries data for a field.
func hasColumn(rows []discover.Row, field int) bool {
	for _, r := range rows {
		switch field {
		case 0:
			if r.MAC != "" {
				return true
			}
		case 1:
			if r.Vendor != "" {
				return true
			}
		case 2:
			if r.Hostname != "" {
				return true
			}
		case 3:
			if r.Type != "" {
				return true
			}
		case 4:
			if r.Ports != "" {
				return true
			}
		case 5:
			if r.OS != "" {
				return true
			}
		}
	}
	return false
}

// renderTable prints a terminal-width-aware, colourised device table. The
// column widths shrink to fit the current window (narrowing the flexible
// columns first) and the same lines are recorded as plain text in the session
// log for the HTML report. Colours degrade automatically when piped.
func renderTable(s *session, rows []discover.Row, width int) {
	if len(rows) == 0 {
		msg := "  no devices found"
		s.pl(msg, msg)
		return
	}

	defs := []cdef{
		{"#", 3, statusValue, statusColor},
		{"IP", 9, func(r discover.Row) string { return r.IP }, ipColor},
	}
	if hasColumn(rows, 0) {
		defs = append(defs, cdef{"MAC", 12, func(r discover.Row) string { return r.MAC }, noColor})
	}
	if hasColumn(rows, 1) {
		defs = append(defs, cdef{"VENDOR", 8, func(r discover.Row) string { return r.Vendor }, dimc})
	}
	if hasColumn(rows, 2) {
		defs = append(defs, cdef{"HOSTNAME", 8, func(r discover.Row) string { return r.Hostname }, dimc})
	}
	if hasColumn(rows, 3) {
		defs = append(defs, cdef{"TYPE", 10, func(r discover.Row) string { return r.Type }, typeColor})
	}
	if hasColumn(rows, 4) {
		defs = append(defs, cdef{"PORTS", 10, func(r discover.Row) string { return r.Ports }, dimc})
	}
	if hasColumn(rows, 5) {
		defs = append(defs, cdef{"OS", 8, func(r discover.Row) string { return r.OS }, noColor})
	}

	// Natural widths from the longest cell (capped so one field cannot blow the
	// whole layout). The # column is fixed at the longest line number.
	widths := make([]int, len(defs))
	maxNum := 1
	if len(rows) >= 10 {
		maxNum = len(fmt.Sprintf("%d", len(rows)))
	}
	for i := range defs {
		if i == 0 {
			widths[i] = ux.Clamp(maxNum+1, defs[i].min, 4)
			continue
		}
		widths[i] = len([]rune(defs[i].header))
	}
	cells := make([][]string, len(rows))
	for ri, r := range rows {
		cells[ri] = make([]string, len(defs))
		for i, d := range defs {
			if i == 0 {
				cells[ri][0] = fmt.Sprintf("%-*s%s", maxNum, strconv.Itoa(ri+1), statusValue(r))
				continue
			}
			v := d.get(r)
			if n := len([]rune(v)); n > widths[i] {
				widths[i] = ux.Clamp(n, defs[i].min, 36)
			}
		}
	}

	// Shrink to fit: reduce the flexible columns until the table fits, then
	// reuse the released room for nothing — columns just get tighter.
	fitWidths(widths, defs, width)

	// Header.
	title := "  " + ux.C(ux.Header, "DEVICE LIST ") + ux.C(ux.Dim, strings.Repeat("─", ux.Clamp(width-14, 2, 64)))
	tPlain := "  DEVICE LIST " + strings.Repeat("─", ux.Clamp(width-14, 2, 64))
	s.pl(title, tPlain)
	hPlain := "  " + lkhdr(defs, widths)
	s.pl(hPlain, hPlain)
	s.pl(sepLine(defs, widths, width), sepLine(defs, widths, width))

	// Rows.
	for ri, r := range rows {
		var drow strings.Builder
		var prow strings.Builder
		for i, d := range defs {
			val := d.get(r)
			if i == 0 {
				val = fmt.Sprintf("%-*s%s", maxNum, strconv.Itoa(ri+1), statusValue(r))
			}
			val = ux.Trunc(val, widths[i])
			if i > 0 {
				drow.WriteString(" ")
				prow.WriteString(" ")
			} else {
				drow.WriteString("  ")
				prow.WriteString("  ")
			}
			drow.WriteString(d.color(r, padTo(val, widths[i])))
			prow.WriteString(padTo(val, widths[i]))
		}
		s.pl(drow.String(), prow.String())
	}
	s.pl(sepLine(defs, widths, width), sepLine(defs, widths, width))
	legend := "  " + ux.C(ux.Dim, "colours by device type · bright = this host · yellow = gateway")
	legPlain := "  colours by device type · bright = this host · yellow = gateway"
	s.pl(legend, legPlain)
	fmt.Fprintln(ux.Out)
}

func lkhdr(defs []cdef, widths []int) string {
	s := "  "
	for i, d := range defs {
		if i > 0 {
			s += " "
		} else {
			s += " "
		}
		s += padTo(d.header, widths[i])
	}
	return s
}

func padTo(v string, n int) string {
	r := []rune(v)
	if len(r) >= n {
		return v
	}
	return v + strings.Repeat(" ", n-len(r))
}

func sepLine(defs []cdef, widths []int, width int) string {
	total := 2
	for i, wd := range widths {
		if i > 0 {
			total++
		}
		total += wd
	}
	n := ux.Clamp(total, 8, width)
	return "  " + strings.Repeat("─", n)
}

// fitWidths shrinks flexible columns until the table fits the terminal width.
func fitWidths(widths []int, defs []cdef, width int) {
	// Flexible columns, most willing to give up space first.
	order := make([]int, 0, len(defs))
	for i := len(defs) - 1; i >= 1; i-- {
		order = append(order, i)
	}
	total := 2
	for i, wd := range widths {
		if i > 0 {
			total++
		}
		total += wd
	}
	for total > width && len(order) > 0 {
		shrunk := false
		var keep []int
		for _, i := range order {
			if widths[i] > defs[i].min {
				widths[i]--
				total--
				shrunk = true
				if widths[i] > defs[i].min {
					keep = append(keep, i)
				}
			}
		}
		order = keep
		if !shrunk {
			break
		}
	}
}
