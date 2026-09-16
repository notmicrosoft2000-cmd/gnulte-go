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
	"sort"
	"strings"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

// The optional interactive device list (-T): a full-screen, filterable and
// sortable table over the same rows the plain table prints. It only runs on a
// live terminal; piped/export runs keep the classic output. Off the alternate
// screen it leaves a snapshot of the filtered rows in the session log so the
// HTML report still shows what the operator saw.

// tvRow carries the fields a table cell may need, decoded once per redraw so
// sorting and filtering touch plain Go values instead of re-splitting strings.
type tvRow struct {
	r    discover.Row
	ip   string
	mac  string
	host string
	typ  string
}

// sortField labels a column for sorting; index 0 matches the "#" column.
const (
	sortIP = iota + 1
	sortMAC
	sortVendor
	sortHostname
	sortType
)

// tvSort keys a row by the current sort field.
func (t tvRow) sortKey(field int) string {
	switch field {
	case sortMAC:
		return t.mac
	case sortVendor:
		return t.r.Vendor
	case sortHostname:
		return t.host
	case sortType:
		return t.typ
	default:
		return t.ip
	}
}

// interactiveTable runs the full-screen device table until the operator quits.
// It returns the rows in the final display order so the caller can reuse them
// for the report snapshot. terminate reports whether the user quit by 'q'
// (making the caller skip the plain table too).
func interactiveTable(rows []discover.Row) (final []discover.Row, quit bool) {
	scr, err := tui.Open()
	if err != nil {
		// Not a live terminal: fall back to the classic table.
		return rows, false
	}
	defer scr.Close()

	t := &tvTable{rows: rows, sortBy: sortIP, detail: -1}
	t.build()
	for {
		t.draw(scr)
		key, r := scr.Key()
		if t.filterEdit {
			if t.handleFilterKey(key, r) {
				continue
			}
		}
		if key == tui.KeyEnter {
			if t.detail >= 0 {
				t.detail = -1
			} else {
				t.detail = t.cursor
			}
			continue
		}
		if t.detail >= 0 {
			switch key {
			case tui.KeyUp:
				if t.detailOff > 0 {
					t.detailOff--
				}
			case tui.KeyDown:
				t.detailOff++
			case tui.KeyEsc:
				t.detail = -1
			case tui.KeyRune:
				if r == 'q' {
					return t.finalRows(), true
				}
			}
			continue
		}
		switch key {
		case tui.KeyUp:
			if t.cursor > 0 {
				t.cursor--
			}
		case tui.KeyDown:
			if t.cursor+1 < len(t.view) {
				t.cursor++
			}
		case tui.KeySpace:
			if len(t.view) > 0 {
				t.detail = t.cursor
			}
		case tui.KeyTab, tui.KeyRight:
			t.cycleSort(1)
		case tui.KeyLeft:
			t.cycleSort(-1)
		case tui.KeyEsc:
			return t.finalRows(), true
		case tui.KeyRune:
			switch r {
			case 'q':
				return t.finalRows(), true
			case 's':
				t.cycleSort(1)
			case 'S':
				t.desc = !t.desc
				t.build()
			case '/':
				t.filterEdit = true
				t.filter = nil
			}
		}
	}
}

// cycleSort moves the active sort column in dir steps (wrapping) and rebuilds.
func (t *tvTable) cycleSort(dir int) {
	fields := []int{sortIP, sortType, sortVendor, sortHostname, sortMAC}
	for i, f := range fields {
		if f == t.sortBy {
			t.sortBy = fields[(i+dir+len(fields))%len(fields)]
			break
		}
	}
	t.build()
}

// handleFilterKey processes keys while the filter line is being typed. It
// reports whether the key was consumed by the filter editor (so the caller
// does not also treat it as a table command, e.g. Enter applying the filter
// must not then toggle the detail pane).
func (t *tvTable) handleFilterKey(key tui.Key, r rune) bool {
	switch key {
	case tui.KeyEsc:
		t.filterEdit = false
		t.filter = nil
		t.build()
		t.cursor = 0
		return true
	case tui.KeyEnter:
		t.filterEdit = false
		t.build()
		return true
	case tui.KeyBackspace:
		if len(t.filter) > 0 {
			t.filter = t.filter[:len(t.filter)-1]
			t.build()
		}
		return true
	case tui.KeySpace:
		t.filter = append(t.filter, ' ')
		t.build()
		return true
	case tui.KeyRune:
		if r >= 0x20 {
			t.filter = append(t.filter, r)
			t.build()
			return true
		}
		return false
	default:
		return false
	}
}

// tvTable is the interactive table state.
type tvTable struct {
	rows   []discover.Row
	view   []tvRow
	cursor int
	detail int // index into view being inspected, or -1
	sortBy int
	desc   bool
	filter []rune
	// detailOff scrolls the detail pane when its content exceeds the screen.
	detailOff  int
	filterEdit bool
}

// build applies the filter, sorts the view, and clamps the cursor.
func (t *tvTable) build() {
	v := make([]tvRow, 0, len(t.rows))
	q := strings.ToLower(string(t.filter))
	for _, r := range t.rows {
		row := tvRow{r: r, ip: r.IP, mac: r.MAC, host: r.Hostname, typ: r.Type}
		if q == "" || row.matches(q) {
			v = append(v, row)
		}
	}
	sort.SliceStable(v, func(a, b int) bool {
		var less bool
		if t.sortBy == sortIP {
			less = ipLess(v[a].ip, v[b].ip)
		} else {
			less = v[a].sortKey(t.sortBy) < v[b].sortKey(t.sortBy)
		}
		if t.desc {
			return !less
		}
		return less
	})
	t.view = v
	if t.cursor >= len(v) {
		t.cursor = 0
	}
	if t.detail >= len(v) {
		t.detail = -1
	}
}

// matches reports whether a row satisfies the filter term (case-insensitive).
func (r tvRow) matches(q string) bool {
	raw := r.r
	hay := strings.ToLower(raw.IP + " " + raw.MAC + " " + raw.Vendor + " " + raw.Hostname + " " + raw.Type + " " + raw.OS)
	return strings.Contains(hay, strings.ToLower(q))
}

// ipLess orders two IPv4 strings as numbers, so 192.168.1.2 precedes
// 192.168.1.10 (byte-wise string order would not).
func ipLess(a, b string) bool {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		na, nb := 0, 0
		fmt.Sscanf(aa[i], "%d", &na)
		fmt.Sscanf(bb[i], "%d", &nb)
		if na != nb {
			return na < nb
		}
	}
	return len(aa) < len(bb)
}

// finalRows returns the display-ordered rows (post-filter, post-sort).
func (t *tvTable) finalRows() []discover.Row {
	out := make([]discover.Row, 0, len(t.view))
	for _, v := range t.view {
		out = append(out, v.r)
	}
	return out
}

// draw renders one frame (table or detail) in a single flush.
func (t *tvTable) draw(scr *tui.Screen) {
	if t.detail >= 0 && t.detail < len(t.view) {
		scr.Draw(t.detailLines(t.view[t.detail].r))
		return
	}
	sortName := []string{"", "IP", "MAC", "vendor", "hostname", "type"}[t.sortBy]
	dir := "asc"
	if t.desc {
		dir = "desc"
	}
	status := fmt.Sprintf("sort %s (%s) · %d/%d shown · colour = type · ↑↓ move · ⏎ details · / filter · s sort · q quit",
		sortName, dir, len(t.view), len(t.rows))
	if t.filterEdit {
		status = "filter: " + string(t.filter) + "▌   (⏎ apply · esc clear)"
	}
	scr.Draw(t.tableLines(status))
}

// cell renders one truncated, coloured field at a fixed width.
func cell(code, s string, w int) string {
	return ux.TruncPad(ux.C(code, s), w)
}

// plainCell renders a plain truncated field at a fixed width.
func plainCell(s string, w int) string {
	return ux.TruncPad(s, w)
}

// twCols divvies the terminal width between the interactive columns. Cells are
// always separated by one gutter space so an exact-fit value never collides
// with the next column, and the PORTS column absorbs whatever is left.
func twCols(width int) (wIp, wMac, wVen, wHost, wTyp, wOs, loose int) {
	wIp, wMac = 15, 17
	wVen, wHost, wTyp, wOs = 20, 14, 14, 14
	if width < 90 {
		wIp, wMac = 14, 15
	}
	seps := 7
	fix := 4 + wIp + wMac + wVen + wHost + wTyp + wOs + seps
	loose = width - fix
	if loose < 8 {
		wVen, wHost, wTyp, wOs = 14, 10, 10, 10
		fix = 4 + wIp + wMac + wVen + wHost + wTyp + wOs + seps
		loose = width - fix
	}
	if loose < 6 {
		loose = 6
	}
	return
}

// twHeader renders the interactive header line.
func twHeader(wIp, wMac, wVen, wHost, wTyp, wOs, loose int) string {
	s := " "
	return cell(ux.Header, "#", 4) + s + cell(ux.Header, "IP", wIp) + s +
		cell(ux.Header, "MAC", wMac) + s + cell(ux.Header, "VENDOR", wVen) + s +
		cell(ux.Header, "HOSTNAME", wHost) + s + cell(ux.Header, "TYPE", wTyp) + s +
		cell(ux.Header, "OS", wOs) + s + cell(ux.Header, "PORTS", loose)
}

// tableLines renders the interactive frame the operator sees.
func (t *tvTable) tableLines(status string) []string {
	width := ux.Width()
	height := ux.Height()
	wIp, wMac, wVen, wHost, wTyp, wOs, loose := twCols(width)
	hdr := twHeader(wIp, wMac, wVen, wHost, wTyp, wOs, loose)

	// Visible window: header row, n rows, separators, status line.
	maxRows := height - 4
	if maxRows < 3 {
		maxRows = 3
	}
	lines := make([]string, 0, maxRows+4)
	lines = append(lines, ux.TruncPad(ux.C(ux.Dim, status), width))
	lines = append(lines, ux.TruncPad(ux.C(ux.Dim, strings.Repeat("─", width-2)), width))
	lines = append(lines, hdr)

	top := t.cursor - maxRows/2
	if top < 0 {
		top = 0
	}
	bottom := top + maxRows
	if bottom > len(t.view) {
		bottom = len(t.view)
		top = bottom - maxRows
		if top < 0 {
			top = 0
		}
	}
	for i := top; i < bottom; i++ {
		v := t.view[i]
		sel := i == t.cursor
		line := t.rowLine(v, wIp, wMac, wVen, wHost, wTyp, wOs, loose, sel)
		if sel {
			line = ux.Invert(line)
		}
		lines = append(lines, ux.TruncPad(line, width))
	}
	// Fill trailing rows so the detail/status bars stay at the bottom.
	for len(lines) < height {
		lines = append(lines, " ")
	}
	return lines
}

// rowLine colours the seven data columns like the plain table does.
func (t *tvTable) rowLine(v tvRow, wIp, wMac, wVen, wHost, wTyp, wOs, loose int, sel bool) string {
	// Selection inverts the row, so dim-on-inverse would read poorly; nudge
	// vendor/hostname/os to plain when selected.
	dim := ux.Dim
	if sel {
		dim = ""
	}
	s := " "
	num := fmt.Sprintf("%-3d%s", t.index(v)+1, statusMark(v.r))
	return cell(ux.Green, num, 4) + s +
		cell(ux.DeviceIPCode(v.r.IsSelf, v.typ), v.ip, wIp) + s +
		cell(dim, v.mac, wMac) + s +
		cell(dim, v.r.Vendor, wVen) + s +
		cell(dim, v.host, wHost) + s +
		cell(ux.TypeColor(v.typ), ux.Trunc(v.typ, wTyp), wTyp) + s +
		cell(dim, ux.Trunc(v.r.OS, wOs), wOs) + s +
		cell(dim, ux.Trunc(v.r.Ports, loose), loose)
}

// index locates v within the current view (displayed numbering).
func (t *tvTable) index(v tvRow) int {
	for i := range t.view {
		if t.view[i].r.IP == v.r.IP && t.view[i].r.MAC == v.r.MAC {
			return i
		}
	}
	return 0
}

// detailLines renders the full detail of one device.
func (t *tvTable) detailLines(r discover.Row) []string {
	width := ux.Width()
	height := ux.Height()
	label := func(k, v string) string {
		if v == "" {
			v = "—"
		}
		return ux.TruncPad(ux.C(ux.Dim, k)+ux.TruncPad(v, width-len(k)-2), width)
	}
	var lines []string
	add := func(s string) {
		lines = append(lines, ux.TruncPad(s, width))
	}
	add(ux.TruncPad(ux.C(ux.Header, "DEVICE "+r.IP+" ")+ux.C(ux.Dim, "  esc return · q quit"), width))
	add("")
	add(label("ip        ", ux.C(ux.DeviceIPCode(r.IsSelf, r.Type), r.IP)))
	add(label("mac       ", r.MAC))
	add(label("vendor    ", r.Vendor))
	add(label("hostname  ", r.Hostname))
	add(label("type      ", ux.C(ux.TypeColor(r.Type), r.Type)))
	add(label("os guess  ", r.OS))
	add(label("scan note ", r.ScanNote))
	add("")
	add(ux.TruncPad(ux.C(ux.Dim, "ports"), width))
	for _, l := range wrapText(ux.C(ux.Dim, r.Ports), width-4) {
		add("  " + l)
	}
	if len(r.Banners) > 0 {
		add("")
		add(ux.TruncPad(ux.C(ux.Dim, "banners"), width))
		for _, b := range r.Banners {
			for _, l := range wrapText(ux.C(ux.Cyan, b), width-4) {
				add("  " + l)
			}
		}
	}
	// Scroll if the content runs past the screen.
	n := len(lines)
	if n > height && t.detailOff > 0 {
		lines = lines[t.detailOff:]
		n = len(lines)
	}
	if n > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, " ")
	}
	return lines
}

// wrapText splits s at whitespace to fit width, keeping ANSI intact per line.
func wrapText(s string, width int) []string {
	if width < 4 {
		width = 4
	}
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		var cur []string
		cw := 0
		for _, tok := range strings.Fields(ln) {
			extra := ux.RuneLen(ux.StripAnsi(tok))
			if cw > 0 && cw+extra+1 > width {
				out = append(out, strings.Join(cur, " "))
				cur = nil
				cw = 0
			}
			cur = append(cur, tok)
			cw += extra
			if cw > 0 {
				cw++
			}
		}
		if len(cur) > 0 {
			out = append(out, strings.Join(cur, " "))
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// statusMark reuses the plain table's S/G/• convention.
func statusMark(r discover.Row) string {
	switch {
	case r.IsSelf:
		return "S"
	case r.OS == "Router/Gateway" || r.Type == "Router/Gateway":
		return "G"
	default:
		return "•"
	}
}

// rawTableLines renders a plain, parseable device list snapshot for the HTML
// report log after the interactive session ends (no ANSI, no layout tricks).
func rawTableLines(rows []discover.Row) []string {
	width := ux.Width()
	if width < 60 {
		width = 80
	}
	wIp, wMac, wVen, wHost, wTyp, wOs, loose := twCols(width)
	s := " "
	head := plainCell("#", 4) + s + plainCell("IP", wIp) + s + plainCell("MAC", wMac) + s +
		plainCell("VENDOR", wVen) + s + plainCell("HOSTNAME", wHost) + s + plainCell("TYPE", wTyp) + s +
		plainCell("OS", wOs) + s + plainCell("PORTS", loose)
	out := make([]string, 0, len(rows)+4)
	out = append(out, "  DEVICE LIST "+strings.Repeat("─", ux.Clamp(width-14, 2, 64)))
	out = append(out, "  "+head)
	out = append(out, "  "+strings.Repeat("─", ux.Clamp(width-2, 8, 64)))
	for i, r := range rows {
		num := fmt.Sprintf("%d%s", i+1, statusMark(r))
		out = append(out, "  "+plainCell(num, 4)+s+plainCell(r.IP, wIp)+s+plainCell(r.MAC, wMac)+s+
			plainCell(r.Vendor, wVen)+s+plainCell(r.Hostname, wHost)+s+plainCell(r.Type, wTyp)+s+
			plainCell(r.OS, wOs)+s+plainCell(r.Ports, loose))
	}
	out = append(out, "  "+strings.Repeat("─", ux.Clamp(width-2, 8, 64)))
	return out
}
