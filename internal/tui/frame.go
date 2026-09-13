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

package tui

import (
	"io"
	"strings"

	"gnulte-go/internal/ux"
)

// DrawFrame repaints a whole frame at the top of the screen in a single write:
// it homes the cursor, writes every line padded to the terminal width, then
// clears the rows below the frame. Batching the entire redraw into one flush is
// what removes the per-line flashing a field-by-field rewrite causes.
func DrawFrame(w io.Writer, width int, lines []string) {
	var b strings.Builder
	total := 0
	for _, ln := range lines {
		total += len(ln) + 2
	}
	b.Grow(total)
	b.WriteString("\033[H")
	for _, ln := range lines {
		b.WriteString(ux.TruncPad(ln, width))
		b.WriteString("\r\n")
	}
	b.WriteString("\033[J")
	if w != nil {
		io.WriteString(w, b.String())
	}
}

// Frame returns the frame as a single string instead of writing it (used by
// tests and by tools that want to route the bytes somewhere unusual).
func Frame(width int, lines []string) string {
	var b strings.Builder
	DrawFrame(&b, width, lines)
	return b.String()
}
