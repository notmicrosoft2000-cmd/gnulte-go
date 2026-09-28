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
	"io"
	"time"
)

// Typeprint writes s to w as if a terminal were typing it: one rune at a time
// with a per-rune pause, flushed as it goes (pass an unbuffered writer such as
// os.Stdout). It degrades to an instant write when typed output is turned off
// or the destination is not a live terminal, so piped output stays parsed by
// machines instead of interleaved with animation pauses.
func Typeprint(w io.Writer, s string, per time.Duration) {
	if per <= 0 || !tty {
		io.WriteString(w, s)
		return
	}
	for _, r := range s {
		io.WriteString(w, string(r))
		time.Sleep(per)
	}
}
