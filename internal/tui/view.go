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
	"os"

	"gnulte-go/internal/ux"
)

// EnterView swaps the terminal onto its alternate buffer, where a dashboard
// can redraw in place without scrolling the scrollback or flashing the shell
// prompt. The returned function restores the primary buffer; ok is false when
// the output is not a live terminal (piped runs fall back to plain lines).
func EnterView() (cleanup func(), ok bool) {
	if !ux.TTY() {
		return func() {}, false
	}
	os.Stdout.WriteString("\033[?1049h")
	return func() { os.Stdout.WriteString("\033[?1049l") }, true
}
