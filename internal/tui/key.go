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

import "unicode/utf8"

// Key is a decoded single key press from the raw terminal stream.
type Key int

const (
	KeyNone Key = iota
	KeyEnter
	KeyEsc
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyTab
	KeySpace
	KeyBackspace
	KeyRune
)

// parseKey interprets as many leading bytes of p as one key press. It returns
// the key, the rune for KeyRune, the number of bytes consumed, and whether the
// sequence is waiting on more input (an ESC that may yet become an arrow).
func parseKey(p []byte) (key Key, r rune, n int, more bool) {
	if len(p) == 0 {
		return KeyNone, 0, 0, false
	}
	switch p[0] {
	case 0x1b:
		if len(p) == 1 {
			return KeyNone, 0, 0, true // could be an arrow still arriving
		}
		switch p[1] {
		case '[', 'O':
			if len(p) < 3 {
				return KeyNone, 0, 0, true
			}
			for i := 2; i < len(p); i++ {
				if p[i] >= 0x40 && p[i] <= 0x7e {
					switch p[i] {
					case 'A':
						return KeyUp, 0, i + 1, false
					case 'B':
						return KeyDown, 0, i + 1, false
					case 'C':
						return KeyRight, 0, i + 1, false
					case 'D':
						return KeyLeft, 0, i + 1, false
					case 'H':
						return KeyUp, 0, i + 1, false // Home => top
					case 'F':
						return KeyDown, 0, i + 1, false // End => bottom
					default:
						return KeyNone, 0, i + 1, false // unhandled CSI
					}
				}
			}
			return KeyNone, 0, 0, true
		default:
			return KeyEsc, 0, 1, false // lone ESC followed by something else
		}
	case '\r', '\n':
		return KeyEnter, 0, 1, false
	case '\t':
		return KeyTab, 0, 1, false
	case ' ':
		return KeySpace, 0, 1, false
	case 0x7f, 0x08:
		return KeyBackspace, 0, 1, false
	default:
		if p[0] < 0x20 {
			return KeyNone, 0, 1, false // unshadowed control bytes are ignored
		}
		rn, size := utf8.DecodeRune(p)
		if rn == utf8.RuneError && size == 1 {
			return KeyRune, rune(p[0]), 1, false
		}
		if size <= len(p) {
			return KeyRune, rn, size, false
		}
		return KeyRune, rune(p[0]), 1, false
	}
}
