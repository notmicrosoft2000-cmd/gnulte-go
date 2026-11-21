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
	"fmt"
	"os"
	"strconv"
	"strings"

	"gnulte-go/internal/ux"
)

// MenuItem is one choice in a simple picker. Label is the plain-language
// action; Detail is an optional one-line explanation shown beside it.
type MenuItem struct {
	Label  string
	Detail string
}

// MenuOptions adds contextual copy to a picker without changing the key
// bindings. Context lines appear between the title rule and the list, Note is
// a single line below it, and Footer replaces the default key hint. Selected
// is the initially highlighted row (zero by default), so a launcher can
// preselect a saved choice without reordering the labels.
type MenuOptions struct {
	Context  []string
	Note     string
	Footer   string
	Selected int
}

const defaultMenuFooter = "↑/↓ choose   Enter run   number jump   q quit"

// MenuFrameWith lays out a picker with contextual copy for a full-frame
// redraw. The selected row gets the arrow marker; every other row is indented
// the same amount so the list does not jump when the selection moves.
func MenuFrameWith(title string, items []MenuItem, sel int, opts MenuOptions) []string {
	footer := opts.Footer
	if footer == "" {
		footer = defaultMenuFooter
	}
	lines := []string{
		"  " + title,
		"  " + strings.Repeat("─", 52),
	}
	for _, line := range opts.Context {
		lines = append(lines, "  "+line)
	}
	lines = append(lines, "")
	for i, item := range items {
		mark := "  "
		if i == sel {
			mark = "▸ "
		}
		row := fmt.Sprintf("  %s%d  %-28s", mark, i+1, item.Label)
		if item.Detail != "" {
			row += "  " + item.Detail
		}
		lines = append(lines, row)
	}
	lines = append(lines, "")
	if opts.Note != "" {
		lines = append(lines, "  "+opts.Note)
	}
	return append(lines, "  "+footer, "")
}

// MenuFrame lays out a picker for a full-frame redraw. The selected row gets
// the arrow marker; every other row is indented the same amount so the list
// does not jump when the selection moves.
func MenuFrame(title string, items []MenuItem, sel int) []string {
	return MenuFrameWith(title, items, sel, MenuOptions{})
}

// Menu asks the operator to pick one item. On a live terminal it opens the
// alternate screen and takes arrow keys, j/k, digits or Enter. When either
// stream is piped it falls back to a numbered prompt, so scripts and the test
// suite can drive the same choices without a PTY. It returns the item index
// and whether a choice was made.
func Menu(title string, items []MenuItem) (int, bool) {
	return MenuWith(title, items, MenuOptions{})
}

// MenuWith is Menu with contextual copy, a custom footer and an optional
// preselected row. The keys and the piped-input fallback are identical.
func MenuWith(title string, items []MenuItem, opts MenuOptions) (int, bool) {
	if len(items) == 0 {
		return -1, false
	}
	if StdinTTY() && ux.TTY() {
		if screen, err := Open(); err == nil {
			defer screen.Close()
			sel := opts.Selected
			if sel < 0 || sel >= len(items) {
				sel = 0
			}
			for {
				screen.Draw(MenuFrameWith(title, items, sel, opts))
				key, r := screen.Key()
				switch {
				case key == KeyUp || key == KeyRune && (r == 'k' || r == 'K'):
					sel = (sel + len(items) - 1) % len(items)
				case key == KeyDown || key == KeyRune && (r == 'j' || r == 'J'):
					sel = (sel + 1) % len(items)
				case key == KeyEnter:
					return sel, true
				case key == KeyEsc || key == KeyRune && (r == 'q' || r == 'Q'):
					return -1, false
				case key == KeyRune && r >= '1' && r <= '9':
					if n := int(r - '1'); n < len(items) {
						return n, true
					}
				}
			}
		}
	}
	// Non-TTY callers still see the context and note before the numbered
	// prompt; plainMenu keeps the long-standing answer/EOF behaviour.
	for _, line := range opts.Context {
		fmt.Println("  " + line)
	}
	if opts.Note != "" {
		fmt.Println("  " + opts.Note)
	}
	return plainMenu(title, items)
}

func plainMenu(title string, items []MenuItem) (int, bool) {
	fmt.Println()
	fmt.Println("  " + title)
	for i, item := range items {
		fmt.Printf("  %d) %s", i+1, item.Label)
		if item.Detail != "" {
			fmt.Printf(" — %s", item.Detail)
		}
		fmt.Println()
	}
	for {
		fmt.Print("  Choose a number (q to quit): ")
		var answer string
		if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
			return -1, false
		}
		if n, ok := ParseMenuChoice(answer, len(items)); ok {
			return n, true
		}
		if strings.EqualFold(answer, "q") || strings.EqualFold(answer, "quit") {
			return -1, false
		}
		fmt.Println("  Please type a number from the list, or q.")
	}
}

// ParseMenuChoice turns a typed answer into a zero-based item index. It is
// exported so launcher tests can check the plain-menu contract directly.
func ParseMenuChoice(answer string, count int) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || n < 1 || n > count {
		return -1, false
	}
	return n - 1, true
}
