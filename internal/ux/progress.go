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
	"fmt"
	"strings"
)

// spinnerFrames drive the animated glyph at the left of the bar/busy line.
var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// Check is the shared completion glyph.
const Check = "✓"

// Busy renders an indeterminate spinner on a single replaced line. When the
// output is piped it prints nothing until Done, keeping logs clean.
type Busy struct {
	label string
	tick  int
	tty   bool
}

// NewBusy starts an indeterminate spinner line for label.
func NewBusy(label string) *Busy {
	b := &Busy{label: label, tty: tty}
	if b.tty {
		fmt.Fprintf(Out, "\r  %c %s …", spinnerFrames[0], b.fit(0))
	}
	return b
}

// Spin advances the animation by one frame.
func (b *Busy) Spin() {
	if !b.tty {
		return
	}
	b.tick = (b.tick + 1) % len(spinnerFrames)
	fmt.Fprintf(Out, "\r  %c %s …", spinnerFrames[b.tick], b.fit(0))
}

// fit trims the label so the spinner line never wraps the terminal width.
func (b *Busy) fit(frame int) string {
	usable := Width() - 2 - 8 // spinner + spaces + ellipsis
	return Trunc(b.label, usable)
}

// Done clears the spinner and leaves a completion line behind.
func (b *Busy) Done(msg string) {
	if b.tty {
		fmt.Fprintf(Out, "\r  %s %s\n", C(Green, Check), msg)
		return
	}
	fmt.Fprintf(Out, "  [✓] %s\n", msg)
}

// Bar is a width-aware progress bar with a spinner and a running live-host
// count. The bar length adapts to the terminal width at every draw.
type Bar struct {
	label string
	total int
	tick  int
	tty   bool
	done  bool
}

// NewBar creates a progress bar for total items. Nothing is printed until the
// first Update or Finish, so piped output is not polluted with redraws.
func NewBar(label string, total int) *Bar {
	return &Bar{label: label, total: total, tty: tty}
}

// fit returns the label to show and the bar length, sizing both to the current
// terminal width so the whole line stays visible (the label gets ellipsized
// before the bar is shrunk below a readable width).
func (b *Bar) fit() (string, int) {
	usable := Width() - 2 // outer margin
	reserve := 30         // spinner + pads + counts + live suffix
	barW := usable - len([]rune(b.label)) - reserve
	if barW >= 4 {
		return b.label, Clamp(barW, 4, 32)
	}
	return Trunc(b.label, Max(usable-reserve-4, 8)), 4
}

// Max returns the larger of a and b.
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// render builds the fill for the current width and fraction.
func (b *Bar) render(done int) string {
	_, fw := b.fit()
	frac := 0
	if b.total > 0 {
		frac = done * fw / b.total
		if frac > fw {
			frac = fw
		}
	}
	var sb strings.Builder
	sb.Grow(fw)
	for i := 0; i < fw; i++ {
		if i < frac {
			sb.WriteString("█")
		} else {
			sb.WriteString("░")
		}
	}
	return sb.String()
}

// Update redraws the bar with the current completed/live counts.
func (b *Bar) Update(done, alive int) {
	if !b.tty {
		return
	}
	b.tick = (b.tick + 1) % len(spinnerFrames)
	label, _ := b.fit()
	fmt.Fprintf(Out, "\r  %c %s  [%s] %d/%d · %d live",
		spinnerFrames[b.tick], label, b.render(done), done, b.total, alive)
}

// Finish resolves the bar into a final check-mark line (or a single plain line
// when piped) and moves to the next console line.
func (b *Bar) Finish(done, alive int) {
	if b.done {
		return
	}
	b.done = true
	label, _ := b.fit()
	if !b.tty {
		fmt.Fprintf(Out, "  [✓] %s — %d/%d probed · %d live\n", label, done, b.total, alive)
		return
	}
	fmt.Fprintf(Out, "\r  %s %s  [%s] %d/%d · %d live\n",
		C(Green, Check), label, C(Green, b.render(done)), done, b.total, alive)
}
