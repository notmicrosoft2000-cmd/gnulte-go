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
	"strings"
	"sync"
)

// Capture is a writer that builds a clean, HTML-safe transcript of a console
// session. Lines that only carry a redraw (\r-prefixed progress frames) are
// dropped so the log keeps only the permanent output.
type Capture struct {
	mu    sync.Mutex
	lines []string
	buf   strings.Builder
}

// NewCapture returns an empty transcript capture.
func NewCapture() *Capture { return &Capture{} }

// Write accumulates console bytes and splits them into lines on the fly.
func (c *Capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			raw := c.buf.String()
			c.buf.Reset()
			// Redraw frames (\r-prefixed progress bars) and blank lines are
			// transient screen state, not history.
			if raw == "" || strings.HasPrefix(raw, "\r") {
				continue
			}
			c.lines = append(c.lines, StripAnsi(strings.TrimSpace(raw)))
			continue
		}
		c.buf.WriteByte(b)
	}
	return len(p), nil
}

// Lines returns the captured transcript (complete lines only).
func (c *Capture) Lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// StripAnsi removes ANSI/OSC escape sequences from s.
func StripAnsi(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' {
			// Skip the ESC and its parameter/final bytes of a CSI sequence
			// (\x1b[ ... final) or an OSC sequence (\x1b] ... BEL).
			i++
			if i < len(s) && s[i] == '[' {
				i++
				for i < len(s) {
					c := s[i]
					i++
					if c >= '@' && c <= '~' {
						break
					}
				}
				continue
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
