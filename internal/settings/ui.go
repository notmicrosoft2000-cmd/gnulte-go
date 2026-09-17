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

package settings

import (
	"fmt"
	"strconv"
	"strings"

	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

// Edit opens the full-screen settings editor and returns the operator's
// version of the config. The new values are written to disk by the caller
// (Save). It fails with a descriptive error when no real terminal is present.
func Edit(c Config) (Config, error) {
	s, err := tui.Open()
	if err != nil {
		return c, err
	}
	defer s.Close()

	e := &editor{s: s, cfg: c}
	e.run()
	return e.cfg, nil
}

type editor struct {
	s     *tui.Screen
	cfg   Config
	items []editItem
	sel   int

	edit    bool
	buf     []rune
	liveErr string
}

type editItem struct {
	label string
	kind  int
	get   func(c Config) string
	set   func(c *Config, v string) error
}

const (
	itemStr = iota
	itemInt
	itemBool
)

func (e *editor) run() {
	e.items = []editItem{
		{"interface", itemStr, func(c Config) string { return orAuto(c.Interface) },
			func(c *Config, v string) error {
				if strings.TrimSpace(v) == "" {
					return fmt.Errorf("interface cannot be empty (leave a value, or 'auto')")
				}
				if v == "auto" {
					c.Interface = ""
					return nil
				}
				c.Interface = v
				return nil
			}},
		{"monitor/traffic interval (s)", itemInt, func(c Config) string { return fmt.Sprintf("%ds", c.IntervalSec) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("whole seconds, 1-60")
				}
				c.IntervalSec = clamp(n, 1, 60)
				return nil
			}},
		{"ping timeout (ms)", itemInt, func(c Config) string { return fmt.Sprintf("%dms", c.TimeoutMs) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a number of milliseconds, 100-60000")
				}
				c.TimeoutMs = clamp(n, 100, 60000)
				return nil
			}},
		{"ping beeps", itemBool, func(c Config) string { return boolText(c.Beeps) },
			func(c *Config, v string) error {
				switch strings.TrimSpace(strings.ToLower(v)) {
				case "on", "1", "yes", "true":
					c.Beeps = true
				case "off", "0", "no", "false":
					c.Beeps = false
				default:
					return fmt.Errorf("on or off")
				}
				return nil
			}},
		{"HTML report after test", itemBool, func(c Config) string { return boolText(c.HTMLReport) },
			func(c *Config, v string) error {
				switch strings.TrimSpace(strings.ToLower(v)) {
				case "on", "1", "yes", "true":
					c.HTMLReport = true
				case "off", "0", "no", "false":
					c.HTMLReport = false
				default:
					return fmt.Errorf("on or off")
				}
				return nil
			}},
		{"scan threads", itemInt, func(c Config) string { return fmt.Sprintf("%d", c.ScanThreads) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 1-512")
				}
				c.ScanThreads = clamp(n, 1, 512)
				return nil
			}},
		{"wifi frames per burst", itemInt, func(c Config) string { return fmt.Sprintf("%d", c.WifiCount) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 1-256")
				}
				c.WifiCount = clamp(n, 1, 256)
				return nil
			}},
		{"wifi delay between bursts (s)", itemInt, func(c Config) string { return fmt.Sprintf("%ds", c.WifiDelaySec) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("whole seconds, 1-60")
				}
				c.WifiDelaySec = clamp(n, 1, 60)
				return nil
			}},
		{"traffic window update (s)", itemInt, func(c Config) string { return fmt.Sprintf("%ds", c.TrafficSec) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("whole seconds, 1-10")
				}
				c.TrafficSec = clamp(n, 1, 10)
				return nil
			}},
		{"deep-scan retries per port", itemInt, func(c Config) string { return fmt.Sprintf("%d", c.ProbeRetries) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 1-5")
				}
				c.ProbeRetries = clamp(n, 1, 5)
				return nil
			}},
		{"OS guess confidence %", itemBool, func(c Config) string { return boolText(c.OSConfidence) },
			func(c *Config, v string) error {
				switch strings.TrimSpace(strings.ToLower(v)) {
				case "on", "1", "yes", "true":
					c.OSConfidence = true
				case "off", "0", "no", "false":
					c.OSConfidence = false
				default:
					return fmt.Errorf("on or off")
				}
				return nil
			}},
		{"uptime estimate (TCP timestamps)", itemBool, func(c Config) string { return boolText(c.UptimeGuess) },
			func(c *Config, v string) error {
				switch strings.TrimSpace(strings.ToLower(v)) {
				case "on", "1", "yes", "true":
					c.UptimeGuess = true
				case "off", "0", "no", "false":
					c.UptimeGuess = false
				default:
					return fmt.Errorf("on or off")
				}
				return nil
			}},
		{"flag ICMP-alive hosts w/o ARP", itemBool, func(c Config) string { return boolText(c.RogueFlag) },
			func(c *Config, v string) error {
				switch strings.TrimSpace(strings.ToLower(v)) {
				case "on", "1", "yes", "true":
					c.RogueFlag = true
				case "off", "0", "no", "false":
					c.RogueFlag = false
				default:
					return fmt.Errorf("on or off")
				}
				return nil
			}},
	}

	for {
		e.draw()
		key, r := e.s.Key()
		if e.edit {
			e.handleEdit(key, r)
			continue
		}
		switch key {
		case tui.KeyUp:
			e.sel = (e.sel + len(e.items) - 1) % len(e.items)
		case tui.KeyDown:
			e.sel = (e.sel + 1) % len(e.items)
		case tui.KeyEsc:
			return
		case tui.KeyEnter, tui.KeySpace:
			it := e.items[e.sel]
			if it.kind == itemBool {
				_ = it.set(&e.cfg, boolText(!e.boolVal(e.sel)))
			} else {
				e.edit = true
				e.buf = nil // typing replaces the value from scratch
				e.liveErr = ""
			}
		}
	}
}

func (e *editor) boolVal(i int) bool { return e.items[i].get(e.cfg) == "on" }

// handleEdit processes keys while typing a text/number value.
func (e *editor) handleEdit(key tui.Key, r rune) {
	switch key {
	case tui.KeyEsc:
		e.edit = false
	case tui.KeyEnter:
		it := e.items[e.sel]
		if err := it.set(&e.cfg, string(e.buf)); err != nil {
			e.liveErr = err.Error()
			return
		}
		e.edit = false
	case tui.KeyBackspace:
		if len(e.buf) > 0 {
			e.buf = e.buf[:len(e.buf)-1]
		}
	case tui.KeyRune:
		if r >= 0x20 {
			if len(e.buf) < 64 {
				e.buf = append(e.buf, r)
			}
		}
	}
}

func orAuto(s string) string {
	if s == "" {
		return "auto"
	}
	return s
}

func boolText(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// draw renders the whole settings screen in one flicker-free flush.
func (e *editor) draw() {
	width := ux.Width()
	inner := width - 4
	if inner > 72 {
		inner = 72
	}
	n := len(e.items)
	lines := make([]string, 0, n+5)
	title := " GNULTE settings "
	lines = append(lines, "  ┌─"+title+strings.Repeat("─", max0(inner-len(title)-2))+"┐")
	for i, it := range e.items {
		label := it.label
		value := it.get(e.cfg)
		if e.edit && i == e.sel {
			value = string(e.buf) + "_"
		}
		body := "  │ " + label + ":" + strings.Repeat(" ", max0(inner-len(label)-len(value)-3)) + value + " │"
		if i == e.sel {
			body = ux.C(ux.Bold, body)
		}
		lines = append(lines, body)
	}
	lines = append(lines, "  └"+strings.Repeat("─", inner)+"┘")
	foot := "  ↑/↓ move · Enter edit or toggle · Esc save & exit"
	if e.edit {
		foot = "  entering a value… Enter accept · Esc cancel"
		if e.liveErr != "" {
			foot = "  " + ux.C(ux.Red, e.liveErr) + " — Enter accept · Esc cancel"
		}
	}
	lines = append(lines, foot)
	e.s.Draw(lines)
}

func max0(v int) int {
	if v < 1 {
		return 1
	}
	return v
}
