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
	top   int // first visible item (scroll window)

	edit    bool
	buf     []rune
	liveErr string
}

// editItem is one editor row: a label, a kind, a getter/setter pair, a
// human help line, and the factory-default display value used by the reset key.
// head rows are non-editable category separators (rendered dim, skipped by the
// arrow keys) that keep the growing option list browsable.
type editItem struct {
	label string
	kind  int
	head  bool
	get   func(c Config) string
	set   func(c *Config, v string) error
	help  string
	def   string
}

const (
	itemStr = iota
	itemInt
	itemBool
	itemHead
)

// run builds the categorized item list and drives the edit loop.
func (e *editor) run() {
	row := func(label string, kind int, get func(c Config) string, set func(c *Config, v string) error, help, def string) editItem {
		return editItem{label: label, kind: kind, get: get, set: set, help: help, def: def}
	}
	head := func(label string) editItem {
		return editItem{label: label, kind: itemHead, head: true}
	}

	e.items = append(e.items,
		head("NETWORK & MONITOR"),
		row("interface", itemStr,
			func(c Config) string { return orAuto(c.Interface) },
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
			},
			"network interface used by monitor/traffic; 'auto' detects the default route", "auto"),
		row("HTML report after test", itemBool,
			func(c Config) string { return boolText(c.HTMLReport) },
			func(c *Config, v string) error { return setBool(&c.HTMLReport, v) },
			"write the post-test HTML report to the report hub", boolText(true)),
		row("ping beeps", itemBool,
			func(c Config) string { return boolText(c.Beeps) },
			func(c *Config, v string) error { return setBool(&c.Beeps, v) },
			"pitch the ping latency as beeps in gnulte's monitor", boolText(true)),
		row("monitor/traffic interval (s)", itemInt,
			func(c Config) string { return fmt.Sprintf("%ds", c.IntervalSec) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("whole seconds, 1-60")
				}
				c.IntervalSec = clamp(n, 1, 60)
				return nil
			},
			"seconds between monitor and traffic window refreshes (1-60)", "1s"),
		row("ping timeout (ms)", itemInt,
			func(c Config) string { return fmt.Sprintf("%dms", c.TimeoutMs) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a number of milliseconds, 100-60000")
				}
				c.TimeoutMs = clamp(n, 100, 60000)
				return nil
			},
			"per-ping timeout; raise it for slow or degraded links (100-60000)", "1000ms"),
		row("ping history depth", itemInt,
			func(c Config) string { return fmt.Sprintf("%d", c.History) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 10-240")
				}
				c.History = clamp(n, 10, 240)
				return nil
			},
			"how many ping samples each monitor keeps per target — the latency history sparkline (10-240)", "60"),
		row("traffic window update (s)", itemInt,
			func(c Config) string { return fmt.Sprintf("%ds", c.TrafficSec) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("whole seconds, 1-10")
				}
				c.TrafficSec = clamp(n, 1, 10)
				return nil
			},
			"refresh interval for the GNULTE-LAN watch window (1-10)", "1s"),
		row("lan alarm rate (kbps)", itemInt,
			func(c Config) string { return orOff(fmt.Sprintf("%dkbps", c.AlarmRateKbps)) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("kilobits per second, 0-1000000 (0 = off)")
				}
				c.AlarmRateKbps = clamp(n, 0, 1000000)
				return nil
			},
			"GNULTE-LAN: mark any host whose down/up speed exceeds this (0 = off)", "0"),
		row("lan alarm latency (ms)", itemInt,
			func(c Config) string { return orOff(fmt.Sprintf("%dms", c.AlarmLatencyMs)) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("milliseconds, 0-60000 (0 = off)")
				}
				c.AlarmLatencyMs = clamp(n, 0, 60000)
				return nil
			},
			"GNULTE-LAN: mark any host whose average ping exceeds this (0 = off)", "0"),
		head("SCANLTE SCAN"),
		row("scan threads", itemInt,
			func(c Config) string { return fmt.Sprintf("%d", c.ScanThreads) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 1-512")
				}
				c.ScanThreads = clamp(n, 1, 512)
				return nil
			},
			"parallel workers for the live-host ping sweep (1-512)", "64"),
		row("deep-scan retries per port", itemInt,
			func(c Config) string { return fmt.Sprintf("%d", c.ProbeRetries) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 1-5")
				}
				c.ProbeRetries = clamp(n, 1, 5)
				return nil
			},
			"how often SCANLTE re-probes a port whose banner came back empty (1-5)", "1"),
		row("OS guess confidence %", itemBool,
			func(c Config) string { return boolText(c.OSConfidence) },
			func(c *Config, v string) error { return setBool(&c.OSConfidence, v) },
			"show a confidence percent next to deep-scan OS guesses", boolText(true)),
		row("uptime estimate (TCP timestamps)", itemBool,
			func(c Config) string { return boolText(c.UptimeGuess) },
			func(c *Config, v string) error { return setBool(&c.UptimeGuess, v) },
			"estimate each host's uptime from TCP timestamps (needs raw sockets)", boolText(true)),
		row("flag ICMP-alive hosts w/o ARP", itemBool,
			func(c Config) string { return boolText(c.RogueFlag) },
			func(c *Config, v string) error { return setBool(&c.RogueFlag, v) },
			"mark hosts that answer ICMP but have no ARP record as possible rogues", boolText(true)),
		row("ARP sweep (when root)", itemBool,
			func(c Config) string { return boolText(c.ArpSweep) },
			func(c *Config, v string) error { return setBool(&c.ArpSweep, v) },
			"also find hosts via an ARP sweep — catches devices that block ping (needs sudo)", boolText(true)),
		row("service discovery (mDNS/DNS-SD)", itemBool,
			func(c Config) string { return boolText(c.ServiceDiscovery) },
			func(c *Config, v string) error { return setBool(&c.ServiceDiscovery, v) },
			"gnulte-scan: ask the network's mDNS/DNS-SD responders (Avahi-style) what each device offers", boolText(true)),
		head("TRAFFIC ENGINE"),
		row("stealth ARP spoofing", itemBool,
			func(c Config) string { return boolText(c.StealthArp) },
			func(c *Config, v string) error { return setBool(&c.StealthArp, v) },
			"gnulte: answer ARP only when asked (on-demand) with a slow cache refresh — far less visible to other scanners", boolText(false)),
		row("advanced mode (echo commands)", itemBool,
			func(c Config) string { return boolText(c.Advanced) },
			func(c *Config, v string) error { return setBool(&c.Advanced, v) },
			"gnulte: echo the exact command line for every tc/arpspoof/sysctl step as it runs (still recorded in the HTML report when off)", boolText(true)),
		head("GNULTE-WIFI"),
		row("wifi frames per burst", itemInt,
			func(c Config) string { return fmt.Sprintf("%d", c.WifiCount) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("a whole number, 1-512")
				}
				c.WifiCount = clamp(n, 1, 512)
				return nil
			},
			"deauth frames sent in each gnulte-wifi burst (1-512)", "64"),
		row("wifi delay between bursts (s)", itemInt,
			func(c Config) string { return fmt.Sprintf("%ds", c.WifiDelaySec) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("whole seconds, 1-60")
				}
				c.WifiDelaySec = clamp(n, 1, 60)
				return nil
			},
			"seconds between bursts (repeat kicks a client that reconnects)", "5s"),
		row("wifi jitter (ms)", itemInt,
			func(c Config) string { return fmt.Sprintf("%dms", c.WifiJitterMs) },
			func(c *Config, v string) error {
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("milliseconds, 0-100")
				}
				c.WifiJitterMs = clamp(n, 0, 100)
				return nil
			},
			"random 0-N ms delay before each frame — irregular timing defeats reconnect timers", "2ms"),
		row("wifi mix deauth reasons", itemBool,
			func(c Config) string { return boolText(c.WifiMixReasons) },
			func(c *Config, v string) error { return setBool(&c.WifiMixReasons, v) },
			"rotate the 802.11 reason code each burst so static filtering can't match", boolText(true)),
		row("wifi channel hop", itemBool,
			func(c Config) string { return boolText(c.WifiHop) },
			func(c *Config, v string) error { return setBool(&c.WifiHop, v) },
			"jump the adapter between channels after each burst", boolText(false)),
		row("wifi hop channels", itemStr,
			func(c Config) string { return c.WifiChannels },
			func(c *Config, v string) error {
				if strings.TrimSpace(v) == "" {
					return fmt.Errorf("at least one channel, comma-separated, e.g. 1,6,11")
				}
				c.WifiChannels = strings.TrimSpace(v)
				return nil
			},
			"comma-separated channel list to hop through, e.g. \"1,6,11\"", "1,6,11"),
		head("TERMINAL & UI"),
		row("typing animation", itemBool,
			func(c Config) string { return boolText(c.Typing) },
			func(c *Config, v string) error { return setBool(&c.Typing, v) },
			"type the interactive confirmation out character by character on live terminals", boolText(true)),
	)

	// The cursor starts on the first editable value, never on a header.
	e.sel = e.firstItem()

	for {
		e.draw()
		key, r := e.s.Key()
		if e.edit {
			e.handleEdit(key, r)
			continue
		}
		switch key {
		case tui.KeyUp:
			e.sel = e.step(-1)
			e.clampTop()
		case tui.KeyDown:
			e.sel = e.step(1)
			e.clampTop()
		case tui.KeyLeft, tui.KeyRight:
			e.jog(key == tui.KeyRight)
		case tui.KeyEsc:
			return
		case tui.KeyEnter, tui.KeySpace:
			it := e.items[e.sel]
			if !it.head && it.kind == itemBool {
				_ = it.set(&e.cfg, boolText(!e.boolVal(e.sel)))
			} else if !it.head {
				e.edit = true
				e.buf = nil // typing replaces the value from scratch
				e.liveErr = ""
			}
		case tui.KeyRune:
			switch r {
			case 'r':
				if err := e.items[e.sel].set(&e.cfg, e.items[e.sel].def); err != nil {
					e.liveErr = err.Error()
				}
			case 'R':
				e.resetAll()
			case 'g':
				e.sel = e.firstItem()
				e.top = 0
			case 'G':
				e.sel = e.lastItem()
				e.clampTop()
			case 'q', 'Q':
				return
			}
		}
	}
}

// step returns the next selectable index in dir's direction, skipping the
// non-editable category headers so the arrow keys always land on a value.
func (e *editor) step(dir int) int {
	n := len(e.items)
	i := e.sel + dir
	for tries := 0; tries < n; tries++ {
		if i < 0 {
			i = n - 1
		} else if i >= n {
			i = 0
		}
		if !e.items[i].head {
			return i
		}
		i += dir
	}
	return e.sel
}

// firstItem/lastItem find the first and last editable value rows (Home/End and
// the g/G jump keys land on a value, never on a header).
func (e *editor) firstItem() int {
	for i := range e.items {
		if !e.items[i].head {
			return i
		}
	}
	return 0
}

func (e *editor) lastItem() int {
	for i := len(e.items) - 1; i >= 0; i-- {
		if !e.items[i].head {
			return i
		}
	}
	return 0
}

func setBool(dst *bool, v string) error {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "on", "1", "yes", "true":
		*dst = true
	case "off", "0", "no", "false":
		*dst = false
	default:
		return fmt.Errorf("on or off")
	}
	return nil
}

// jog nudges an int item by ±1 while the editor screenshots the numeric part
// out of the getter. Bool items simply toggle.
func (e *editor) jog(dir bool) {
	it := e.items[e.sel]
	if it.kind == itemStr {
		return
	}
	if it.kind == itemBool {
		_ = it.set(&e.cfg, boolText(!e.boolVal(e.sel)))
		return
	}
	n := parseInt(e.items[e.sel].get(e.cfg))
	if dir {
		n++
	} else {
		n--
	}
	_ = it.set(&e.cfg, strconv.Itoa(n))
}

func parseInt(s string) int {
	var d strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d.WriteRune(r)
		}
	}
	if d.Len() == 0 {
		return 0
	}
	n, _ := strconv.Atoi(d.String())
	return n
}

// resetAll restores every value row to its factory default (headers untouched).
func (e *editor) resetAll() {
	for i := range e.items {
		if e.items[i].head {
			continue
		}
		_ = e.items[i].set(&e.cfg, e.items[i].def)
	}
	e.liveErr = ""
}

// clampTop keeps the selected row inside the scroll window.
func (e *editor) clampTop() {
	visible := e.visible()
	if e.sel < e.top {
		e.top = e.sel
	}
	if e.sel >= e.top+visible {
		e.top = e.sel - visible + 1
	}
}

func (e *editor) visible() int {
	h := ux.Height()
	if h < 10 {
		return 3
	}
	return h - 5
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
			if len(e.buf) < 96 {
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

// orOff renders zeroed thresholds as "off" so the editor reads naturally while
// the jog/parse machinery still extracts the numeric 0 for ±1 nudging.
func orOff(s string) string {
	if strings.HasPrefix(s, "0") {
		return "off"
	}
	return s
}

func boolText(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// draw renders the whole settings screen in one flicker-free flush: category
// headers, the scroll window, and a footer with the current help for the row
// under the cursor. The box scales with the terminal up to 96 columns so a
// wide window shows a wide list (headers divide it into browsable sections).
func (e *editor) draw() {
	width := ux.Width()
	inner := width - 4
	if inner > 96 {
		inner = 96
	}
	if inner < 40 {
		inner = 40
	}
	visible := e.visible()
	lines := make([]string, 0, visible+6)
	title := " GNULTE settings — v13 "
	lines = append(lines, "  ┌─"+title+strings.Repeat("─", max0(inner-len(title)-2))+"┐")

	if e.edit {
		lines = append(lines, "  │ "+ux.C(ux.Bold, "enter a value for: "+e.items[e.sel].label)+strings.Repeat(" ", max0(inner-2-len("enter a value for: "+e.items[e.sel].label)))+" │")
	}

	// A slim scroll marker when the list is taller than the window.
	showScroll := len(e.items) > visible

	shown := 0
	for i := e.top; i < len(e.items) && shown < visible; i++ {
		it := e.items[i]
		var body string
		if it.head {
			// Category separator: a dim rule with the section name in it.
			pad := inner - len(it.label) - 5
			if pad < 1 {
				pad = 1
			}
			body = "  │── " + ux.C(ux.Dim+ux.Bold, it.label) + strings.Repeat("─", pad) + " ─│"
			body = ux.C(ux.Dim, body)
		} else {
			body = "  │ " + it.label + ":" + strings.Repeat(" ", max0(inner-len(it.label)-len(it.get(e.cfg))-3)) + it.get(e.cfg) + " "
			if e.edit && i == e.sel {
				body = "  │ " + it.label + ":" + strings.Repeat(" ", max0(inner-len(it.label)-len(string(e.buf))-4)) + string(e.buf) + "_ │"
				body = ux.C(ux.Bold, body)
			}
			if i == e.sel && !e.edit {
				body = ux.C(ux.Bold, body)
			}
		}
		if showScroll {
			mark := " "
			if i >= e.top+visible {
				mark = "▸"
			}
			body = trimRightCell(body) + mark + "│"
		}
		lines = append(lines, body)
		shown++
	}
	for ; shown < visible; shown++ {
		lines = append(lines, "  │"+strings.Repeat(" ", inner)+"│")
	}
	lines = append(lines, "  └"+strings.Repeat("─", inner)+"┘")

	foot := "  ↑/↓ move · ←/→ adjust · Enter edit/toggle · g/G first/last · r reset · R reset all · Esc save & exit"
	if e.edit {
		foot = "  entering a value… Enter accept · Esc cancel"
		if e.liveErr != "" {
			foot = "  " + ux.C(ux.Red, e.liveErr) + " — Enter accept · Esc cancel"
		}
	} else if it := e.items[e.sel]; !it.head && it.help != "" {
		foot = "  " + ux.C(ux.Dim, it.help)
	}
	lines = append(lines, foot)
	e.s.Draw(lines)
}

// trimRightCell drops the last visible cell from a box row. When the row was
// colourised (bold selection), the trailing ANSI reset is kept whole so the
// line never ends inside an escape sequence.
func trimRightCell(s string) string {
	const reset = "\033[0m"
	if strings.HasSuffix(s, reset) {
		return s[:len(s)-len(reset)]
	}
	if len(s) > 0 {
		return s[:len(s)-1]
	}
	return s
}

func max0(v int) int {
	if v < 1 {
		return 1
	}
	return v
}
