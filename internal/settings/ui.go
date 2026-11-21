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
	"unicode/utf8"

	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

// Exact screen strings from the v17 settings design.
const (
	settingsTitle  = "GNULTE settings — v17"
	settingsSub    = "Saved defaults for every tool. Enter a value directly; ←/→ steps by one."
	settingsPages  = "1 NETWORK & MONITOR  2 SCANLTE SCAN  3 TRAFFIC ENGINE  4 GNULTE-WIFI  5 TERMINAL & UI"
	settingsFoot   = "↑↓ field · ←/→ step · Enter edit/toggle · 1-5 page · / find · c changed · s save · Esc save & exit · D discard"
	editFootSuffix = "Enter accept · Esc cancel value"
	discardAsk     = "Discard unsaved changes? y/N"
	resetAllAsk    = "Reset all settings to defaults? y/N"
	noMatchFmt     = `No settings match "%s". Esc to clear.`
	savedFmt       = "Saved to %s."
)

// Exact validation strings; they double as the help shown while a value is
// being typed, so they must agree with the setters.
const (
	valSeconds   = "Whole seconds, 1–60."
	valMillis    = "A number of milliseconds, 100–60000."
	valHistory   = "Whole number, 10–240."
	valWifiCount = "Whole number, 1–256."
	valRate      = "Kilobits per second, 0–1000000 (0 = off)."
	valBool      = "on or off."
	valChannels  = "At least one channel, comma-separated, e.g. 1,6,11."
	valInterface = "Interface cannot be empty. Type auto to detect the default route."
)

// The five category strings are part of the editor's contract; page jumps use
// these names in this order.
var categoryNames = [5]string{
	"NETWORK & MONITOR",
	"SCANLTE SCAN",
	"TRAFFIC ENGINE",
	"GNULTE-WIFI",
	"TERMINAL & UI",
}

// Edit opens the full-screen settings editor and returns the operator's
// version of the config plus a save flag. The caller writes the config only
// when save is true; a confirmed discard returns false so the file is left
// untouched. It fails with a descriptive error when no terminal is present.
func Edit(c Config) (Config, bool, error) {
	s, err := tui.Open()
	if err != nil {
		return c, false, err
	}
	defer s.Close()

	e := newEditor(c)
	e.s = s
	save := e.run()
	return e.cfg, save, nil
}

type editmode int

const (
	modeNav editmode = iota
	modeValue
	modeFilter
	modeDiscard
	modeReset
)

type editor struct {
	s       *tui.Screen
	cfg     Config
	initial Config // snapshot used by [unsaved: N] and D discard
	items   []editItem
	save    func(Config) error

	sel  int // index into items, or -1 when the current view is empty
	top  int // first visible row view
	page int // zero-based category page

	mode         editmode
	buf          []rune // typed value
	filterBuf    []rune
	filter       string
	changedOnly  bool
	showAdvanced bool

	liveErr    string // validation or reset error
	notice     string // transient jog message ("At minimum (1)")
	status     string // transient "Saved to <path>." message
	saveOnExit bool   // false only after a confirmed D discard
}

// editItem is one editor row: a label, a kind, a getter/setter pair, a
// human help line, and the factory-default display value used by the reset key.
// head rows are non-editable category separators; integer rows also carry the
// bounds used for validation and arrow-jog messages.
type editItem struct {
	label    string
	kind     int
	head     bool
	page     int
	get      func(c Config) string
	set      func(c *Config, v string) error
	help     string
	hint     string // short validation help, shown while editing
	def      string
	lo, hi   int
	advanced bool // marked with "+" and hideable via -
}

const (
	itemStr = iota
	itemInt
	itemBool
	itemHead
)

// newEditor builds the categorized item list and captures the starting state.
// It is pure (apart from choosing Save as the default writer) so the editor
// can be tested without a PTY.
func newEditor(c Config) *editor {
	e := &editor{cfg: c, initial: c, save: Save, showAdvanced: true, saveOnExit: true}
	e.items = buildItems()
	e.sel = e.firstItem()
	return e
}

// buildItems keeps the original editItem/get/set/def model and adds the two v17
// rows under TERMINAL & UI. The setters validate instead of silently clamping;
// arrow-jog applies the clamp separately and reports it as a transient notice.
func buildItems() []editItem {
	row := func(label string, kind int, get func(Config) string, set func(c *Config, v string) error, help, def string) editItem {
		return editItem{label: label, kind: kind, get: get, set: set, help: help, def: def}
	}
	head := func(page int) editItem {
		return editItem{label: categoryNames[page], kind: itemHead, head: true, page: page}
	}
	intRow := func(label string, field func(*Config) *int, get func(Config) string, lo, hi int, hint, help, def string) editItem {
		it := row(label, itemInt, get, intSetter(field, lo, hi, hint), help, def)
		it.hint, it.lo, it.hi = hint, lo, hi
		return it
	}
	boolRow := func(label string, field func(*Config) *bool, help, def string) editItem {
		it := row(label, itemBool,
			func(c Config) string { return boolText(*field(&c)) },
			func(c *Config, v string) error { return setBool(field(c), v) },
			help, def)
		it.hint = valBool
		return it
	}

	items := []editItem{
		head(0),
		row("interface", itemStr,
			func(c Config) string { return orAuto(c.Interface) },
			func(c *Config, v string) error {
				if strings.TrimSpace(v) == "" {
					return fmt.Errorf("%s", valInterface)
				}
				if v == "auto" {
					c.Interface = ""
					return nil
				}
				c.Interface = v
				return nil
			},
			"network interface used by monitor/traffic; 'auto' detects the default route", "auto"),
		boolRow("HTML report after test", func(c *Config) *bool { return &c.HTMLReport },
			"write the post-test HTML report to the report hub", boolText(true)),
		boolRow("ping beeps", func(c *Config) *bool { return &c.Beeps },
			"pitch the ping latency as beeps in gnulte's monitor", boolText(true)),
		intRow("monitor/traffic interval (s)", func(c *Config) *int { return &c.IntervalSec },
			func(c Config) string { return fmt.Sprintf("%ds", c.IntervalSec) },
			1, 60, valSeconds, "seconds between monitor and traffic window refreshes (1–60)", "1s"),
		intRow("ping timeout (ms)", func(c *Config) *int { return &c.TimeoutMs },
			func(c Config) string { return fmt.Sprintf("%dms", c.TimeoutMs) },
			100, 60000, valMillis, "per-ping timeout; raise it for slow or degraded links (100–60000)", "1000ms"),
		intRow("ping history depth", func(c *Config) *int { return &c.History },
			func(c Config) string { return fmt.Sprintf("%d", c.History) },
			10, 240, valHistory, "How many ping samples each monitor keeps per target. Range 10–240.", "60"),
		intRow("traffic window update (s)", func(c *Config) *int { return &c.TrafficSec },
			func(c Config) string { return fmt.Sprintf("%ds", c.TrafficSec) },
			1, 10, "Whole seconds, 1–10.", "refresh interval for the GNULTE-WATCH watch window (1–10)", "1s"),
		intRow("lan alarm rate (kbps)", func(c *Config) *int { return &c.AlarmRateKbps },
			func(c Config) string { return orOff(fmt.Sprintf("%dkbps", c.AlarmRateKbps)) },
			0, 1000000, valRate, "GNULTE-WATCH: mark any host whose down/up speed exceeds this (0 = off)", "0"),
		intRow("lan alarm latency (ms)", func(c *Config) *int { return &c.AlarmLatencyMs },
			func(c Config) string { return orOff(fmt.Sprintf("%dms", c.AlarmLatencyMs)) },
			0, 60000, "Milliseconds, 0–60000 (0 = off).", "GNULTE-WATCH: mark any host whose average ping exceeds this (0 = off)", "0"),

		head(1),
		intRow("scan threads", func(c *Config) *int { return &c.ScanThreads },
			func(c Config) string { return fmt.Sprintf("%d", c.ScanThreads) },
			1, 512, "Whole number, 1–512.", "parallel workers for the live-host ping sweep (1–512)", "64"),
		intRow("deep-scan retries per port", func(c *Config) *int { return &c.ProbeRetries },
			func(c Config) string { return fmt.Sprintf("%d", c.ProbeRetries) },
			1, 5, "Whole number, 1–5.", "how often SCANLTE re-probes a port whose banner came back empty (1–5)", "1"),
		boolRow("OS guess confidence %", func(c *Config) *bool { return &c.OSConfidence },
			"show a confidence percent next to deep-scan OS guesses", boolText(true)),
		boolRow("uptime estimate (TCP timestamps)", func(c *Config) *bool { return &c.UptimeGuess },
			"estimate each host's uptime from TCP timestamps (needs raw sockets)", boolText(true)),
		boolRow("flag ICMP-alive hosts w/o ARP", func(c *Config) *bool { return &c.RogueFlag },
			"mark hosts that answer ICMP but have no ARP record as possible rogues", boolText(true)),
		boolRow("ARP sweep (when root)", func(c *Config) *bool { return &c.ArpSweep },
			"also find hosts via an ARP sweep — catches devices that block ping (needs sudo)", boolText(true)),
		boolRow("service discovery (mDNS/DNS-SD)", func(c *Config) *bool { return &c.ServiceDiscovery },
			"gnulte-scan: ask the network's mDNS/DNS-SD responders (Avahi-style) what each device offers", boolText(true)),

		head(2),
		boolRow("stealth ARP spoofing", func(c *Config) *bool { return &c.StealthArp },
			"gnulte: answer ARP only when asked (on-demand) with a slow cache refresh — far less visible to other scanners", boolText(false)),
		boolRow("echo commands in sessions", func(c *Config) *bool { return &c.Advanced },
			"gnulte: echo the exact command line for every tc/arpspoof/sysctl step as it runs (still recorded in the HTML report when off)", boolText(true)),

		head(3),
		intRow("wifi frames per burst", func(c *Config) *int { return &c.WifiCount },
			func(c Config) string { return fmt.Sprintf("%d", c.WifiCount) },
			1, 256, valWifiCount, "deauth frames sent in each gnulte-wifi burst (1–256)", "64"),
		intRow("wifi delay between bursts (s)", func(c *Config) *int { return &c.WifiDelaySec },
			func(c Config) string { return fmt.Sprintf("%ds", c.WifiDelaySec) },
			1, 60, valSeconds, "seconds between bursts (repeat kicks a client that reconnects), 1–60", "5s"),
		intRow("wifi jitter (ms)", func(c *Config) *int { return &c.WifiJitterMs },
			func(c Config) string { return fmt.Sprintf("%dms", c.WifiJitterMs) },
			0, 100, "Milliseconds, 0–100.", "random 0-N ms delay before each frame — irregular timing defeats reconnect timers", "2ms"),
		boolRow("wifi mix deauth reasons", func(c *Config) *bool { return &c.WifiMixReasons },
			"rotate the 802.11 reason code each burst so static filtering can't match", boolText(true)),
		boolRow("wifi channel hop", func(c *Config) *bool { return &c.WifiHop },
			"jump the adapter between channels after each burst", boolText(false)),
		row("wifi hop channels", itemStr,
			func(c Config) string { return c.WifiChannels },
			func(c *Config, v string) error {
				if strings.TrimSpace(v) == "" {
					return fmt.Errorf("%s", valChannels)
				}
				c.WifiChannels = strings.TrimSpace(v)
				return nil
			},
			"comma-separated channel list to hop through, e.g. \"1,6,11\"", "1,6,11"),

		head(4),
		boolRow("typing animation", func(c *Config) *bool { return &c.Typing },
			"type the interactive confirmation out character by character on live terminals", boolText(true)),
		boolRow("Detailed controls in hub", func(c *Config) *bool { return &c.HubDetailed },
			"ask Standard/Detailed before launching a tool from gnulte-hub", boolText(false)),
		boolRow("topology animation", func(c *Config) *bool { return &c.TopologyAnimation },
			"animate the PATH topology in gnulte-watch when reduced motion is not active", boolText(true)),
	}

	// Fill in each row's page from the preceding header and mark the one
	// Detailed-only row; the marker changes visibility, never the value.
	page := 0
	for i := range items {
		if items[i].head {
			page = items[i].page
		}
		items[i].page = page
		if items[i].label == "wifi hop channels" {
			items[i].hint = valChannels
		}
	}
	for i := range items {
		if items[i].label == "stealth ARP spoofing" {
			items[i].advanced = true
		}
	}
	return items
}

func intSetter(field func(*Config) *int, lo, hi int, hint string) func(*Config, string) error {
	return func(c *Config, v string) error { return setInt(field(c), v, lo, hi, hint) }
}

// setInt rejects both malformed and out-of-range input. Values like "1000ms"
// are accepted for reset defaults and jog results, never silently clamped.
func setInt(dst *int, v string, lo, hi int, hint string) error {
	n, err := strconv.Atoi(trimUnit(strings.TrimSpace(v)))
	if err != nil || n < lo || n > hi {
		return fmt.Errorf("%s", hint)
	}
	*dst = n
	return nil
}

func trimUnit(s string) string {
	if strings.HasSuffix(s, "ms") {
		return strings.TrimSuffix(s, "ms")
	}
	if strings.HasSuffix(s, "s") {
		return strings.TrimSuffix(s, "s")
	}
	return s
}

// run drives the edit loop and returns whether the caller should persist the
// returned config. All key handling lives in pure helpers so tests can
// exercise navigation, validation and discard without a terminal.
func (e *editor) run() bool {
	for {
		e.draw()
		key, r := e.s.Key()
		if e.handleKey(key, r) {
			return e.saveOnExit
		}
	}
}

func (e *editor) handleKey(key tui.Key, r rune) bool {
	// Jog and save messages last for one key press only.
	e.notice = ""
	e.status = ""
	switch e.mode {
	case modeValue:
		e.handleValueKey(key, r)
		return false
	case modeFilter:
		e.handleFilterKey(key, r)
		return false
	case modeDiscard:
		return e.handleConfirm(key, r, true)
	case modeReset:
		return e.handleConfirm(key, r, false)
	default:
		return e.handleNav(key, r)
	}
}

// handleNav returns true when the editor should exit; saveOnExit says whether
// the caller should persist the returned config.
func (e *editor) handleNav(key tui.Key, r rune) bool {
	switch key {
	case tui.KeyUp:
		e.sel = e.step(-1)
		e.clampTop()
		e.liveErr = ""
	case tui.KeyDown:
		e.sel = e.step(1)
		e.clampTop()
		e.liveErr = ""
	case tui.KeyLeft, tui.KeyRight:
		e.jog(key == tui.KeyRight)
	case tui.KeyEsc:
		return true // save & exit, as before
	case tui.KeyEnter, tui.KeySpace:
		e.beginEdit()
	case tui.KeyRune:
		return e.handleNavRune(r)
	}
	return false
}

func (e *editor) handleNavRune(r rune) bool {
	switch r {
	case '/':
		e.mode = modeFilter
		e.filter, e.filterBuf = "", nil
		e.top = 0
		e.clampSel()
	case 'c':
		e.changedOnly = !e.changedOnly
		e.top = 0
		e.clampSel()
		e.liveErr = ""
	case 's':
		e.saveNow()
	case 'D':
		if e.changedCount() > 0 {
			e.mode = modeDiscard
			return false
		}
		// No unsaved state is still a discard: exit without a later save.
		e.saveOnExit = false
		return true
	case 'q', 'Q':
		return true // save & exit, as before
	case 'R':
		e.mode = modeReset
	case 'r':
		if e.sel >= 0 {
			it := e.items[e.sel]
			if err := it.set(&e.cfg, it.def); err != nil {
				e.liveErr = err.Error()
			} else {
				e.liveErr = ""
			}
		}
	case 'g':
		e.sel = e.firstItem()
		e.top = 0
	case 'G':
		e.sel = e.lastItem()
		e.clampTop()
	case '+', '-':
		e.showAdvanced = r == '+'
		e.top = 0
		e.clampSel()
	default:
		if page, ok := pageForRune(r); ok {
			e.setPage(page)
		}
	}
	return false
}

func (e *editor) handleConfirm(key tui.Key, r rune, discard bool) bool {
	if key == tui.KeyRune && (r == 'y' || r == 'Y') {
		e.mode = modeNav
		if discard {
			e.cfg = e.initial
			e.saveOnExit = false
			return true
		}
		e.resetAll()
		return false
	}
	if key == tui.KeyEsc || key == tui.KeyEnter ||
		(key == tui.KeyRune && (r == 'n' || r == 'N')) {
		e.mode = modeNav
	}
	return false
}

func (e *editor) beginEdit() {
	if e.sel < 0 {
		return
	}
	it := e.items[e.sel]
	if it.kind == itemBool {
		_ = it.set(&e.cfg, boolText(!e.boolVal(e.sel)))
		return
	}
	e.mode = modeValue
	e.buf = nil // typing replaces the value from scratch
	e.liveErr = ""
}

func (e *editor) handleValueKey(key tui.Key, r rune) {
	switch key {
	case tui.KeyEsc:
		e.mode = modeNav
		e.liveErr = ""
	case tui.KeyEnter:
		if e.sel < 0 {
			e.mode = modeNav
			return
		}
		it := e.items[e.sel]
		if err := it.set(&e.cfg, string(e.buf)); err != nil {
			e.liveErr = err.Error() // stay in edit mode; never clamp typed input
			return
		}
		e.mode = modeNav
		e.liveErr = ""
	case tui.KeyBackspace:
		if len(e.buf) > 0 {
			e.buf = e.buf[:len(e.buf)-1]
		}
	case tui.KeySpace:
		if len(e.buf) < 96 {
			e.buf = append(e.buf, ' ')
		}
	case tui.KeyRune:
		// Digits (and every other printable rune) are value characters here;
		// no page jump can be triggered while editing.
		if r >= 0x20 && len(e.buf) < 96 {
			e.buf = append(e.buf, r)
		}
	}
}

func (e *editor) handleFilterKey(key tui.Key, r rune) {
	switch key {
	case tui.KeyEsc:
		e.mode = modeNav
		e.filter, e.filterBuf = "", nil
		e.top = 0
		e.clampSel()
	case tui.KeyEnter:
		e.mode = modeNav
		e.top = 0
		e.clampSel()
	case tui.KeyBackspace:
		if len(e.filterBuf) > 0 {
			e.filterBuf = e.filterBuf[:len(e.filterBuf)-1]
			e.applyFilter()
		}
	case tui.KeySpace:
		if len(e.filterBuf) < 64 {
			e.filterBuf = append(e.filterBuf, ' ')
			e.applyFilter()
		}
	case tui.KeyRune:
		if r >= 0x20 && len(e.filterBuf) < 64 {
			e.filterBuf = append(e.filterBuf, r)
			e.applyFilter()
		}
	}
}

func (e *editor) applyFilter() {
	e.filter = string(e.filterBuf)
	e.top = 0
	e.clampSel()
}

func (e *editor) saveNow() {
	path := Path()
	save := e.save
	if save == nil {
		save = Save
	}
	if err := save(e.cfg); err != nil {
		e.status = err.Error()
		return
	}
	e.initial = e.cfg
	e.status = fmt.Sprintf(savedFmt, path)
	e.liveErr = ""
}

func pageForRune(r rune) (int, bool) {
	if r >= '1' && r <= '5' {
		return int(r - '1'), true
	}
	return 0, false
}

func (e *editor) setPage(p int) {
	if p < 0 || p >= len(categoryNames) {
		return
	}
	e.page = p
	e.filter, e.filterBuf = "", nil
	e.changedOnly = false
	e.top = 0
	e.sel = e.firstItem()
	e.liveErr = ""
}

// pageRange returns the half-open item-index range for the active page.
func (e *editor) pageRange() (int, int) {
	for i, it := range e.items {
		if it.head && it.page == e.page {
			end := len(e.items)
			for j := i + 1; j < len(e.items); j++ {
				if e.items[j].head {
					end = j
					break
				}
			}
			return i, end
		}
	}
	return len(e.items), len(e.items)
}

// rowView is one rendered row in the active page. Head rows are inert.
type rowView struct {
	idx      int
	head     bool
	label    string
	value    string
	changed  string
	advanced bool
}

// entries applies page, changed-only, filter and advanced-row visibility.
func (e *editor) entries() []rowView {
	start, end := e.pageRange()
	out := make([]rowView, 0, end-start)
	for i := start; i < end; i++ {
		it := e.items[i]
		if it.head {
			out = append(out, rowView{idx: i, head: true, label: it.label})
			continue
		}
		if it.advanced && !e.showAdvanced {
			continue
		}
		if e.changedOnly && !e.isChanged(i) {
			continue
		}
		if e.filter != "" && !matchesFilter(it.label, e.filter) {
			continue
		}
		value := it.get(e.cfg)
		if e.mode == modeValue && i == e.sel {
			value = string(e.buf) + "_"
		}
		changed := ""
		if e.isChanged(i) {
			changed = fmt.Sprintf("* changed (default %s)", it.def)
		}
		out = append(out, rowView{idx: i, label: it.label, value: value, changed: changed, advanced: it.advanced})
	}
	return out
}

func matchesFilter(label, filter string) bool {
	return strings.Contains(strings.ToLower(label), strings.ToLower(filter))
}

// visibleRows returns the selectable item indexes in display order.
func (e *editor) visibleRows() []int {
	out := []int{}
	for _, v := range e.entries() {
		if !v.head {
			out = append(out, v.idx)
		}
	}
	return out
}

func indexOf(rows []int, sel int) int {
	for i, v := range rows {
		if v == sel {
			return i
		}
	}
	return -1
}

// step moves within the active page and stops at its ends (no wrap).
func (e *editor) step(dir int) int {
	rows := e.visibleRows()
	if len(rows) == 0 {
		return -1
	}
	pos := indexOf(rows, e.sel)
	if pos < 0 {
		if dir > 0 {
			return rows[0]
		}
		return rows[len(rows)-1]
	}
	next := pos + dir
	if next < 0 {
		next = 0
	}
	if next >= len(rows) {
		next = len(rows) - 1
	}
	return rows[next]
}

func (e *editor) firstItem() int {
	rows := e.visibleRows()
	if len(rows) == 0 {
		return -1
	}
	return rows[0]
}

func (e *editor) lastItem() int {
	rows := e.visibleRows()
	if len(rows) == 0 {
		return -1
	}
	return rows[len(rows)-1]
}

func (e *editor) clampSel() {
	rows := e.visibleRows()
	if len(rows) == 0 {
		e.sel = -1
		e.top = 0
		return
	}
	if indexOf(rows, e.sel) < 0 {
		e.sel = rows[0]
	}
	e.clampTop()
}

func setBool(dst *bool, v string) error {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "on", "1", "yes", "true":
		*dst = true
	case "off", "0", "no", "false":
		*dst = false
	default:
		return fmt.Errorf("%s", valBool)
	}
	return nil
}

// jog nudges an int item by ±1 using the getter's numeric part. Bool items
// toggle. Only the jog clamps out-of-range steps and reports the bound.
func (e *editor) jog(right bool) {
	if e.sel < 0 {
		return
	}
	it := e.items[e.sel]
	if it.head {
		return
	}
	if it.kind == itemBool {
		_ = it.set(&e.cfg, boolText(!e.boolVal(e.sel)))
		return
	}
	if it.kind != itemInt {
		return
	}
	n := parseInt(it.get(e.cfg))
	if right {
		n++
	} else {
		n--
	}
	if it.hi > 0 {
		if n < it.lo {
			n = it.lo
			e.notice = fmt.Sprintf("At minimum (%d)", it.lo)
		} else if n > it.hi {
			n = it.hi
			e.notice = fmt.Sprintf("At maximum (%d)", it.hi)
		}
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

func (e *editor) resetAll() {
	for i := range e.items {
		if e.items[i].head {
			continue
		}
		_ = e.items[i].set(&e.cfg, e.items[i].def)
	}
	e.liveErr = ""
}

func (e *editor) isChanged(i int) bool {
	it := e.items[i]
	return it.get(e.cfg) != it.get(e.initial)
}

func (e *editor) changedCount() int {
	n := 0
	for i, it := range e.items {
		if !it.head && e.isChanged(i) {
			n++
		}
	}
	return n
}

// visible is the number of list rows that fit below the two header lines and
// above the rule/help/footer lines.
func (e *editor) visible() int { return visibleFor(ux.Height()) }

func visibleFor(h int) int {
	v := h - 9
	if v < 3 {
		v = 3
	}
	if v > 24 {
		v = 24
	}
	return v
}

func (e *editor) clampTop() {
	entries := e.entries()
	if e.top < 0 {
		e.top = 0
	}
	if e.top >= len(entries) {
		e.top = max0(len(entries) - 1)
	}
	v := e.visible()
	if e.top+v > len(entries) {
		e.top = len(entries) - v
		if e.top < 0 {
			e.top = 0
		}
	}
}

func (e *editor) boolVal(i int) bool { return e.items[i].get(e.cfg) == "on" }

func orAuto(s string) string {
	if s == "" {
		return "auto"
	}
	return s
}

// orOff renders zeroed thresholds as "off" while jog/parse still sees the 0.
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

// lines renders the whole frame from editor state. Tests call it with fixed
// dimensions; draw uses the live terminal size.
func (e *editor) lines(w, h int) []string {
	inner := w - 4
	if inner > 96 {
		inner = 96
	}
	if inner < 40 {
		inner = 40
	}
	visible := visibleFor(h)
	entries := e.entries()
	e.clampTop()

	lines := make([]string, 0, visible+9)
	cap := max0(inner - utf8.RuneCountInString(settingsTitle) - 2)
	lines = append(lines, "  ┌─"+settingsTitle+strings.Repeat("─", cap)+"┐")

	right := Path()
	if n := e.changedCount(); n > 0 {
		dirty := fmt.Sprintf("[unsaved: %d]", n)
		right = dirty + "  " + right
		if utf8.RuneCountInString(settingsSub)+utf8.RuneCountInString(right)+2 > inner {
			right = dirty
		}
	}
	sub := settingsSub
	if pad := inner - utf8.RuneCountInString(sub) - utf8.RuneCountInString(right); pad > 0 {
		sub += strings.Repeat(" ", pad) + right
	}
	lines = append(lines, boxContent(sub, inner))
	lines = append(lines, boxContent(settingsPages, inner))
	lines = append(lines, "  ├"+strings.Repeat("─", inner)+"┤")

	shown := 0
	if e.filter != "" && len(e.visibleRows()) == 0 {
		lines = append(lines, boxContent(fmt.Sprintf(noMatchFmt, e.filter), inner))
	}
	for i := e.top; i < len(entries) && shown < visible; i++ {
		v := entries[i]
		text := formatRow(v, v.idx == e.sel, inner)
		if v.head {
			text = ux.C(ux.Dim+ux.Bold, text)
		} else if v.idx == e.sel {
			text = ux.C(ux.Bold, text)
		}
		lines = append(lines, boxContent(text, inner))
		shown++
	}
	for ; shown < visible; shown++ {
		lines = append(lines, boxContent("", inner))
	}
	lines = append(lines, "  └"+strings.Repeat("─", inner)+"┘")
	lines = append(lines, "  "+e.helpLine())
	lines = append(lines, "  "+ux.C(ux.Dim, settingsFoot))
	return lines
}

// helpLine is the contextual line directly under the value list. While a
// value is being edited it keeps that field's validation help visible.
func (e *editor) helpLine() string {
	switch e.mode {
	case modeValue:
		msg := e.liveErr
		if msg == "" && e.sel >= 0 {
			msg = e.items[e.sel].hint
		}
		if msg == "" {
			msg = "Enter a value"
		}
		return msg + " · " + editFootSuffix
	case modeFilter:
		return "Find: " + e.filter + " · Enter apply · Esc clear"
	case modeDiscard:
		return discardAsk
	case modeReset:
		return resetAllAsk
	}
	if e.status != "" {
		return e.status
	}
	if e.notice != "" {
		return e.notice
	}
	if e.liveErr != "" {
		return e.liveErr
	}
	if e.sel >= 0 && e.items[e.sel].help != "" {
		return ux.C(ux.Dim, e.items[e.sel].help)
	}
	return ""
}

func formatRow(v rowView, selected bool, width int) string {
	if v.head {
		text := "── " + v.label + " "
		return text + strings.Repeat("─", max0(width-utf8.RuneCountInString(text)))
	}
	marker := "  "
	if selected {
		marker = "▸ "
	}
	left := marker
	if v.advanced {
		left += "+ "
	}
	left += v.label
	right := v.value
	if v.changed != "" {
		right += "  " + v.changed
	}
	dots := width - utf8.RuneCountInString(left) - utf8.RuneCountInString(right) - 2
	if dots < 1 {
		dots = 1
	}
	return left + " " + strings.Repeat(".", dots) + " " + right
}

func boxContent(s string, inner int) string {
	pad := inner - utf8.RuneCountInString(s)
	if pad < 0 {
		pad = 0
	}
	return "  │ " + s + strings.Repeat(" ", pad) + " │"
}

func (e *editor) draw() { e.s.Draw(e.lines(ux.Width(), ux.Height())) }

func max0(v int) int {
	if v < 1 {
		return 1
	}
	return v
}
