package settings

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gnulte-go/internal/tui"
)

// Compile-time guard for the discard API required by section 2.4.
var _ func(Config) (Config, bool, error) = Edit

// testItems builds a small two-page categorized list mirroring the real editor
// shape: heads separating editable rows, with the same get/set helper wiring.
func testItems() []editItem {
	return []editItem{
		{label: "HEAD A", kind: itemHead, head: true, page: 0},
		{label: "a1", kind: itemBool, page: 0,
			get:  func(c Config) string { return boolText(c.Advanced) },
			set:  func(c *Config, v string) error { return setBool(&c.Advanced, v) },
			hint: valBool, def: boolText(true)},
		{label: "a2", kind: itemInt, page: 0,
			get:  func(c Config) string { return "10" },
			set:  func(c *Config, v string) error { return nil },
			hint: valHistory, def: "10"},
		{label: "HEAD B", kind: itemHead, head: true, page: 1},
		{label: "b1", kind: itemBool, page: 1,
			get:  func(c Config) string { return boolText(c.Typing) },
			set:  func(c *Config, v string) error { return setBool(&c.Typing, v) },
			hint: valBool, def: boolText(true)},
	}
}

func selectLabel(t *testing.T, e *editor, label string) {
	t.Helper()
	for i, it := range e.items {
		if !it.head && it.label == label {
			e.page = it.page
			e.sel = i
			e.top = 0
			return
		}
	}
	t.Fatalf("no edit item labelled %q", label)
}

func findItem(t *testing.T, e *editor, label string) editItem {
	t.Helper()
	for _, it := range e.items {
		if !it.head && it.label == label {
			return it
		}
	}
	t.Fatalf("no edit item labelled %q", label)
	return editItem{}
}

func TestEditorStartsOnFirstValue(t *testing.T) {
	e := newEditor(Default())
	if e.items[e.sel].head {
		t.Fatalf("firstItem landed on a header (index %d)", e.sel)
	}
	if e.items[e.sel].label != "interface" {
		t.Fatalf("firstItem = %q, want interface", e.items[e.sel].label)
	}
	if e.items[e.lastItem()].head {
		t.Fatalf("lastItem landed on a header (index %d)", e.lastItem())
	}
	if got := e.items[e.lastItem()].label; got != "lan alarm latency (ms)" {
		t.Fatalf("lastItem on page 1 = %q, want lan alarm latency (ms)", got)
	}
}

func TestEditorStepSkipsHeadersAndStopsAtPageEnd(t *testing.T) {
	e := &editor{items: testItems(), initial: Default(), showAdvanced: true}

	e.sel = 1 // a1 on page 0
	if got := e.items[e.step(1)].label; got != "a2" {
		t.Fatalf("down from a1 = %q, want a2", got)
	}
	// Page ends stop the cursor; they do not wrap into the next page.
	if got := e.items[e.step(1)].label; got != "a2" {
		t.Fatalf("down from a2 = %q, want a2 (page end)", got)
	}
	if got := e.items[e.step(-1)].label; got != "a1" {
		t.Fatalf("up from a2 = %q, want a1", got)
	}
	if got := e.items[e.step(-1)].label; got != "a1" {
		t.Fatalf("up from a1 = %q, want a1 (page start)", got)
	}

	e.page, e.sel = 1, 3 // b1 on page 1
	if got := e.items[e.step(1)].label; got != "b1" {
		t.Fatalf("down from b1 = %q, want b1 (page end)", got)
	}
	if got := e.items[e.step(-1)].label; got != "b1" {
		t.Fatalf("up from b1 = %q, want b1 (page start)", got)
	}
}

func TestEditorResetAllSkipsHeaders(t *testing.T) {
	e := newEditor(Default())
	e.cfg.Advanced = false
	e.cfg.Typing = false
	e.cfg.HubDetailed = true
	e.cfg.TopologyAnimation = false
	e.resetAll()
	if e.cfg != Default() {
		t.Fatalf("resetAll did not restore defaults: %+v", e.cfg)
	}
}

func TestEditorCategoryShape(t *testing.T) {
	e := newEditor(Default())
	heads := 0
	for i, it := range e.items {
		if it.head {
			heads++
			if it.get != nil || it.set != nil {
				t.Fatalf("head at %d has get/set wiring", i)
			}
			if it.page < 0 || it.page >= len(categoryNames) || categoryNames[it.page] != it.label {
				t.Fatalf("head %q has unexpected page %d", it.label, it.page)
			}
			continue
		}
		foundHead := false
		for _, h := range e.items {
			if h.head && h.page == it.page && h.label == categoryNames[it.page] {
				foundHead = true
				break
			}
		}
		if !foundHead {
			t.Fatalf("row %q is on wrong page %d", it.label, it.page)
		}
	}
	if heads != 5 {
		t.Fatalf("got %d category heads, want 5", heads)
	}
	if categoryNames != [5]string{
		"NETWORK & MONITOR", "SCANLTE SCAN", "TRAFFIC ENGINE", "GNULTE-WIFI", "TERMINAL & UI",
	} {
		t.Fatalf("category strings changed: %q", categoryNames)
	}
}

func TestSettingsTitlePagesAndFooter(t *testing.T) {
	e := newEditor(Default())
	frame := strings.Join(e.lines(110, 30), "\n")
	for _, want := range []string{settingsTitle, settingsSub, settingsPages, settingsFoot} {
		if !strings.Contains(frame, want) {
			t.Fatalf("frame missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, "v13") {
		t.Fatalf("frame still advertises v13")
	}
}

func TestSettingsLabelsAndHelpFixes(t *testing.T) {
	e := newEditor(Default())
	e.setPage(2)
	frame := strings.Join(e.lines(110, 30), "\n")
	if !strings.Contains(frame, "echo commands in sessions") {
		t.Fatal("command-echo row was not relabelled")
	}
	if strings.Contains(frame, "advanced mode (echo commands)") {
		t.Fatal("old command-echo label is still present")
	}

	wifi := findItem(t, e, "wifi frames per burst")
	if wifi.hint != valWifiCount || !strings.Contains(wifi.help, "1–256") {
		t.Fatalf("wifi frames help/range wrong: hint=%q help=%q", wifi.hint, wifi.help)
	}
	delay := findItem(t, e, "wifi delay between bursts (s)")
	if delay.hint != valSeconds || !strings.Contains(delay.help, "1–60") {
		t.Fatalf("wifi delay help/range wrong: hint=%q help=%q", delay.hint, delay.help)
	}
	echo := findItem(t, e, "echo commands in sessions")
	cfg := Default()
	cfg.Advanced = false
	if err := echo.set(&cfg, "on"); err != nil || !cfg.Advanced {
		t.Fatalf("relabelled row no longer toggles Advanced: err=%v cfg=%+v", err, cfg)
	}

	e.setPage(4)
	frame = strings.Join(e.lines(110, 30), "\n")
	for _, want := range []string{"typing animation", "Detailed controls in hub", "topology animation", "check for updates on startup"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("TERMINAL & UI page missing %q:\n%s", want, frame)
		}
	}
	updates := findItem(t, e, "check for updates on startup")
	cfg.AutoUpdate = false
	if err := updates.set(&cfg, "on"); err != nil || !cfg.AutoUpdate {
		t.Fatalf("startup update row no longer toggles AutoUpdate: err=%v cfg=%+v", err, cfg)
	}
}

func TestPageJumpsOnlyInNavigationMode(t *testing.T) {
	e := newEditor(Default())

	e.handleKey(tui.KeyRune, '2')
	if e.page != 1 || e.items[e.sel].label != "scan threads" {
		t.Fatalf("2 did not jump to SCANLTE SCAN: page=%d sel=%q", e.page, e.items[e.sel].label)
	}
	e.handleKey(tui.KeyRune, '5')
	if e.page != 4 || e.items[e.sel].label != "typing animation" {
		t.Fatalf("5 did not jump to TERMINAL & UI: page=%d sel=%q", e.page, e.items[e.sel].label)
	}

	selectLabel(t, e, "ping timeout (ms)")
	e.beginEdit()
	e.handleKey(tui.KeyRune, '2')
	if e.mode != modeValue || e.page != 0 || string(e.buf) != "2" {
		t.Fatalf("digit in edit mode changed state: mode=%d page=%d buf=%q", e.mode, e.page, string(e.buf))
	}
}

func TestTypedInputRejectedButJogClamps(t *testing.T) {
	e := newEditor(Default())
	selectLabel(t, e, "ping timeout (ms)")

	e.mode, e.buf = modeValue, []rune("2")
	e.handleKey(tui.KeyEnter, 0)
	if e.mode != modeValue || e.liveErr != valMillis || e.cfg.TimeoutMs != 1000 {
		t.Fatalf("out-of-range value was not held in edit mode: mode=%d err=%q timeout=%d", e.mode, e.liveErr, e.cfg.TimeoutMs)
	}
	e.handleKey(tui.KeyEsc, 0)
	if e.mode != modeNav {
		t.Fatal("Esc did not cancel the value")
	}

	e.cfg.TimeoutMs = 100
	e.handleKey(tui.KeyLeft, 0)
	if e.cfg.TimeoutMs != 100 || e.notice != "At minimum (100)" {
		t.Fatalf("left jog did not clamp with notice: timeout=%d notice=%q", e.cfg.TimeoutMs, e.notice)
	}

	e.mode, e.buf = modeValue, []rune("250")
	e.handleKey(tui.KeyEnter, 0)
	if e.mode != modeNav || e.cfg.TimeoutMs != 250 {
		t.Fatalf("valid value rejected: mode=%d timeout=%d", e.mode, e.cfg.TimeoutMs)
	}

	selectLabel(t, e, "scan threads")
	e.cfg.ScanThreads = 512
	e.handleKey(tui.KeyRight, 0)
	if e.cfg.ScanThreads != 512 || e.notice != "At maximum (512)" {
		t.Fatalf("right jog did not clamp with notice: threads=%d notice=%q", e.cfg.ScanThreads, e.notice)
	}
}

func TestDirtyChangedSaveAndDiscard(t *testing.T) {
	e := newEditor(Default())
	if e.changedCount() != 0 || strings.Contains(strings.Join(e.lines(110, 30), "\n"), "[unsaved:") {
		t.Fatal("a fresh editor should have no unsaved rows")
	}

	selectLabel(t, e, "ping history depth")
	it := e.items[e.sel]
	if err := it.set(&e.cfg, "120"); err != nil {
		t.Fatal(err)
	}
	frame := strings.Join(e.lines(110, 30), "\n")
	if !strings.Contains(frame, "[unsaved: 1]") || !strings.Contains(frame, "* changed (default 60)") {
		t.Fatalf("dirty markers missing:\n%s", frame)
	}

	saves := 0
	e.save = func(Config) error { saves++; return nil }
	e.handleKey(tui.KeyRune, 's')
	if saves != 1 || e.changedCount() != 0 || !e.saveOnExit {
		t.Fatalf("save did not clear dirty state: saves=%d dirty=%d saveOnExit=%v", saves, e.changedCount(), e.saveOnExit)
	}
	if got := e.helpLine(); got != fmt.Sprintf(savedFmt, Path()) {
		t.Fatalf("save message = %q, want %q", got, fmt.Sprintf(savedFmt, Path()))
	}

	if err := it.set(&e.cfg, "240"); err != nil {
		t.Fatal(err)
	}
	e.handleKey(tui.KeyRune, 'D')
	if e.mode != modeDiscard || e.helpLine() != discardAsk {
		t.Fatalf("D did not ask to discard: mode=%d line=%q", e.mode, e.helpLine())
	}
	e.handleKey(tui.KeyRune, 'n')
	if e.mode != modeNav || e.cfg.History != 240 || !e.saveOnExit {
		t.Fatalf("N did not cancel discard: mode=%d history=%d saveOnExit=%v", e.mode, e.cfg.History, e.saveOnExit)
	}
	e.handleKey(tui.KeyRune, 'D')
	if !e.handleKey(tui.KeyRune, 'y') || e.cfg != e.initial || e.cfg.History != 120 || e.saveOnExit {
		t.Fatalf("discard did not restore the saved state: cfg=%+v initial=%+v saveOnExit=%v", e.cfg, e.initial, e.saveOnExit)
	}

	clean := newEditor(Default())
	if !clean.handleKey(tui.KeyRune, 'D') || clean.mode != modeNav || clean.saveOnExit {
		t.Fatal("discard with no changes should exit without prompting or saving")
	}
	for _, key := range []struct {
		k tui.Key
		r rune
	}{{tui.KeyEsc, 0}, {tui.KeyRune, 'q'}, {tui.KeyRune, 'Q'}} {
		other := newEditor(Default())
		if !other.handleKey(key.k, key.r) || !other.saveOnExit {
			t.Fatalf("exit key %v/%q did not request a save", key.k, key.r)
		}
	}
}

// callerPersist mirrors the caller pattern after Edit: persist only when the
// returned save flag is true. A confirmed discard must never reach SaveTo.
func callerPersist(cfg Config, save bool, path string) error {
	if !save {
		return nil
	}
	return SaveTo(cfg, path)
}

func TestDiscardCallerPatternLeavesConfigFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	original := []byte("{\n  \"interface\": \"eth9\",\n  \"topology_animation\": false\n}\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}

	// Drive the real editor state machine instead of opening a PTY, then
	// emulate exactly what each caller does with Edit's (Config, bool, error).
	e := newEditor(cfg)
	selectLabel(t, e, "ping history depth")
	if err := e.items[e.sel].set(&e.cfg, "240"); err != nil {
		t.Fatal(err)
	}
	e.handleKey(tui.KeyRune, 'D')
	if !e.handleKey(tui.KeyRune, 'y') || e.saveOnExit {
		t.Fatalf("confirmed discard returned save=%v, want false", e.saveOnExit)
	}
	if err := callerPersist(e.cfg, e.saveOnExit, path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("discard rewrote config file:\n got %q\nwant %q", got, original)
	}

	// Sanity check: the same caller pattern does write when save is true.
	if err := callerPersist(e.cfg, true, path); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, original) {
		t.Fatal("caller pattern with save=true did not write the config file")
	}
}

func TestFilterAndChangedOnlyViews(t *testing.T) {
	e := newEditor(Default())
	e.setPage(4)
	e.handleKey(tui.KeyRune, '/')
	for _, r := range "topo" {
		e.handleKey(tui.KeyRune, r)
	}
	if e.mode != modeFilter || len(e.visibleRows()) != 1 {
		t.Fatalf("filter did not narrow TERMINAL & UI: mode=%d rows=%v", e.mode, e.visibleRows())
	}
	if got := e.items[e.sel].label; got != "topology animation" {
		t.Fatalf("filter selection = %q, want topology animation", got)
	}
	e.handleKey(tui.KeyEsc, 0)
	if e.filter != "" || e.mode != modeNav {
		t.Fatalf("Esc did not clear the filter: filter=%q mode=%d", e.filter, e.mode)
	}

	e.setPage(0)
	e.handleKey(tui.KeyRune, '/')
	for _, r := range "topo" {
		e.handleKey(tui.KeyRune, r)
	}
	if got := strings.Join(e.lines(110, 30), "\n"); !strings.Contains(got, fmt.Sprintf(noMatchFmt, "topo")) {
		t.Fatalf("no-match message missing:\n%s", got)
	}
	e.handleKey(tui.KeyEsc, 0)

	selectLabel(t, e, "ping history depth")
	_ = e.items[e.sel].set(&e.cfg, "120")
	e.handleKey(tui.KeyRune, 'c')
	rows := e.visibleRows()
	if len(rows) != 1 || e.items[rows[0]].label != "ping history depth" {
		t.Fatalf("changed-only view = %v, want only ping history depth", rows)
	}
	e.handleKey(tui.KeyRune, 'c')
	if len(e.visibleRows()) == 1 {
		t.Fatal("c did not toggle back to the full page")
	}
}
