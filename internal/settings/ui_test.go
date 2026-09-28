package settings

import "testing"

// testItems builds a small categorized list mirroring the real editor shape:
// heads separating editable rows, with the same get/set helper wiring.
func testItems() []editItem {
	items := []editItem{
		{label: "HEAD A", kind: itemHead, head: true},
		{label: "a1", kind: itemBool,
			get: func(c Config) string { return boolText(c.Advanced) },
			set: func(c *Config, v string) error { return setBool(&c.Advanced, v) },
			def: boolText(true)},
		{label: "a2", kind: itemInt,
			get: func(c Config) string { return "10" },
			set: func(c *Config, v string) error { return nil },
			def: "10"},
		{label: "HEAD B", kind: itemHead, head: true},
		{label: "b1", kind: itemBool,
			get: func(c Config) string { return boolText(c.Typing) },
			set: func(c *Config, v string) error { return setBool(&c.Typing, v) },
			def: boolText(true)},
	}
	return items
}

func TestEditorStartsOnFirstValue(t *testing.T) {
	e := &editor{items: testItems()}
	e.sel = e.firstItem()
	if e.items[e.sel].head {
		t.Fatalf("firstItem landed on a header (index %d)", e.sel)
	}
	if e.items[e.sel].label != "a1" {
		t.Fatalf("firstItem = %q, want a1", e.items[e.sel].label)
	}
	if e.items[e.lastItem()].head {
		t.Fatalf("lastItem landed on a header (index %d)", e.lastItem())
	}
}

func TestEditorStepSkipsHeaders(t *testing.T) {
	e := &editor{items: testItems()}

	// Down from a1 → a2 (skips nothing yet).
	e.sel = 1
	e.sel = e.step(1)
	if e.items[e.sel].label != "a2" {
		t.Fatalf("down from a1 = %q, want a2", e.items[e.sel].label)
	}
	// Down from a2 → b1, jumping over "HEAD B".
	e.sel = e.step(1)
	if e.items[e.sel].label != "b1" {
		t.Fatalf("down from a2 = %q, want b1 (header skipped)", e.items[e.sel].label)
	}
	// Down from b1 wraps to a1, jumping over HEAD A and HEAD B.
	e.sel = e.step(1)
	if e.items[e.sel].label != "a1" {
		t.Fatalf("wrap from b1 = %q, want a1", e.items[e.sel].label)
	}
	// Up from a1 wraps to b1.
	e.sel = e.step(-1)
	if e.items[e.sel].label != "b1" {
		t.Fatalf("wrap up from a1 = %q, want b1", e.items[e.sel].label)
	}
}

func TestEditorResetAllSkipsHeaders(t *testing.T) {
	e := &editor{items: testItems(), cfg: Default()}
	e.cfg.Advanced = false
	e.cfg.Typing = false
	e.resetAll()
	if !e.cfg.Advanced || !e.cfg.Typing {
		t.Fatalf("resetAll did not restore bools: %+v", e.cfg)
	}
}

func TestEditorCategoryShape(t *testing.T) {
	// Every head row is inert: a real screen editor never toggles or edits it.
	for i, it := range testItems() {
		if it.head && (it.get != nil || it.set != nil) {
			t.Fatalf("head at %d has get/set wiring", i)
		}
	}
}
