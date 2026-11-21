package tui

import (
	"strings"
	"testing"
)

func TestParseMenuChoice(t *testing.T) {
	for _, tc := range []struct {
		answer string
		count  int
		want   int
		ok     bool
	}{
		{"1", 4, 0, true},
		{" 4 ", 4, 3, true},
		{"5", 4, -1, false},
		{"0", 4, -1, false},
		{"q", 4, -1, false},
		{"", 4, -1, false},
	} {
		got, ok := ParseMenuChoice(tc.answer, tc.count)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseMenuChoice(%q, %d) = (%d, %v), want (%d, %v)", tc.answer, tc.count, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMenuFrameWithContextNoteFooter(t *testing.T) {
	items := []MenuItem{
		{Label: "First", Detail: "one"},
		{Label: "Second", Detail: "two"},
	}
	opts := MenuOptions{
		Context:  []string{"First context line", "Second context line"},
		Note:     "A note below the list",
		Footer:   "custom keys",
		Selected: 1,
	}
	frame := MenuFrameWith("A title", items, opts.Selected, opts)
	joined := strings.Join(frame, "\n")
	for _, want := range []string{
		"A title", "First context line", "Second context line",
		"First", "Second", "A note below the list", "custom keys", "▸ 2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("frame is missing %q: %q", want, joined)
		}
	}
	if strings.Contains(joined, defaultMenuFooter) {
		t.Errorf("custom footer did not replace the default: %q", joined)
	}
	titleAt := strings.Index(joined, "A title")
	contextAt := strings.Index(joined, "First context line")
	rowAt := strings.Index(joined, "1  First")
	noteAt := strings.Index(joined, "A note below the list")
	footerAt := strings.Index(joined, "custom keys")
	if !(titleAt < contextAt && contextAt < rowAt && rowAt < noteAt && noteAt < footerAt) {
		t.Errorf("frame copy is out of order: %q", joined)
	}
	// title, rule, two context lines, blank, rows, blank, note, footer, blank
	if want := len(items) + 9; len(frame) != want {
		t.Errorf("frame has %d lines, want %d: %q", len(frame), want, joined)
	}
}

func TestMenuFrame(t *testing.T) {
	items := []MenuItem{
		{Label: "Slow down a device", Detail: "pick a device"},
		{Label: "Block a device", Detail: "cut its network"},
		{Label: "Quit"},
	}
	frame := MenuFrame("What now?", items, 1)
	joined := strings.Join(frame, "\n")
	if !strings.Contains(joined, "What now?") {
		t.Fatalf("frame is missing its title: %q", joined)
	}
	for _, label := range []string{"Slow down a device", "Block a device", "Quit"} {
		if !strings.Contains(joined, label) {
			t.Errorf("frame is missing %q", label)
		}
	}
	if !strings.Contains(joined, "▸ 2") {
		t.Errorf("frame does not mark the selected row: %q", joined)
	}
	if len(frame) != len(items)+6 {
		t.Errorf("frame has %d lines, want %d", len(frame), len(items)+6)
	}
}
