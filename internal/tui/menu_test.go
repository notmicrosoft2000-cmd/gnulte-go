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
