package tui

import (
	"strings"
	"testing"

	"gnulte-go/internal/ux"
)

func TestParseKey(t *testing.T) {
	cases := []struct {
		in   []byte
		key  Key
		r    rune
		more bool
	}{
		{[]byte{'\r'}, KeyEnter, 0, false},
		{[]byte{'\n'}, KeyEnter, 0, false},
		{[]byte{'a'}, KeyRune, 'a', false},
		{[]byte{' '}, KeySpace, 0, false},
		{[]byte{'\t'}, KeyTab, 0, false},
		{[]byte{0x7f}, KeyBackspace, 0, false},
		{[]byte{0x08}, KeyBackspace, 0, false},
		{[]byte{0x1b}, KeyNone, 0, true},
		{[]byte{0x1b, '['}, KeyNone, 0, true},
		{[]byte{0x1b, '[', 'A'}, KeyUp, 0, false},
		{[]byte{0x1b, '[', 'B'}, KeyDown, 0, false},
		{[]byte{0x1b, '[', 'C'}, KeyRight, 0, false},
		{[]byte{0x1b, '[', 'D'}, KeyLeft, 0, false},
		{[]byte{0x1b, 'O', 'A'}, KeyUp, 0, false},
		{[]byte{0x1b, 'O', 'B'}, KeyDown, 0, false},
		{[]byte{0x1b, 'x'}, KeyEsc, 0, false},
		{[]byte{'3', '4'}, KeyRune, '3', false},
	}
	for _, tc := range cases {
		k, r, _, more := parseKey(tc.in)
		if k != tc.key || r != tc.r || more != tc.more {
			t.Errorf("parseKey(%q) = (%d,%q,%v), want (%d,%q,%v)",
				tc.in, k, r, more, tc.key, tc.r, tc.more)
		}
	}
}

func TestFramePadsAndHomes(t *testing.T) {
	f := Frame(20, []string{"alpha", "beta"})
	if !strings.HasPrefix(f, "\033[H") {
		t.Fatalf("frame must home the cursor, got %q", f)
	}
	if !strings.HasSuffix(f, "\033[J") {
		t.Fatalf("frame must clear below, got %q", f)
	}
	if !strings.Contains(f, "alpha"+strings.Repeat(" ", 15)) {
		t.Fatalf("first line not padded to width: %q", f)
	}
	if strings.Count(f, "\r\n") != 2 {
		t.Fatalf("expected two lines, got %q", f)
	}
}

func TestFrameTruncatesLongLines(t *testing.T) {
	f := Frame(8, []string{"012345678901234567890"})
	if strings.Count(f, "0") > 8 {
		t.Fatalf("long line was not truncated, got %q", f)
	}
}

func TestTruncPadColourReset(t *testing.T) {
	// A coloured line that overflows must not leak its tint into the next row.
	colored := "\x1b[1;33mlong-amber-line-here"
	s := ux.TruncPad(colored, 8)
	if !strings.Contains(s, ux.Reset) {
		t.Fatalf("truncated coloured line did not restore the palette: %q", s)
	}
	if len([]rune(ux.TruncPad("no-escape", 0))) != len([]rune("no-escape")) {
		t.Fatalf("zero/negative width must leave the string untouched")
	}
	if ux.TruncPad("x", 5) != "x    " {
		t.Fatalf("padding failed: %q", ux.TruncPad("x", 5))
	}
}
