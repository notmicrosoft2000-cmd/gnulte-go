package ux

import (
	"strings"
	"testing"
)

func TestStripAnsi(t *testing.T) {
	got := StripAnsi("\033[0;32m✓\033[0m \033[1;33m▲ +4\033[0m")
	want := "✓ ▲ +4"
	if got != want {
		t.Errorf("StripAnsi = %q, want %q", got, want)
	}
	if StripAnsi("plain") != "plain" {
		t.Error("plain text should pass through")
	}
}

func TestCaptureDropsRedraws(t *testing.T) {
	c := NewCapture()
	if _, err := c.Write([]byte("  #001 [12:00:00] ✓ 192.168.99.1  12ms  ttl=64\n")); err != nil {
		t.Fatal(err)
	}
	// A progress-frame redraw starts with \r and has no newline: it must not
	// pollute the transcript.
	if _, err := c.Write([]byte("\r  ⠋ scanning  [████] 5/10 · 2 live")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("\n  scan complete\n")); err != nil {
		t.Fatal(err)
	}
	lines := c.Lines()
	if len(lines) != 2 {
		t.Fatalf("captured %d lines, want 2: %#v", len(lines), lines)
	}
	if lines[0] != "#001 [12:00:00] ✓ 192.168.99.1  12ms  ttl=64" {
		t.Errorf("sample line mangled: %q", lines[0])
	}
	if lines[1] != "scan complete" {
		t.Errorf("final line mangled: %q", lines[1])
	}
}

func TestSplitPorts(t *testing.T) {
	got := SplitPorts("443,80, 53,,999999,0,abc")
	want := []int{443, 80, 53}
	if len(got) != len(want) {
		t.Fatalf("SplitPorts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SplitPorts[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestTrunc(t *testing.T) {
	if Trunc("hello", 10) != "hello" {
		t.Error("short string should be untouched")
	}
	if !strings.HasSuffix(Trunc("helloworld", 3), "…") {
		t.Errorf("long string should be ellipsized, got %q", Trunc("helloworld", 3))
	}
}

// TestTruncPadAnsi verifies CSI colour sequences are treated as invisible when
// measuring and padding, so full-frame table redraws keep their alignment.
// Tests normally run with tty=false (piped stdout), so the colour path is
// forced on and restored around the assertions.
func TestTruncPadAnsi(t *testing.T) {
	old := tty
	tty = true
	defer func() { tty = old }()
	cases := []struct {
		in, want string
		width    int
	}{
		{"\033[1;36m#\033[0m", "\033[1;36m#\033[0m   ", 4},
		{"\033[1;36mIP\033[0m", "\033[1;36mIP\033[0m             ", 15},
		{"\033[2mabcdef\033[0m", "\033[2mabcd\033[0m", 4},     // truncation re-applies reset
		{"\033[0;32m✓\033[0m ok", "\033[0;32m✓\033[0m ok", 4}, // multibyte + colour counting
	}
	for _, tc := range cases {
		if got := TruncPad(tc.in, tc.width); got != tc.want {
			t.Errorf("TruncPad(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
		}
	}
}

func TestTypeColorHues(t *testing.T) {
	for _, tc := range []struct {
		typ, code string
	}{
		{"Mobile", Magenta},
		{"Apple device", Cyan},
		{"Computer", Blue},
		{"Router/AP", Yellow},
		{"Router/Gateway", Yellow},
		{"Printer", Green},
		{"Roku", Red},
		{"Google Cast", Red},
		{"Camera/NVR", Red},
		{"Media/TV", Red},
		{"IoT (smart home)", Red},
		{"Raspberry Pi", Green},
		{"Device", Dim},
		{"", Dim},
	} {
		if got := TypeColor(tc.typ); got != tc.code {
			t.Errorf("TypeColor(%q) = %q, want %q", tc.typ, got, tc.code)
		}
	}
}

// TestHostHuesAreDistinctAndCycle pins the per-IP palette: eight hues, each
// distinct, wrapping for out-of-range and negative indexes.
func TestHostHuesAreDistinctAndCycle(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < NHostHues; i++ {
		h := Hue(i)
		if h == "" || h == Dim || h == Red {
			t.Fatalf("Hue(%d) = %q — palette must avoid the dim/red health colours", i, h)
		}
		if seen[h] {
			t.Fatalf("Hue(%d) repeats %q — hues must be distinct", i, h)
		}
		seen[h] = true
	}
	if Hue(0) != Hue(NHostHues) || Hue(0) != Hue(-NHostHues) {
		t.Fatalf("Hue must cycle: Hue(0)=%q Hue(N)=%q Hue(-N)=%q", Hue(0), Hue(NHostHues), Hue(-NHostHues))
	}
}

func TestDeviceIPCode(t *testing.T) {
	if got := DeviceIPCode(true, "Phone"); got != Header {
		t.Errorf("self host should be Header, got %q", got)
	}
	if got := DeviceIPCode(false, "Router/Gateway"); got != Target {
		t.Errorf("gateway should be Target, got %q", got)
	}
	if got := DeviceIPCode(false, "Mobile"); got != Magenta {
		t.Errorf("mobile should be Magenta, got %q", got)
	}
	if got := DeviceIPCode(false, "Computer"); got != Blue {
		t.Errorf("computer should be Blue, got %q", got)
	}
}
