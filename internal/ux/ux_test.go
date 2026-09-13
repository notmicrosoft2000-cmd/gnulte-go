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
