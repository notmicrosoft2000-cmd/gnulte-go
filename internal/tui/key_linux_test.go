//go:build linux

package tui

import (
	"os"
	"testing"
	"time"
)

// TestKeyStreamBuffersQueuedKeys writes several keypresses into a pipe in one
// burst and checks they are all decoded in order (a dropped queued arrow regressed the editor).
func TestKeyStreamBuffersQueuedKeys(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	k := newKeyStream(int(pr.Fd()))

	if _, err := pw.WriteString("\x1b[B\x1b[B"); err != nil {
		t.Fatal(err)
	}
	if key, _ := k.read(); key != KeyDown {
		t.Fatalf("first key = %d, want KeyDown", key)
	}
	if key, _ := k.read(); key != KeyDown {
		t.Fatalf("second key = %d, want KeyDown (queued bytes were lost)", key)
	}
}

// TestKeyStreamLoneEsc ensures a lone Escape is reported after its grace pause.
func TestKeyStreamLoneEsc(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	k := newKeyStream(int(pr.Fd()))
	if _, err := pw.WriteString("\x1b"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	key, _ := k.read()
	if key != KeyEsc {
		t.Fatalf("key = %d, want KeyEsc", key)
	}
	if d := time.Since(start); d > 1*time.Second {
		t.Fatalf("lone ESC took %.0fms to decode, should be ~40ms", d.Seconds()*1000)
	}
}
