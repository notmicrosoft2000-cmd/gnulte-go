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

// TestKeyStreamPollTimeout reports a key that never arrives without blocking.
func TestKeyStreamPollTimeout(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	k := newKeyStream(int(pr.Fd()))
	start := time.Now()
	if key, _ := k.poll(5); key != KeyNone {
		t.Fatalf("poll on empty pipe = %d, want KeyNone", key)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("poll blocked %.0fms, should have timed out in ~5ms", d.Seconds()*1000)
	}
}

// TestKeyStreamPollDecodesArrow checks that a key arriving during the poll
// window is decoded (and queued sequences still decode fully).
func TestKeyStreamPollDecodesArrow(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	k := newKeyStream(int(pr.Fd()))
	if _, err := pw.WriteString("\x1b[A\x1b[B"); err != nil {
		t.Fatal(err)
	}
	if key, _ := k.poll(200); key != KeyUp {
		t.Fatalf("first poll = %d, want KeyUp", key)
	}
	if key, _ := k.poll(200); key != KeyDown {
		t.Fatalf("second poll = %d, want KeyDown (arrow bytes lost across polls)", key)
	}
}

// TestKeyStreamPollLoneEsc resolves a lone Escape within its grace beat.
func TestKeyStreamPollLoneEsc(t *testing.T) {
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
	if key, _ := k.poll(500); key != KeyEsc {
		t.Fatalf("poll = %d, want KeyEsc", key)
	}
}
