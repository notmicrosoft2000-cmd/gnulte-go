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

// TestKeyStreamReadsOneByteAtATime stops a menu from consuming a key that
// belongs to the next screen or child process. A queued digit must still be
// pending after an arrow is decoded.
func TestKeyStreamReadsOneByteAtATime(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	k := newKeyStream(int(pr.Fd()))
	if _, err := pw.WriteString("\x1b[B3"); err != nil {
		t.Fatal(err)
	}
	if key, _ := k.read(); key != KeyDown {
		t.Fatalf("first key = %d, want KeyDown", key)
	}
	if len(k.pending) != 0 {
		t.Fatalf("pending = %q, want no read-ahead past the arrow", k.pending)
	}
	if key, r := k.read(); key != KeyRune || r != '3' {
		t.Fatalf("second key = (%d, %q), want KeyRune '3'", key, r)
	}
}

// TestFlushPendingDropsPartialKey checks that a stray arrow prefix cannot be
// mistaken for the first key of a child process or a canonical-mode prompt.
func TestFlushPendingDropsPartialKey(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	k := newKeyStream(int(pr.Fd()))
	k.pending = []byte("\x1b[")
	k.flushPending()
	if len(k.pending) != 0 {
		t.Fatalf("flushPending left %q behind", k.pending)
	}
	if _, err := pw.WriteString("3"); err != nil {
		t.Fatal(err)
	}
	if key, r := k.read(); key != KeyRune || r != '3' {
		t.Fatalf("key after flush = (%d, %q), want KeyRune '3'", key, r)
	}

	// The exported handoff helper reaches the same shared stream.
	sharedKeys.pending = []byte{'\x1b'}
	FlushPending()
	if len(sharedKeys.pending) != 0 {
		t.Fatalf("FlushPending left %q behind", sharedKeys.pending)
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
