// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package monitor

import "testing"

// TestProcessKeysLoneEscapeDoesNotSpin: a lone ESC (or a partial CSI split
// across reads) must be returned untouched, not re-examined in place forever.
// The old inner loop used a bare `break` inside a switch, which left the byte
// in `pending` and spun the reader at 100% CPU.
func TestProcessKeysLoneEscapeDoesNotSpin(t *testing.T) {
	var sel int32
	rest := processKeys([]byte{0x1b}, &sel, 3)
	if len(rest) != 1 || rest[0] != 0x1b {
		t.Fatalf("lone ESC tail = %v, want [27]", rest)
	}
	// A partial "ESC [" is held back too.
	rest = processKeys(append(rest, '['), &sel, 3)
	if len(rest) != 2 {
		t.Fatalf("partial CSI tail = %v, want 2 bytes", rest)
	}
	// Completing it moves the selection and drains the buffer.
	rest = processKeys(append(rest, 'A'), &sel, 3)
	if len(rest) != 0 {
		t.Fatalf("completed sequence left %v", rest)
	}
	if sel != 2 { // up from 0 wraps to n-1
		t.Fatalf("arrow-up moved sel to %d, want 2", sel)
	}
}

func TestProcessKeysArrowsAndVim(t *testing.T) {
	var sel int32
	processKeys([]byte{'j'}, &sel, 3)
	if sel != 1 {
		t.Fatalf("j moved to %d, want 1", sel)
	}
	processKeys([]byte{0x1b, '[', 'B'}, &sel, 3)
	if sel != 2 {
		t.Fatalf("down arrow moved to %d, want 2", sel)
	}
	processKeys([]byte{'k'}, &sel, 3)
	if sel != 1 {
		t.Fatalf("k moved to %d, want 1", sel)
	}
}

// An ESC followed by a non-sequence byte must drop the ESC and still process
// the byte (and possible later keys), not swallow or re-loop on it.
func TestProcessKeysEscThenKey(t *testing.T) {
	var sel int32
	rest := processKeys([]byte{0x1b, 'j'}, &sel, 3)
	if len(rest) != 0 || sel != 1 {
		t.Fatalf("ESC j => tail %v sel %d, want empty/1", rest, sel)
	}
	// Unknown bytes are dropped without disturbing the selection.
	var kept int32
	if rest := processKeys([]byte{0x1b, 'x', 0x00}, &kept, 3); len(rest) != 0 || kept != 0 {
		t.Fatalf("ESC x NUL => tail %v sel %d, want empty/0", rest, kept)
	}
}
