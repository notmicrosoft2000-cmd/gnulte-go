// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import "testing"

// TestHopLabelWraps: a long hopping run keeps incrementing the index, so the
// label must wrap instead of indexing past the channel list (that panicked with
// "index out of range").
func TestHopLabelWraps(t *testing.T) {
	chans := []uint8{1, 6, 11}
	if got := hopLabel(chans, 0); got != "  · ch 1" {
		t.Errorf("hopLabel(0) = %q, want ch 1", got)
	}
	if got := hopLabel(chans, 4); got != "  · ch 6" { // 4 % 3 == 1
		t.Errorf("hopLabel(4) = %q, want ch 6", got)
	}
	if got := hopLabel(chans, 1_000_000); got != "  · ch 6" { // 1e6 % 3 == 1
		t.Errorf("hopLabel(1e6) = %q, want the wrapped ch 6", got)
	}
	if got := hopLabel(nil, 5); got != "" {
		t.Errorf("hopLabel(nil) = %q, want empty", got)
	}
}
