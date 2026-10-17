// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package sound

import "testing"

// TestIsAplayUsesBaseName: isAplay decides whether the player gets the
// aplay-only "-q" flag. A path that merely *ends* in "aplay" (e.g.
// "not-aplay") is a different program and must not be mistaken for it.
func TestIsAplayUsesBaseName(t *testing.T) {
	for _, p := range []string{"aplay", "/usr/bin/aplay", "/usr/local/bin/aplay"} {
		if !isAplay(p) {
			t.Errorf("isAplay(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"paplay", "/usr/bin/paplay", "/opt/not-aplay", "/opt/my-aplay", "play", ""} {
		if isAplay(p) {
			t.Errorf("isAplay(%q) = true, want false", p)
		}
	}
}
