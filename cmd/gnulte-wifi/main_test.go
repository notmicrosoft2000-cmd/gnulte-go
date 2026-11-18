// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"testing"

	"gnulte-go/internal/airframes"
)

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

// TestFormatStations: the target list shown in notices must name every station
// and keep the readable broadcast label.
func TestFormatStations(t *testing.T) {
	bc := mustMAC(t, airframes.Broadcast)
	if got := formatStations([]airframes.MAC{bc}); got != "broadcast (all clients)" {
		t.Errorf("broadcast label = %q", got)
	}
	two := []airframes.MAC{
		mustMAC(t, "00:0c:41:63:45:6a"),
		mustMAC(t, "aa:bb:cc:dd:ee:ff"),
	}
	if got := formatStations(two); got != "00:0c:41:63:45:6a, aa:bb:cc:dd:ee:ff" {
		t.Errorf("station list = %q", got)
	}
}

// TestDefaultReasonPreset: the default --reason string must still resolve to
// the station-leaving code after the switch from int to name-or-number.
func TestDefaultReasonPreset(t *testing.T) {
	code, name, err := airframes.ParseReason("7")
	if err != nil || code != 7 || name != "leaving" {
		t.Fatalf("default reason = %d,%q,%v; want 7,leaving", code, name, err)
	}
	for _, preset := range []string{"leaving", "inactivity", "handshake"} {
		if _, _, err := airframes.ParseReason(preset); err != nil {
			t.Errorf("documented preset %q does not parse: %v", preset, err)
		}
	}
}
