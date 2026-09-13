// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

//go:build !linux

package monitor

// enableKeyboard is a no-op off Linux: selection stays at the first target.
func enableKeyboard(targets int, sel *int32) func() {
	return func() {}
}
