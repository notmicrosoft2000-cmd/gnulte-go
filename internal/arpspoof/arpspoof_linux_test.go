// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

//go:build linux

package arpspoof

import "testing"

func TestIsLocal(t *testing.T) {
	sp := &Spoofer{ourMAC: mac("aa:aa:aa:aa:aa:aa")}
	if !sp.IsLocal(mac("aa:aa:aa:aa:aa:aa")) {
		t.Error("own MAC must be local")
	}
	if sp.IsLocal(mac("bb:bb:bb:bb:bb:bb")) {
		t.Error("foreign MAC must not be local")
	}
}
