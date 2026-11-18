// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.

package airframes

import (
	"strings"
	"testing"
)

func TestParseReasonNumeric(t *testing.T) {
	code, name, err := ParseReason("7")
	if err != nil || code != 7 || name != "leaving" {
		t.Fatalf("ParseReason(7) = %d,%q,%v", code, name, err)
	}
	// An unnamed numeric code is still accepted, with no friendly name.
	code, name, err = ParseReason("42")
	if err != nil || code != 42 || name != "" {
		t.Fatalf("ParseReason(42) = %d,%q,%v", code, name, err)
	}
	if _, _, err := ParseReason("70000"); err == nil {
		t.Error("out-of-range code should fail")
	}
}

func TestParseReasonNamesAndAliases(t *testing.T) {
	cases := map[string]uint16{
		"leaving":        7,
		"LEAVING":        7,
		"  inactivity  ": 4,
		"handshake":      23,
		"left":           7,
		"4way":           23,
		"auth-invalid":   2,
	}
	for in, want := range cases {
		code, name, err := ParseReason(in)
		if err != nil || code != want || name == "" {
			t.Errorf("ParseReason(%q) = %d,%q,%v; want code %d and a name", in, code, name, err, want)
		}
	}
	if _, _, err := ParseReason("nonsense"); err == nil {
		t.Error("unknown name should fail")
	} else if !strings.Contains(err.Error(), "leaving") {
		t.Errorf("error should list valid names: %v", err)
	}
}

func TestFormatReason(t *testing.T) {
	if got := FormatReason(7); got != "7 (leaving)" {
		t.Errorf("FormatReason(7) = %q", got)
	}
	if got := FormatReason(99); got != "99" {
		t.Errorf("FormatReason(99) = %q", got)
	}
	if got := ReasonName(99); got != "" {
		t.Errorf("ReasonName(99) = %q", got)
	}
}

func TestReasonPresetsStable(t *testing.T) {
	p := ReasonPresets()
	if len(p) < 5 {
		t.Fatalf("only %d presets", len(p))
	}
	for i := 1; i < len(p); i++ {
		if p[i-1].Code >= p[i].Code {
			t.Errorf("presets not in code order: %d then %d", p[i-1].Code, p[i].Code)
		}
	}
}
