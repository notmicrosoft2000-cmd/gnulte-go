// GNULTE — network testing toolkit (Go).
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL v3.

package main

import "testing"

func TestMatchAnySubstringCaseInsensitive(t *testing.T) {
	cases := []struct {
		actual string
		want   []string
		ok     bool
	}{
		{"Phone", []string{}, true},
		{"Xiaomi Communications Co. Ltd", []string{"phone"}, false},
		{"Phone", []string{"phone"}, true},
		{"Printer, e.g. office", []string{"printer"}, true},
		{"Raspberry Pi", []string{"pi"}, true},
		{"Router", []string{"phone", "router"}, true},
		{"Mobile Device", []string{"mobile"}, true},
		{"Frontiir Co. Ltd.", []string{"frontiir"}, true},
		{"Frontiir Co. Ltd.", []string{"xiaomi", "frontiir"}, true},
		{"Frontiir Co. Ltd.", []string{"", "xiaomi"}, false},
	}
	for _, c := range cases {
		if got := matchAny(c.actual, c.want); got != c.ok {
			t.Errorf("matchAny(%q, %v) = %v, want %v", c.actual, c.want, got, c.ok)
		}
	}
}
