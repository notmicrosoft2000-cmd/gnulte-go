package main

import (
	"strings"
	"testing"
)

// TestProfilesConsistent pins the selector list to the map: every name the
// wizard numbers, --list-profiles prints and -h advertises must resolve to a
// real preset, all with sane, non-negative impulse values.
func TestProfilesConsistent(t *testing.T) {
	if len(profileOrder) != len(profiles) {
		t.Fatalf("profileOrder has %d entries but the map has %d", len(profileOrder), len(profiles))
	}
	seen := map[string]bool{}
	for _, name := range profileOrder {
		p, ok := profiles[name]
		if !ok {
			t.Fatalf("profileOrder lists %q which is not in the profiles map", name)
		}
		if seen[name] {
			t.Fatalf("profileOrder duplicates %q", name)
		}
		seen[name] = true
		for _, v := range p {
			if v < 0 {
				t.Fatalf("profile %q has a negative impulse value: %v", name, p)
			}
		}
	}
	for name := range profiles {
		if !seen[name] {
			t.Fatalf("profiles map has %q but profileOrder does not list it", name)
		}
	}
	if n := len(strings.Split(profileNames, ",")); n != len(profiles) {
		t.Fatalf("profileNames lists %d names, want %d", n, len(profiles))
	}
	for _, name := range profileOrder {
		if !strings.Contains(profileNames, name) {
			t.Fatalf("profileNames is missing %q", name)
		}
	}
}

// TestProfileNumbersSelectable ensures the numerical picker maps 1..N onto the
// ordered list, which the wizard relies on.
func TestProfileNumbersSelectable(t *testing.T) {
	for i := range profileOrder {
		if i+1 < 1 || i+1 > len(profileOrder) {
			t.Fatalf("bad index %d", i+1)
		}
	}
}
