package main

import "testing"

func TestSimpleProfileForIndex(t *testing.T) {
	for _, tc := range []struct {
		index int
		want  string
	}{
		{0, "cellular"},
		{1, "voip"},
		{2, "web"},
		{3, "extreme"},
		{4, ""},
		{99, ""},
	} {
		if got := simpleProfileForIndex(tc.index); got != tc.want {
			t.Errorf("simpleProfileForIndex(%d) = %q, want %q", tc.index, got, tc.want)
		}
	}
	for _, name := range []string{"cellular", "voip", "web", "extreme"} {
		if _, ok := profiles[name]; !ok {
			t.Errorf("simple menu maps to unknown profile %q", name)
		}
	}
}
