// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"strings"
	"testing"
)

// The 1<<40 branch used to be a copy of the 1<<30 branch: it divided by 1<<40
// (TiB) but labelled the result GiB, so a 1.5 TiB session printed "1.5 GiB".
func TestHumanBytesUnitLadder(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{512, "512 B"},
		{2 << 10, "2.0 KiB"},
		{3 << 20, "3.0 MiB"},
		{4 << 30, "4.0 GiB"},
		{5 << 40, "5.0 TiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func clip(s string) string {
	if len(s) > 240 {
		return s[:240]
	}
	return s
}

// The card title was composed as markup and then passed through htmlEscape a
// second time, so every host with a resolved hostname (the normal case) showed
// the literal text "<span class=dim>(192.168.x.y)</span>" in its heading.
func TestCardHTMLTitleIsNotDoubleEscaped(t *testing.T) {
	inf := hostInfo{IP: "192.0.2.10", Host: "nas", Type: "NAS"}
	html := cardHTML(inf.IP, inf, &hostStat{}, nil, 1)
	if strings.Contains(html, "&lt;span") {
		t.Errorf("card title contains escaped markup (double-escaped):\n%s", clip(html))
	}
	if !strings.Contains(html, "<h3>nas <span class=dim>(192.0.2.10)</span>") {
		t.Errorf("card title missing expected hostname heading, got:\n%s", clip(html))
	}
}
