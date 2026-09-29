package scanner

import (
	"strings"
	"testing"

	"gnulte-go/internal/discover"
)

func row(ip, mac, vendor, typ, host string) discover.Row {
	return discover.Row{IP: ip, MAC: mac, Vendor: vendor, Type: typ, Hostname: host}
}

func TestDiffLifecycle(t *testing.T) {
	prev := []discover.Row{
		row("10.0.0.1", "aa:1", "RouterCo", "Router/Gateway", "gateway"),
		row("10.0.0.2", "aa:2", "ACME", "Phone", "phone"),
		row("10.0.0.3", "aa:3", "ACME", "Desktop", "gone-host"), // will disappear
	}
	next := []discover.Row{
		row("10.0.0.1", "aa:1", "RouterCo", "Router/Gateway", "gateway"), // same → ALIVE
		row("10.0.0.2", "aa:2", "ACME", "Phone", "renamed"),               // host moved → CHANGED
		row("10.0.0.9", "aa:9", "Tesla", "Car", "model-s"),                // brand new
	}
	d := Diff(prev, next)
	if got := d["10.0.0.1"]; got != DeltaAlive {
		t.Errorf("10.0.0.1 = %v, want ALIVE", got)
	}
	if got := d["10.0.0.2"]; got != DeltaChanged {
		t.Errorf("10.0.0.2 = %v, want CHANGED", got)
	}
	if got := d["10.0.0.3"]; got != DeltaGone {
		t.Errorf("10.0.0.3 = %v, want GONE", got)
	}
	if got := d["10.0.0.9"]; got != DeltaNew {
		t.Errorf("10.0.0.9 = %v, want NEW", got)
	}
	if len(d) != 4 {
		t.Errorf("delta has %d entries, want 4", len(d))
	}
}

func TestDiffChangedMAC(t *testing.T) {
	prev := []discover.Row{row("10.0.0.5", "aa:5", "ACME", "Phone", "p")}
	next := []discover.Row{row("10.0.0.5", "bb:5", "ACME", "Phone", "p")}
	if got := Diff(prev, next)["10.0.0.5"]; got != DeltaChanged {
		t.Errorf("MAC swap = %v, want CHANGED", got)
	}
}

func TestDiffSummaryAndLines(t *testing.T) {
	d := Delta{
		"10.0.0.1": DeltaAlive,
		"10.0.0.2": DeltaNew,
		"10.0.0.3": DeltaGone,
		"10.0.0.4": DeltaChanged,
	}
	if s := d.Summary(); s != "Δ 1 new · 1 gone · 1 changed" {
		t.Errorf("Summary: %q", s)
	}
	lines := d.Lines()
	if len(lines) != 4 {
		t.Fatalf("Lines has %d entries, want 4", len(lines))
	}
	// Lines sort by IP: .1 alive, .2 new, .3 gone, .4 changed.
	if !strings.Contains(lines[0], "· ALIVE") || !strings.Contains(lines[1], "▲ NEW") ||
		!strings.Contains(lines[2], "▼ GONE") || !strings.Contains(lines[3], "~ CHANGED") {
		t.Errorf("lines not ordered/formed: %q", lines)
	}
}

func TestDeltaEmpty(t *testing.T) {
	var d Delta
	if s := d.Summary(); s != "no change" {
		t.Errorf("empty summary: %q", s)
	}
	if got := len(Diff(nil, nil)); got != 0 {
		t.Errorf("nil diff = %d entries, want 0", got)
	}
}

func TestMarkStability(t *testing.T) {
	want := map[DeltaStatus]string{DeltaAlive: "·", DeltaNew: "▲", DeltaGone: "▼", DeltaChanged: "~"}
	for s, m := range want {
		if s.Mark() != m {
			t.Errorf("Mark(%v) = %q, want %q", s, s.Mark(), m)
		}
	}
}

func TestDeltaChangesNarrowsToMovement(t *testing.T) {
	d := Delta{
		"10.0.0.1": DeltaAlive,
		"10.0.0.2": DeltaNew,
		"10.0.0.3": DeltaGone,
		"10.0.0.4": DeltaChanged,
	}
	ch := d.Changes()
	if len(ch) != 3 {
		t.Fatalf("Changes = %d lines, want 3 (alive filtered)\n%q", len(ch), ch)
	}
	for _, ln := range ch {
		if strings.HasPrefix(ln, "·") {
			t.Errorf("alive line leaked into Changes: %q", ln)
		}
	}
}