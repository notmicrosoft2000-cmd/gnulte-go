// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package monitor

import (
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
)

func TestRateTextRateFormats(t *testing.T) {
	if got := rateTextRate(traffic.Rate{}); got != "↓0 ↑0" {
		t.Errorf("zero rate = %q, want ↓0 ↑0", got)
	}
	got := rateTextRate(traffic.Rate{RXBytes: 2048, TXBytes: 1024})
	if !strings.HasPrefix(got, "↓") || !strings.Contains(got, "↑") {
		t.Errorf("rate text = %q, want a down and an up figure", got)
	}
}

// fakeTraffic stands in for the live counter and counts Snapshot calls.
type fakeTraffic struct {
	calls int
	rates map[string]traffic.Rate
}

func (f *fakeTraffic) Snapshot() map[string]traffic.Rate {
	f.calls++
	return f.rates
}

func (f *fakeTraffic) Close() {}

// TestDashboardTakesOneTrafficSnapshot: Snapshot advances the counter's
// previous-totals baseline, so the dashboard must take exactly one per frame
// and format every host from it. The old code called Snapshot once per host
// (via rateText), which zeroed every host after the first.
func TestDashboardTakesOneTrafficSnapshot(t *testing.T) {
	f := &fakeTraffic{rates: map[string]traffic.Rate{"10.0.0.1": {RXBytes: 100}}}
	m := &Monitor{Targets: []string{"10.0.0.1", "10.0.0.2"}, Traffic: f}
	stats := []*Stats{{}, {}}
	m.renderDashboard(stats, []string{"", ""}, false, false)
	if f.calls != 1 {
		t.Fatalf("dashboard took %d traffic snapshots, want exactly 1", f.calls)
	}
}

// TestScaleRate: a delta measured over secs is rescaled to a per-second value;
// unit and non-positive intervals are a no-op.
func TestScaleRate(t *testing.T) {
	r := traffic.Rate{RXBytes: 1000, TXBytes: 500, RXPkts: 10, TXPkts: 5}
	if got := scaleRate(r, 1); got != r {
		t.Errorf("scaleRate(1) = %+v, want unchanged", got)
	}
	if got := scaleRate(r, 0); got != r {
		t.Errorf("scaleRate(0) = %+v, want unchanged", got)
	}
	half := scaleRate(r, 2)
	if half.RXBytes != 500 || half.TXBytes != 250 || half.RXPkts != 5 || half.TXPkts != 3 {
		t.Errorf("scaleRate(2) = %+v, want RX/TX 500/250 and pkts 5/3", half)
	}
	if got := scaleRate(r, 0.5); got.RXBytes != 2000 {
		t.Errorf("scaleRate(0.5).RXBytes = %d, want 2000", got.RXBytes)
	}
}

// TestRateTextScalesByRealElapsed: the counter reports a delta per Snapshot, so
// "B/s" is only honest when calls are one second apart. Single-target mode
// samples at the operator's --interval, so rateText must rescale by the wall
// time actually elapsed (here: a 4KB delta over two seconds is 2KB/s).
func TestRateTextScalesByRealElapsed(t *testing.T) {
	f := &fakeTraffic{rates: map[string]traffic.Rate{"10.0.0.1": {RXBytes: 4096}}}
	m := &Monitor{Traffic: f}
	m.lastRate = time.Now().Add(-2 * time.Second)
	if got := m.rateText("10.0.0.1"); got != "↓2.0KB/s" {
		t.Fatalf("rate over 2s = %q, want the delta halved to ↓2.0KB/s", got)
	}
}
