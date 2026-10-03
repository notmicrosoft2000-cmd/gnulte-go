// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "watch-history.jsonl")
	ts := "2026-10-03T10:00:00Z"
	want := []Entry{
		{Kind: KindUp, TS: ts, IP: "10.0.0.5", Name: "laptop"},
		{Kind: KindSnapshot, TS: ts, IP: "10.0.0.5", AvgMS: 42, P95MS: 70, UpSec: 600, Loss: 1.5},
	}
	for _, e := range want {
		if err := Append(path, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Load returned %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLoadSkipsCorruptAndMissing(t *testing.T) {
	if got, err := Load(filepath.Join(t.TempDir(), "nope.jsonl")); err != nil || got != nil {
		t.Fatalf("Load(missing) = %v, %v; want nil, nil", got, err)
	}
	path := filepath.Join(t.TempDir(), "w.jsonl")
	body := "\n" +
		`{"kind":"up","ts":"2026-10-03T10:00:00Z","ip":"10.0.0.1"}` + "\n" +
		`{this is not json` + "\n" +
		`{"kind":"down","ts":"2026-10-03T10:01:00Z"}` + "\n" + // no ip → skipped
		`{"kind":"down","ts":"2026-10-03T10:02:00Z","ip":"10.0.0.1"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 || got[0].Kind != KindUp || got[1].Kind != KindDown {
		t.Fatalf("Load = %+v, want the two valid records", got)
	}
}

func TestPathHonoursXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	if got := Path(); got != "/tmp/xdg-test/gnulte-go/watch-history.jsonl" {
		t.Fatalf("Path = %q", got)
	}
}

func TestWindowAndOnDay(t *testing.T) {
	day := time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)
	mk := func(h int, d int) Entry {
		ts := time.Date(2026, 10, d, h, 0, 0, 0, time.Local).Format(time.RFC3339)
		return Entry{Kind: KindUp, TS: ts, IP: "10.0.0.1"}
	}
	entries := []Entry{mk(9, 2), mk(9, 3), mk(15, 3), {Kind: KindUp, TS: "garbage", IP: "10.0.0.1"}}

	if got := OnDay(entries, day); len(got) != 2 {
		t.Fatalf("OnDay = %d entries, want 2", len(got))
	}
	since := time.Date(2026, 10, 3, 0, 0, 0, 0, time.Local)
	if got := Window(entries, since, day.Add(24*time.Hour)); len(got) != 2 {
		t.Fatalf("Window = %d entries, want 2", len(got))
	}
	// An entry outside the window is dropped.
	before := time.Date(2026, 10, 3, 16, 0, 0, 0, time.Local)
	if got := Window(entries, before, day.Add(24*time.Hour)); len(got) != 0 {
		t.Fatalf("Window(after 16:00) = %d entries, want 0", len(got))
	}
}

func TestDailyAggregates(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)
	at := func(_ string, d, h int) string {
		return time.Date(2026, 10, d, h, 0, 0, 0, time.Local).Format(time.RFC3339)
	}
	entries := []Entry{
		{Kind: KindSnapshot, TS: at("a", 1, 10), IP: "a", AvgMS: 40, P95MS: 60, UpSec: 3600, Loss: 1},
		{Kind: KindSnapshot, TS: at("a", 1, 18), IP: "a", AvgMS: 60, P95MS: 80, UpSec: 1800, Loss: 3},
		{Kind: KindSnapshot, TS: at("a", 2, 10), IP: "a", AvgMS: 50, P95MS: 55, UpSec: 7200, Loss: 0},
		{Kind: KindDown, TS: at("a", 2, 11), IP: "a"},
		{Kind: KindSnapshot, TS: at("a", 3, 10), IP: "a", AvgMS: 30, P95MS: 35, UpSec: 3600, Loss: 2},
		// Later today than `now`: must be ignored, not folded into today.
		{Kind: KindSnapshot, TS: at("a", 3, 18), IP: "a", AvgMS: 999, P95MS: 999, UpSec: 1},
		{Kind: KindSnapshot, TS: at("a", 30, 10), IP: "a", AvgMS: 999, P95MS: 999, UpSec: 1},
		{Kind: KindSnapshot, TS: at("b", 2, 10), IP: "b", AvgMS: 10, P95MS: 10, UpSec: 1},
	}
	days := Daily(entries, "a", 3, now)
	if len(days) != 3 {
		t.Fatalf("Daily = %d buckets, want 3", len(days))
	}
	want := []Day{
		{Date: "2026-10-01", AvgMS: 50, P95MS: 80, UpSec: 5400, Downs: 0, Sessions: 2, Loss: 2},
		{Date: "2026-10-02", AvgMS: 50, P95MS: 55, UpSec: 7200, Downs: 1, Sessions: 1, Loss: 0},
		{Date: "2026-10-03", AvgMS: 30, P95MS: 35, UpSec: 3600, Downs: 0, Sessions: 1, Loss: 2},
	}
	for i := range want {
		if days[i] != want[i] {
			t.Errorf("day %d = %+v, want %+v", i, days[i], want[i])
		}
	}
	// A window with no data still yields the empty buckets for a stable axis.
	if empty := Daily(nil, "a", 2, now); len(empty) != 2 || empty[0].Sessions != 0 {
		t.Fatalf("Daily(nil) = %+v, want two empty days", empty)
	}
}

func TestHealthScore(t *testing.T) {
	cases := []struct {
		name             string
		avg, p95, base   int
		loss             float64
		churn, wantScore int
		wantLabel        string
	}{
		{"perfect", 20, 20, 20, 0, 0, 100, "excellent"},
		{"a little loss", 20, 20, 20, 4, 0, 90, "excellent"},
		{"heavy loss", 20, 20, 20, 20, 0, 60, "fair"},
		{"latency drift", 20, 20, 10, 0, 0, 80, "good"},
		{"churn", 20, 20, 20, 0, 5, 85, "good"},
		{"clamped to zero", 1000, 2000, 10, 50, 10, 5, "poor"},
		{"negative loss ignored", 20, 20, 20, -3, 0, 100, "excellent"},
	}
	for _, c := range cases {
		got, label := HealthScore(c.avg, c.p95, c.base, c.loss, c.churn)
		if got != c.wantScore || label != c.wantLabel {
			t.Errorf("%s: HealthScore = %d %q, want %d %q", c.name, got, label, c.wantScore, c.wantLabel)
		}
	}
}

func TestLatchHysteresis(t *testing.T) {
	var l Latch
	l.Threshold = 3

	// The first sample seeds silently, whichever side it is.
	if flipped, up := l.Observe(true); flipped || !up {
		t.Fatalf("seed up = flipped %v up %v, want silent up", flipped, up)
	}
	// A single dropped ping must not flip a healthy host, and a recovery
	// resets the run.
	if flipped, _ := l.Observe(false); flipped {
		t.Fatal("one miss must not flip")
	}
	if flipped, _ := l.Observe(true); flipped {
		t.Fatal("recovery must not flip")
	}
	// Three consecutive misses do.
	if flipped, _ := l.Observe(false); flipped {
		t.Fatal("second consecutive miss must not flip yet")
	}
	if flipped, _ := l.Observe(false); flipped {
		t.Fatal("third miss should still be waiting")
	}
	if flipped, up := l.Observe(false); !flipped || up {
		t.Fatalf("third consecutive miss = flipped %v up %v, want flip down", flipped, up)
	}
	// And it takes three hits to come back.
	l.Observe(true)
	l.Observe(true)
	if flipped, up := l.Observe(true); !flipped || !up {
		t.Fatalf("third consecutive hit = flipped %v up %v, want flip up", flipped, up)
	}
	if !l.Seeded() || !l.Up() {
		t.Fatal("latch should be seeded and up")
	}
}

func TestLatchSkippedDownSeed(t *testing.T) {
	var l Latch // Threshold 0 → treated as 1: immediate flips
	if flipped, up := l.Observe(false); flipped || up {
		t.Fatalf("seed down = flipped %v up %v, want silent down", flipped, up)
	}
	if flipped, up := l.Observe(true); !flipped || !up {
		t.Fatalf("Threshold 0 flip = %v %v, want immediate up", flipped, up)
	}
}

func TestFormatPct(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want string
	}{{0, "0%"}, {2.5, "2.5%"}, {100, "100%"}, {1.25, "1.2%"}} {
		if got := FormatPct(c.in); got != c.want {
			t.Errorf("FormatPct(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEntryTime(t *testing.T) {
	if _, ok := (Entry{TS: "nope"}).Time(); ok {
		t.Error("bad timestamp should not parse")
	}
	if t0, ok := (Entry{TS: "2026-10-03T10:00:00Z"}).Time(); !ok || t0.Year() != 2026 {
		t.Errorf("valid timestamp did not parse: %v %v", t0, ok)
	}
}

func TestDailyClampsDays(t *testing.T) {
	now := time.Now()
	if got := Daily(nil, "a", 0, now); len(got) != 1 {
		t.Fatalf("Daily(days=0) = %d buckets, want 1", len(got))
	}
	if got := Daily(nil, "a", -5, now); len(got) != 1 {
		t.Fatalf("Daily(days<0) = %d buckets, want 1", len(got))
	}
}

func TestKindStrings(t *testing.T) {
	for _, c := range []struct {
		k    Kind
		want string
	}{{KindUp, "up"}, {KindDown, "down"}, {KindSnapshot, "snapshot"}} {
		if string(c.k) != c.want || !strings.Contains(string(c.k), c.want) {
			t.Errorf("Kind %v != %q", c.k, c.want)
		}
	}
}
