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

package main

import (
	"strings"
	"testing"

	"gnulte-go/internal/monitor"
)

func TestPercentileNearestRank(t *testing.T) {
	var xs []int
	for i := 1; i <= 100; i++ {
		xs = append(xs, i)
	}
	if got := percentile(xs, 0.95); got != 95 {
		t.Errorf("p95 = %d, want 95", got)
	}
	if got := percentile(xs, 0.50); got != 50 {
		t.Errorf("p50 = %d, want 50", got)
	}
	if got := percentile([]int{7}, 0.99); got != 7 {
		t.Errorf("single sample p99 = %d, want 7", got)
	}
	// 9 values: nearest-rank p95 is ceil(8.55)-1 = index 8 → 9. A floor-based
	// rank would pick index 7 → 8.
	if got := percentile([]int{1, 2, 3, 4, 5, 6, 7, 8, 9}, 0.95); got != 9 {
		t.Errorf("p95 of 1..9 = %d, want 9", got)
	}
}

func TestStddevPopulation(t *testing.T) {
	xs := []int{2, 4, 4, 4, 5, 5, 7, 9}
	if got := stddev(xs); got != 2 {
		t.Errorf("stddev = %v, want 2", got)
	}
	if got := stddev([]int{5}); got != 0 {
		t.Errorf("single-sample stddev = %v, want 0", got)
	}
}

func TestRoughMOSMonotonic(t *testing.T) {
	clean := RoughMOS(10, 0)
	if clean < 3.9 || clean > 4.5 {
		t.Fatalf("clean MOS = %.2f, want ~4.4", clean)
	}
	if slow := RoughMOS(400, 0); slow >= clean {
		t.Errorf("400ms MOS %.2f should be below clean %.2f", slow, clean)
	}
	if lossy := RoughMOS(10, 20); lossy >= clean {
		t.Errorf("20%% loss MOS %.2f should be below clean %.2f", lossy, clean)
	}
	// 1% loss at no delay sits around 3.9. A scale slip that treated loss as
	// a fraction rather than a percentage would crush it below 2.
	if mild := RoughMOS(0, 1); mild < 3.8 || mild > 4.0 {
		t.Errorf("1%% loss MOS = %.2f, want ~3.9", mild)
	}
	if full := RoughMOS(0, 100); full < 1 || full >= 2.5 {
		t.Errorf("100%% loss MOS = %.2f, want ~1.7", full)
	}
}

func TestSummarizeAggregatesAndBucketsRuns(t *testing.T) {
	results := []monitor.Result{
		{IP: "10.0.0.1", Stats: monitor.Stats{
			Count: 4, Drops: 2, Min: 10, Max: 40, Total: 100,
			Samples:    []int{10, 20, 30, 40},
			LossSeries: []int{0, 100, 0, 100, 100, 100},
		}},
		{IP: "10.0.0.2", Stats: monitor.Stats{
			Count: 5, Drops: 1, Min: 50, Max: 90, Total: 350,
			Samples:    []int{50, 60, 70, 80, 90},
			LossSeries: []int{100, 0, 0, 0, 0, 0},
		}},
	}
	s := Summarize(results)
	if s.Targets != 2 || s.Attempts != 12 || s.Lost != 3 {
		t.Fatalf("counts = %+v", s)
	}
	if s.Samples != 9 || s.Min != 10 || s.Max != 90 {
		t.Fatalf("span = %+v", s)
	}
	// sum = 10+20+30+40+50+60+70+80+90 = 450, /9 = 50
	if s.Avg != 50 {
		t.Fatalf("avg = %d, want 50", s.Avg)
	}
	// sorted p95 nearest-rank of 9 values → index ceil(8.55)-1 = 8 → 90
	if s.P95 != 90 {
		t.Fatalf("p95 = %d, want 90", s.P95)
	}
	// Three runs: [100] and [100,100,100] on host 1, [100] on host 2.
	if s.LossRuns["1"] != 2 || s.LossRuns["2-3"] != 1 {
		t.Fatalf("loss runs = %v, want 1x2 and 2-3x1", s.LossRuns)
	}
	if s.MOS <= 0 || s.MOS > 4.5 {
		t.Fatalf("MOS = %.2f out of range", s.MOS)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	s := Summarize(nil)
	if s.Attempts != 0 || s.Console() != nil {
		t.Fatalf("empty summary = %+v / %v", s, s.Console())
	}
}

func TestSummaryConsoleMentionsP95(t *testing.T) {
	s := Summarize([]monitor.Result{{IP: "10.0.0.1", Stats: monitor.Stats{
		Count: 3, Samples: []int{10, 20, 30}, Min: 10, Max: 30, Total: 60,
		LossSeries: []int{0, 0, 0},
	}}})
	joined := strings.Join(s.Console(), "\n")
	for _, want := range []string{"p95", "MOS", "attempts"} {
		if !strings.Contains(joined, want) {
			t.Errorf("console summary missing %q:\n%s", want, joined)
		}
	}
}
