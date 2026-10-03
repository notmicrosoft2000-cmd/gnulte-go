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
	"fmt"
	"math"
	"sort"
	"strings"

	"gnulte-go/internal/monitor"
)

// SessionSummary is the whole-run rollup printed at the end of a test and
// embedded in the HTML report: latency percentiles, the loss rate, a run-length
// distribution of the drop bursts, and a rough E-model MOS.
type SessionSummary struct {
	Targets  int
	Attempts int
	Lost     int
	LossPct  float64
	Samples  int
	Min      int64
	Avg      int64
	P95      int64
	Max      int64
	StdDev   float64
	MOS      float64

	// LossRuns counts consecutive-drop runs by size bucket ("1", "2-3",
	// "4-7", "8-15", "16+"); map iteration order is not meaningful, the
	// renderer sorts it.
	LossRuns map[string]int
}

// lossBuckets is the fixed display order for the run-length distribution.
var lossBuckets = []string{"1", "2-3", "4-7", "8-15", "16+"}

// Summarize rolls every target's Stats into one SessionSummary. It is pure so
// the percentile, run-length and MOS maths can be tested without a session.
func Summarize(results []monitor.Result) SessionSummary {
	s := SessionSummary{Targets: len(results), LossRuns: map[string]int{}}
	var all []int
	for _, r := range results {
		st := r.Stats
		s.Attempts += st.Count + st.Drops
		s.Lost += st.Drops
		all = append(all, st.Samples...)
		countRuns(&s, st.LossSeries)
	}
	s.Samples = len(all)
	if s.Attempts > 0 {
		s.LossPct = float64(s.Lost) * 100 / float64(s.Attempts)
	}
	if len(all) > 0 {
		sort.Ints(all)
		s.Min = int64(all[0])
		s.Max = int64(all[len(all)-1])
		var sum int64
		for _, v := range all {
			sum += int64(v)
		}
		s.Avg = sum / int64(len(all))
		s.P95 = int64(percentile(all, 0.95))
		s.StdDev = stddev(all)
	}
	s.MOS = RoughMOS(float64(s.Avg), s.LossPct)
	return s
}

// countRuns adds each run of consecutive drops in the series to the bucket
// tally. A trailing run is counted too.
func countRuns(s *SessionSummary, series []int) {
	run := 0
	for _, v := range series {
		if v > 0 {
			run++
			continue
		}
		if run > 0 {
			s.LossRuns[lossBucket(run)]++
			run = 0
		}
	}
	if run > 0 {
		s.LossRuns[lossBucket(run)]++
	}
}

func lossBucket(n int) string {
	switch {
	case n <= 1:
		return "1"
	case n <= 3:
		return "2-3"
	case n <= 7:
		return "4-7"
	case n <= 15:
		return "8-15"
	default:
		return "16+"
	}
}

// p95Of returns the 95th-percentile latency of an unsorted sample slice,
// leaving the caller's slice untouched.
func p95Of(samples []int) int64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]int(nil), samples...)
	sort.Ints(cp)
	return int64(percentile(cp, 0.95))
}

// percentile returns the nearest-rank percentile of an already-sorted slice.
func percentile(sorted []int, p float64) int {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func stddev(xs []int) float64 {
	n := len(xs)
	if n < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += float64(x)
	}
	mean := sum / float64(n)
	var ss float64
	for _, x := range xs {
		d := float64(x) - mean
		ss += d * d
	}
	return math.Sqrt(ss / float64(n))
}

// RoughMOS is a deliberately coarse E-model estimate from round-trip latency
// and loss: one-way delay impairs R, random loss adds equipment impairment,
// and R maps to the 1.0–4.5 MOS scale. It is a sanity signal, not a verdict.
func RoughMOS(rttMS, lossPct float64) float64 {
	if rttMS < 0 {
		rttMS = 0
	}
	if lossPct < 0 {
		lossPct = 0
	}
	d := rttMS / 2 // one-way delay
	id := 0.024 * d
	if d > 177.3 {
		id += 0.11 * (d - 177.3)
	}
	ie := 30 * math.Log(1+15*(lossPct/100))
	r := 93.2 - id - ie
	if r < 0 {
		r = 0
	}
	if r > 100 {
		r = 100
	}
	mos := 1 + 0.035*r + 7e-6*r*(r-100)*(r-60)
	if mos < 1 {
		mos = 1
	}
	if mos > 4.5 {
		mos = 4.5
	}
	return mos
}

// lossRunText renders the distribution as "1×5, 2-3×2", or "" when nothing was
// lost.
func (s SessionSummary) lossRunText() string {
	var parts []string
	for _, b := range lossBuckets {
		if n := s.LossRuns[b]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s×%d", b, n))
		}
	}
	return strings.Join(parts, ", ")
}

// Console renders the summary as the lines printed at the end of a run.
func (s SessionSummary) Console() []string {
	if s.Attempts == 0 {
		return nil
	}
	out := []string{fmt.Sprintf("  targets %d · %d attempts · %d lost (%.1f%%)",
		s.Targets, s.Attempts, s.Lost, s.LossPct)}
	if s.Samples > 0 {
		out = append(out, fmt.Sprintf("  latency  min %dms · avg %dms · p95 %dms · max %dms · σ %.1fms",
			s.Min, s.Avg, s.P95, s.Max, s.StdDev))
	}
	line := fmt.Sprintf("  MOS %.1f (rough)", s.MOS)
	if runs := s.lossRunText(); runs != "" {
		line += " · loss runs " + runs
	}
	out = append(out, line)
	return out
}
