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

package scenario

import (
	"strings"
	"testing"
	"time"
)

const sample = `{
  "name": "loss ladder",
  "loop": true,
  "phases": [
    {"name": "clean", "duration": 10, "latency": 20, "jitter": 5},
    {"name": "degrade", "duration": 20, "latency": 150, "jitter": 10, "loss": 8,
     "wobble": {"type": "sine", "amplitude_ms": 100, "period_s": 8},
     "burst": {"loss_pct": 40, "on_s": 2, "off_s": 6}}
  ]
}`

func mustParse(t *testing.T, doc string) *Scenario {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestParseFlatParams(t *testing.T) {
	s := mustParse(t, sample)
	if s.Name != "loss ladder" || !s.Loop || len(s.Phases) != 2 {
		t.Fatalf("scenario = %+v", s)
	}
	if got := s.Phases[0]; got.LatencyMS != 20 || got.JitterMS != 5 || got.LossPct != 0 {
		t.Fatalf("phase 0 = %+v, want latency 20 jitter 5", got.Impairment)
	}
	if got := s.Phases[1]; got.LatencyMS != 150 || got.LossPct != 8 || got.Wobble == nil || got.Burst == nil {
		t.Fatalf("phase 1 = %+v", got)
	}
	if s.Duration() != 30*time.Second {
		t.Fatalf("duration = %s, want 30s", s.Duration())
	}
}

func TestAtSelectsPhaseAndWobble(t *testing.T) {
	s := mustParse(t, sample)
	// tIn = 2 inside "degrade": sine quarter-period → +amplitude; burst is off
	// at exactly on_s, so the phase's own 8% loss stands.
	p, name, done := s.At(12 * time.Second)
	if name != "degrade" || done {
		t.Fatalf("At(12s) = %q done=%v", name, done)
	}
	if p.LatencyMS != 250 || p.LossPct != 8 {
		t.Fatalf("At(12s) params = %+v, want latency 250 loss 8", p)
	}
	// tIn = 6: sine three-quarter-period → -amplitude.
	p, _, _ = s.At(16 * time.Second)
	if p.LatencyMS != 50 {
		t.Fatalf("At(16s) latency = %d, want 50", p.LatencyMS)
	}
}

func TestAtBurstOverridesLoss(t *testing.T) {
	s := mustParse(t, sample)
	// tIn = 1 is inside the 2-second burst window.
	p, _, _ := s.At(11 * time.Second)
	if p.LossPct != 40 {
		t.Fatalf("At(11s) loss = %d, want the burst's 40", p.LossPct)
	}
	// tIn = 4 is outside it again.
	p, _, _ = s.At(14 * time.Second)
	if p.LossPct != 8 {
		t.Fatalf("At(14s) loss = %d, want the phase's 8", p.LossPct)
	}
}

func TestAtFirstPhaseAndLoop(t *testing.T) {
	s := mustParse(t, sample)
	if p, name, _ := s.At(5 * time.Second); name != "clean" || p.LatencyMS != 20 {
		t.Fatalf("At(5s) = %q %+v", name, p)
	}
	// 35s wraps once around the 30s loop to t=5s.
	if _, name, done := s.At(35 * time.Second); name != "clean" || done {
		t.Fatalf("At(35s) = %q done=%v, want clean/loop", name, done)
	}
	// 65s wraps twice, to the same t=5s; a single subtraction would land at
	// t=35s inside "degrade" instead.
	if _, name, _ := s.At(65 * time.Second); name != "clean" {
		t.Fatalf("At(65s) = %q, want clean after two loops", name)
	}
}

func TestAtNegativeElapsedIsStart(t *testing.T) {
	s := mustParse(t, sample)
	if p, name, _ := s.At(-3 * time.Second); name != "clean" || p.LatencyMS != 20 {
		t.Fatalf("At(-3s) = %q %+v, want the first phase", name, p)
	}
}

func TestAtUnnamedPhaseGetsNumberedLabel(t *testing.T) {
	s := mustParse(t, `{"phases":[{"duration":1,"latency":1},{"duration":1,"latency":2}]}`)
	if _, name, _ := s.At(500 * time.Millisecond); name != "phase 1" {
		t.Fatalf("At = %q, want the positional label %q", name, "phase 1")
	}
	if _, name, _ := s.At(1500 * time.Millisecond); name != "phase 2" {
		t.Fatalf("At = %q, want the positional label %q", name, "phase 2")
	}
}

func TestAtNonLoopClampsDone(t *testing.T) {
	doc := strings.Replace(sample, `"loop": true`, `"loop": false`, 1)
	s := mustParse(t, doc)
	p, name, done := s.At(90 * time.Second)
	if name != "degrade" || !done {
		t.Fatalf("At(90s) = %q done=%v, want the final phase with done", name, done)
	}
	if p.LatencyMS == 0 {
		t.Fatalf("clamped params should still be the final phase: %+v", p)
	}
}

func TestAtWobbleTypes(t *testing.T) {
	saw := `{"phases":[{"duration":10,"latency":100,
	  "wobble":{"type":"sawtooth","amplitude_ms":80,"period_s":10}}]}`
	s := mustParse(t, saw)
	if p, _, _ := s.At(5 * time.Second); p.LatencyMS != 140 {
		t.Fatalf("sawtooth half-period latency = %d, want 140", p.LatencyMS)
	}
	// A quarter period is 20 up the ramp; a decreasing ramp would read 160.
	if p, _, _ := s.At(2500 * time.Millisecond); p.LatencyMS != 120 {
		t.Fatalf("sawtooth quarter-period latency = %d, want 120", p.LatencyMS)
	}
	// A wobble must never drive latency below zero.
	deep := `{"phases":[{"duration":10,"latency":20,
	  "wobble":{"type":"sine","amplitude_ms":500,"period_s":4}}]}`
	s = mustParse(t, deep)
	if p, _, _ := s.At(3 * time.Second); p.LatencyMS < 0 {
		t.Fatalf("latency went negative: %d", p.LatencyMS)
	}
}

func TestParseRejectsBadDocuments(t *testing.T) {
	cases := map[string]string{
		"empty":            `{"phases":[]}`,
		"zero duration":    `{"phases":[{"duration":0,"latency":1}]}`,
		"negative latency": `{"phases":[{"duration":1,"latency":-1}]}`,
		"loss over 100":    `{"phases":[{"duration":1,"loss":60,"dup":50}]}`,
		"bad wobble type":  `{"phases":[{"duration":1,"wobble":{"type":"jitter","amplitude_ms":1,"period_s":1}}]}`,
		"zero period":      `{"phases":[{"duration":1,"wobble":{"type":"sine","amplitude_ms":1,"period_s":0}}]}`,
		"zero burst cycle": `{"phases":[{"duration":1,"burst":{"loss_pct":10,"on_s":0,"off_s":0}}]}`,
		"burst loss > 100": `{"phases":[{"duration":1,"burst":{"loss_pct":101,"on_s":1,"off_s":1}}]}`,
		"unknown field":    `{"phases":[{"duration":1,"latancy":5}]}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected a parse/validation error", name)
		}
	}
}

func TestDescribe(t *testing.T) {
	s := mustParse(t, sample)
	if got := s.Describe(); !strings.Contains(got, "loss ladder") || !strings.Contains(got, "loop") {
		t.Errorf("Describe = %q", got)
	}
}
