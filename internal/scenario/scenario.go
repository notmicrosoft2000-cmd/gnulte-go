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

// Package scenario turns a JSON script of timed phases into the impairment
// values a shaping session should be running at any moment. It is pure — a
// scenario plus an elapsed duration yields an engine.Impairment and a phase
// name — so the clock, the sine/sawtooth wobble and the burst-loss generator
// can be unit-tested with no terminal, socket or root.
package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"gnulte-go/internal/engine"
)

// Wobble modulates the phase's base latency over time. Type is "sine" (the
// latency swings ±AmplitudeMS) or "sawtooth" (it rises from the base to
// base+AmplitudeMS then snaps back).
type Wobble struct {
	Type        string  `json:"type"`
	AmplitudeMS int     `json:"amplitude_ms"`
	PeriodS     float64 `json:"period_s"`
}

// Burst raises loss for OnS seconds every OnS+OffS, overriding the phase's loss
// with LossPct for the duration of the on-window.
type Burst struct {
	LossPct int     `json:"loss_pct"`
	OnS     float64 `json:"on_s"`
	OffS    float64 `json:"off_s"`
}

// Phase is one timed step: base impairment values, optionally modulated by a
// wobble or a burst generator. The impairment fields are embedded so the JSON
// is flat, e.g. {"name":"storm","duration":20,"latency":200,"loss":5}.
type Phase struct {
	Name     string  `json:"name"`
	Duration float64 `json:"duration"` // seconds
	engine.Impairment
	Wobble *Wobble `json:"wobble,omitempty"`
	Burst  *Burst  `json:"burst,omitempty"`
}

// Scenario is an ordered list of phases, optionally looping.
type Scenario struct {
	Name   string  `json:"name"`
	Loop   bool    `json:"loop"`
	Phases []Phase `json:"phases"`
}

// Parse decodes and validates a scenario document. Unknown JSON keys are
// rejected so a typo ("latancy") is an error rather than a silently ignored
// field.
func Parse(data []byte) (*Scenario, error) {
	var s Scenario
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scenario: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Load reads and parses a scenario file.
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scenario: %w", err)
	}
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Validate checks the whole document before any of it is applied.
func (s *Scenario) Validate() error {
	if len(s.Phases) == 0 {
		return errors.New("scenario has no phases")
	}
	for i := range s.Phases {
		p := &s.Phases[i]
		label := p.displayName(i)
		if p.Duration <= 0 {
			return fmt.Errorf("phase %q: duration must be greater than zero", label)
		}
		if err := p.Impairment.Validate(); err != nil {
			return fmt.Errorf("phase %q: %w", label, err)
		}
		if p.Wobble != nil {
			switch p.Wobble.Type {
			case "sine", "sawtooth":
			default:
				return fmt.Errorf("phase %q: wobble type %q (want sine or sawtooth)", label, p.Wobble.Type)
			}
			if p.Wobble.AmplitudeMS < 0 {
				return fmt.Errorf("phase %q: wobble amplitude_ms cannot be negative", label)
			}
			if p.Wobble.PeriodS <= 0 {
				return fmt.Errorf("phase %q: wobble period_s must be greater than zero", label)
			}
		}
		if p.Burst != nil {
			if p.Burst.LossPct < 0 || p.Burst.LossPct > 100 {
				return fmt.Errorf("phase %q: burst loss_pct must be between 0 and 100", label)
			}
			if p.Burst.OnS < 0 || p.Burst.OffS < 0 {
				return fmt.Errorf("phase %q: burst on_s/off_s cannot be negative", label)
			}
			if p.Burst.OnS+p.Burst.OffS <= 0 {
				return fmt.Errorf("phase %q: burst on_s+off_s must be greater than zero", label)
			}
		}
	}
	return nil
}

func (p *Phase) displayName(i int) string {
	if p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("phase %d", i+1)
}

// Duration is the total run time of one pass through the phases.
func (s *Scenario) Duration() time.Duration {
	var total float64
	for _, p := range s.Phases {
		total += p.Duration
	}
	return time.Duration(total * float64(time.Second))
}

// At returns the impairment and phase name in effect after elapsed has passed.
// A looping scenario wraps at the end; a one-shot scenario clamps to the end
// and reports done=true so the caller can stop re-applying.
func (s *Scenario) At(elapsed time.Duration) (engine.Impairment, string, bool) {
	t := elapsed.Seconds()
	if t < 0 {
		t = 0
	}
	total := s.Duration().Seconds()
	done := false
	if total > 0 && t >= total {
		if s.Loop {
			t = math.Mod(t, total)
		} else {
			t = total - 1e-9 // evaluate the final phase at its end
			done = true
		}
	}

	acc := 0.0
	idx := len(s.Phases) - 1
	for i := range s.Phases {
		d := s.Phases[i].Duration
		if t < acc+d {
			idx = i
			break
		}
		acc += d
	}
	ph := &s.Phases[idx]
	p := ph.Impairment
	tIn := t - acc

	p.LatencyMS += wobbleDelta(ph.Wobble, tIn)
	if p.LatencyMS < 0 {
		p.LatencyMS = 0
	}
	if ph.Burst != nil {
		cycle := ph.Burst.OnS + ph.Burst.OffS
		if cycle > 0 && math.Mod(tIn, cycle) < ph.Burst.OnS {
			p.LossPct = ph.Burst.LossPct
			// Keep the engine's "loss+dup+reorder <= 100" invariant even if
			// the burst is greedy next to the phase's own duplication.
			if extra := p.DupPct + p.ReorderPct; p.LossPct+extra > 100 {
				p.LossPct = 100 - extra
			}
		}
	}
	return p, ph.displayName(idx), done
}

// wobbleDelta is the latency offset the wobble contributes t seconds into its
// phase. A nil or zero wobble is a no-op.
func wobbleDelta(w *Wobble, t float64) int {
	if w == nil || w.AmplitudeMS == 0 || w.PeriodS <= 0 {
		return 0
	}
	frac := math.Mod(t, w.PeriodS) / w.PeriodS
	switch w.Type {
	case "sine":
		return int(math.Round(float64(w.AmplitudeMS) * math.Sin(2*math.Pi*frac)))
	case "sawtooth":
		return int(math.Round(float64(w.AmplitudeMS) * frac))
	default:
		return 0
	}
}

// Describe renders a one-line human summary of the scenario, used by the CLI
// when a scenario is loaded.
func (s *Scenario) Describe() string {
	if s.Name == "" {
		if s.Loop {
			return fmt.Sprintf("%d-phase loop, %s total", len(s.Phases), s.Duration())
		}
		return fmt.Sprintf("%d-phase script, %s total", len(s.Phases), s.Duration())
	}
	if s.Loop {
		return fmt.Sprintf("%s — %d-phase loop, %s total", s.Name, len(s.Phases), s.Duration())
	}
	return fmt.Sprintf("%s — %d-phase script, %s total", s.Name, len(s.Phases), s.Duration())
}
