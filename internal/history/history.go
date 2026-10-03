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

// Package history records what gnulte-lan's watch mode saw over time: host
// up/down transitions and one daily rollup per host per session, kept as an
// append-only JSONL file beside the device inventory. It also owns the small
// pure pieces the live watch needs — a debounce latch for up/down edges, a
// daily aggregation for the 7-day trend, and a coarse network health score —
// so that behaviour is testable with no terminal, socket or clock.
package history

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// Kind tags each JSONL record so transitions and daily rollups can share one
// file.
type Kind string

const (
	KindUp       Kind = "up"       // a host came back
	KindDown     Kind = "down"     // a host stopped answering
	KindSnapshot Kind = "snapshot" // a per-session daily rollup
)

// Entry is one JSONL record. Only the fields relevant to Kind are set; the
// zero value is omitted for the rest via omitempty.
type Entry struct {
	Kind  Kind    `json:"kind"`
	TS    string  `json:"ts"` // RFC3339
	IP    string  `json:"ip"`
	Name  string  `json:"name,omitempty"`
	AvgMS int     `json:"avg_ms,omitempty"`
	P95MS int     `json:"p95_ms,omitempty"`
	UpSec int     `json:"up_sec,omitempty"`
	Loss  float64 `json:"loss_pct,omitempty"`
}

// Time parses the entry timestamp, reporting whether it was valid.
func (e Entry) Time() (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, e.TS)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Path is the default timeline file: beside the device inventory under the
// toolkit's config dir ($XDG_CONFIG_HOME/gnulte-go/watch-history.jsonl).
func Path() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			base = ""
		} else {
			base = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(base, "gnulte-go", "watch-history.jsonl")
}

// Append adds one record to the JSONL file, creating the folder and file if
// needed. Watchers are single-writer, so a plain O_APPEND is enough; a crash
// can at worst lose the last line, which Load tolerates.
func Append(path string, e Entry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = f.Write(b)
	return err
}

// Load reads every valid record, silently skipping blank or corrupt lines so
// one truncated write cannot poison a week of history.
func Load(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Entry
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		if e.IP == "" {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// Window returns the entries with a parseable timestamp in [since, until].
func Window(entries []Entry, since, until time.Time) []Entry {
	var out []Entry
	for _, e := range entries {
		t, ok := e.Time()
		if !ok || t.Before(since) || t.After(until) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// OnDay returns the entries whose timestamp falls on day (local calendar day).
func OnDay(entries []Entry, day time.Time) []Entry {
	y, m, d := day.Date()
	start := time.Date(y, m, d, 0, 0, 0, 0, day.Location())
	return Window(entries, start, start.AddDate(0, 0, 1).Add(-time.Nanosecond))
}

// Day is one calendar-day bucket of a host's history.
type Day struct {
	Date     string // "2006-01-02"
	AvgMS    int
	P95MS    int
	UpSec    int
	Downs    int
	Sessions int
	Loss     float64 // mean snapshot loss for the day
}

// Daily aggregates a host's snapshots and down transitions into `days`
// buckets, oldest first and ending on now's day. Empty days are included so a
// trend chart has a stable x-axis.
func Daily(entries []Entry, ip string, days int, now time.Time) []Day {
	if days < 1 {
		days = 1
	}
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	start := today.AddDate(0, 0, -(days - 1))

	byDate := map[string]*Day{}
	order := make([]string, 0, days)
	for i := 0; i < days; i++ {
		date := start.AddDate(0, 0, i).Format("2006-01-02")
		byDate[date] = &Day{Date: date}
		order = append(order, date)
	}

	avgSum := map[string]int{}
	lossSum := map[string]float64{}
	for _, e := range entries {
		if e.IP != ip {
			continue
		}
		t, ok := e.Time()
		if !ok || t.Before(start) || t.After(now) {
			continue
		}
		date := t.Format("2006-01-02")
		day := byDate[date]
		if day == nil {
			continue
		}
		switch e.Kind {
		case KindSnapshot:
			day.Sessions++
			avgSum[date] += e.AvgMS
			lossSum[date] += e.Loss
			if e.P95MS > day.P95MS {
				day.P95MS = e.P95MS
			}
			day.UpSec += e.UpSec
		case KindDown:
			day.Downs++
		}
	}
	out := make([]Day, 0, days)
	for _, date := range order {
		day := byDate[date]
		if day.Sessions > 0 {
			day.AvgMS = avgSum[date] / day.Sessions
			day.Loss = lossSum[date] / float64(day.Sessions)
		}
		out = append(out, *day)
	}
	return out
}

// HealthScore turns a host's recent numbers into a 0–100 score and a word.
// It is deliberately blunt: loss dominates, latency drift from the host's own
// baseline is next, a wide p95/avg spread and up/down churn finish it off.
func HealthScore(avgMS, p95MS, baselineMS int, lossPct float64, churn int) (int, string) {
	if lossPct < 0 {
		lossPct = 0
	}
	score := 100.0
	score -= math.Min(40, lossPct*2.5)
	if baselineMS > 0 && avgMS > baselineMS {
		score -= math.Min(25, float64(avgMS-baselineMS)/float64(baselineMS)*20)
	}
	if avgMS > 0 && p95MS > avgMS {
		score -= math.Min(15, float64(p95MS-avgMS)/float64(avgMS)*10)
	}
	if churn > 0 {
		score -= math.Min(20, float64(churn)*3)
	}
	if score < 0 {
		score = 0
	}
	s := int(math.Round(score))
	switch {
	case s >= 90:
		return s, "excellent"
	case s >= 75:
		return s, "good"
	case s >= 50:
		return s, "fair"
	default:
		return s, "poor"
	}
}

// Latch debounces a yes/no signal (here: did the host answer?). A transition is
// only believed after Threshold consecutive samples on the new side, so one
// dropped ping does not raise a false "down". The first sample seeds the state
// silently — a run should not open with an alert for every host at once.
type Latch struct {
	Threshold int
	state     bool
	run       int
	seeded    bool
}

// Observe feeds one sample (up=true means the host answered). It returns
// flipped=true on the sample that changes the stable state, plus that state.
func (l *Latch) Observe(up bool) (flipped, stable bool) {
	if l.Threshold < 1 {
		l.Threshold = 1
	}
	if !l.seeded {
		l.seeded = true
		l.state = up
		return false, l.state
	}
	if up == l.state {
		l.run = 0
		return false, l.state
	}
	l.run++
	if l.run >= l.Threshold {
		l.state = up
		l.run = 0
		return true, l.state
	}
	return false, l.state
}

// Up reports the current stable state.
func (l *Latch) Up() bool { return l.state }

// Seeded reports whether Observe has seen its first sample.
func (l *Latch) Seeded() bool { return l.seeded }

// FormatPct renders a loss percentage for the console without a trailing .0
// for whole numbers.
func FormatPct(p float64) string {
	if p == math.Trunc(p) {
		return fmt.Sprintf("%.0f%%", p)
	}
	return fmt.Sprintf("%.1f%%", p)
}
