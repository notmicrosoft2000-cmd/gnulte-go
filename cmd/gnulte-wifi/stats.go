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
	"sort"
	"strings"
	"time"

	"gnulte-go/internal/airframes"
)

// ParseStations splits a comma-separated list of MACs. Whitespace around each
// entry is ignored; empty entries are rejected so a stray trailing comma does
// not silently shrink the target list.
func ParseStations(s string) ([]airframes.MAC, error) {
	parts := strings.Split(s, ",")
	out := make([]airframes.MAC, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty station in list %q", s)
		}
		mac, err := airframes.ParseMAC(part)
		if err != nil {
			return nil, err
		}
		out = append(out, mac)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no stations given")
	}
	return out, nil
}

// stationForBurst picks the target for a zero-based burst index when steering
// across several stations. A streak of N sends N consecutive bursts to one
// station before moving to the next, wrapping after the last one. A streak
// below 1 is treated as 1.
func stationForBurst(stations []airframes.MAC, burst, streak int) airframes.MAC {
	if len(stations) == 0 {
		return airframes.MAC{}
	}
	if streak < 1 {
		streak = 1
	}
	return stations[(burst/streak)%len(stations)]
}

// JitterStats counts the jitter delay actually applied before each frame. The
// burst loop feeds it the chosen delay; it reads no clock, so it stays
// deterministic and easy to test.
type JitterStats struct {
	frames  uint64
	delayed uint64
	min     int
	max     int
	sum     uint64
	started bool
}

// Add records one frame's jitter in milliseconds. Negative values count as no
// jitter (the loop never produces one, but callers stay forgiving).
func (j *JitterStats) Add(ms int) {
	if ms < 0 {
		ms = 0
	}
	j.frames++
	if ms > 0 {
		j.delayed++
	}
	if !j.started || ms < j.min {
		j.min = ms
	}
	if !j.started || ms > j.max {
		j.max = ms
	}
	j.started = true
	j.sum += uint64(ms)
}

func (j *JitterStats) Frames() uint64  { return j.frames }
func (j *JitterStats) Delayed() uint64 { return j.delayed }

func (j *JitterStats) Min() int {
	if !j.started {
		return 0
	}
	return j.min
}

func (j *JitterStats) Max() int {
	if !j.started {
		return 0
	}
	return j.max
}

func (j *JitterStats) Mean() float64 {
	if j.frames == 0 {
		return 0
	}
	return float64(j.sum) / float64(j.frames)
}

func (j *JitterStats) Total() time.Duration {
	return time.Duration(j.sum) * time.Millisecond
}

// String renders a one-line summary of the delays seen so far.
func (j *JitterStats) String() string {
	if j.frames == 0 {
		return "no frames"
	}
	return fmt.Sprintf("%d/%d frames delayed, %d-%d ms (avg %.1f ms, total %s)",
		j.delayed, j.frames, j.min, j.max, j.Mean(), j.Total())
}

// DwellStats accumulates how long the adapter stayed on each channel while
// hopping. The burst loop supplies elapsed wall time per stay; the accumulator
// itself never reads the clock.
type DwellStats struct {
	byChannel map[uint8]*dwell
}

type dwell struct {
	bursts  uint64
	elapsed time.Duration
}

// Record adds one stay on a channel: the number of bursts sent there and how
// long the adapter remained before moving on.
func (d *DwellStats) Record(channel uint8, bursts int, elapsed time.Duration) {
	if d.byChannel == nil {
		d.byChannel = make(map[uint8]*dwell)
	}
	e := d.byChannel[channel]
	if e == nil {
		e = &dwell{}
		d.byChannel[channel] = e
	}
	e.bursts += uint64(bursts)
	e.elapsed += elapsed
}

// DwellRow is the accumulated stay for one channel.
type DwellRow struct {
	Channel uint8
	Bursts  uint64
	Dwell   time.Duration
}

// Rows returns the per-channel totals sorted by channel number.
func (d *DwellStats) Rows() []DwellRow {
	rows := make([]DwellRow, 0, len(d.byChannel))
	for ch, e := range d.byChannel {
		rows = append(rows, DwellRow{Channel: ch, Bursts: e.bursts, Dwell: e.elapsed})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Channel < rows[j].Channel })
	return rows
}

// FormatDwell renders channel dwell totals on one line.
func FormatDwell(rows []DwellRow) string {
	if len(rows) == 0 {
		return "no channel data"
	}
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("ch %d: %dB / %.1fs", r.Channel, r.Bursts, r.Dwell.Seconds()))
	}
	return strings.Join(parts, ", ")
}
