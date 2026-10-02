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

// Package toptalk turns a traffic snapshot into ranked, human-readable rows:
// per-host and per-conversation rates, peer counts, and the byte/rate/bar
// formatting the top view paints. It is deliberately pure — no sockets, no
// terminal — so the ranking and units can be unit-tested without root.
package toptalk

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"gnulte-go/internal/traffic"
)

// Row is one host's traffic over a sampling interval, expressed as per-second
// rates.
type Row struct {
	Host     string
	Down     int64 // bytes/s received by the host
	Up       int64 // bytes/s sent by the host
	DownPkts int64 // packets/s received
	UpPkts   int64 // packets/s sent
	Peers    int   // distinct conversation partners seen in the interval
}

// Total is the combined up+down rate.
func (r Row) Total() int64 { return r.Down + r.Up }

// Flow is one conversation's traffic over a sampling interval, as rates. A and
// B are "ip:port" endpoints; AB is A→B and BA is B→A.
type Flow struct {
	A, B     string
	AB, BA   int64
	ABp, BAp int64
}

// Total is the combined rate in both directions.
func (f Flow) Total() int64 { return f.AB + f.BA }

// Rows converts a traffic snapshot into per-host rows, keeps only the hosts
// match accepts (a nil match keeps everything), and sorts by combined rate
// descending. Ties break on the host string so equal-rate output is stable.
func Rows(rates map[string]traffic.Rate, seconds float64, match func(string) bool) []Row {
	rows := make([]Row, 0, len(rates))
	for host, r := range rates {
		if match != nil && !match(host) {
			continue
		}
		rows = append(rows, Row{
			Host:     host,
			Down:     perSec(r.RXBytes, seconds),
			Up:       perSec(r.TXBytes, seconds),
			DownPkts: perSec(r.RXPkts, seconds),
			UpPkts:   perSec(r.TXPkts, seconds),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total() != rows[j].Total() {
			return rows[i].Total() > rows[j].Total()
		}
		return rows[i].Host < rows[j].Host
	})
	return rows
}

// FlowRows converts conversations into ranked rows, keeping a conversation when
// either endpoint passes match (nil match keeps all) and sorting by combined
// rate descending.
func FlowRows(flows []traffic.Flow, seconds float64, match func(string) bool) []Flow {
	out := make([]Flow, 0, len(flows))
	for _, f := range flows {
		if match != nil && !match(f.A) && !match(f.B) {
			continue
		}
		out = append(out, Flow{
			A: f.A, B: f.B,
			AB: perSec(f.AB, seconds), BA: perSec(f.BA, seconds),
			ABp: perSec(f.ABp, seconds), BAp: perSec(f.BAp, seconds),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total() != out[j].Total() {
			return out[i].Total() > out[j].Total()
		}
		if out[i].A != out[j].A {
			return out[i].A < out[j].A
		}
		return out[i].B < out[j].B
	})
	return out
}

// Peers counts, for every host, how many distinct endpoints it talked to during
// the interval. A host that only talked to itself contributes nothing.
func Peers(flows []traffic.Flow) map[string]int {
	sets := map[string]map[string]bool{}
	for _, f := range flows {
		a, b := HostOf(f.A), HostOf(f.B)
		if a == "" || b == "" || a == b {
			continue
		}
		addPeer(sets, a, b)
		addPeer(sets, b, a)
	}
	out := make(map[string]int, len(sets))
	for host, set := range sets {
		out[host] = len(set)
	}
	return out
}

func addPeer(sets map[string]map[string]bool, host, peer string) {
	s := sets[host]
	if s == nil {
		s = map[string]bool{}
		sets[host] = s
	}
	s[peer] = true
}

// HostOf strips the ":port" from an "ip:port" endpoint.
func HostOf(ep string) string {
	if i := strings.LastIndexByte(ep, ':'); i >= 0 {
		return ep[:i]
	}
	return ep
}

// perSec converts a byte/packet count over seconds into a per-second rate,
// rounded to the nearest unit.
func perSec(n int64, seconds float64) int64 {
	if n <= 0 {
		return 0
	}
	if seconds <= 0 {
		return n
	}
	return int64(math.Round(float64(n) / seconds))
}

// HumanBytes renders a byte count with binary units and one decimal above KiB.
func HumanBytes(n int64) string {
	neg := false
	if n < 0 {
		neg, n = true, -n
	}
	var s string
	switch {
	case n < 1024:
		s = fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		s = fmt.Sprintf("%.1f KiB", float64(n)/1024)
	case n < 1024*1024*1024:
		s = fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	default:
		s = fmt.Sprintf("%.1f GiB", float64(n)/(1024*1024*1024))
	}
	if neg {
		return "-" + s
	}
	return s
}

// HumanRate renders a per-second byte rate.
func HumanRate(bytesPerSec int64) string { return HumanBytes(bytesPerSec) + "/s" }

// Bar draws a proportional bar of the given width: solid cells for v out of
// max, light cells for the remainder. A non-positive max or v draws an empty
// bar.
func Bar(v, max int64, width int) string {
	if width <= 0 {
		return ""
	}
	if max <= 0 || v <= 0 {
		return strings.Repeat("·", width)
	}
	filled := int(math.Round(float64(v) / float64(max) * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("█", filled) + strings.Repeat("·", width-filled)
}
