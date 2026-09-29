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

package scanner

import (
	"fmt"
	"sort"
	"strings"

	"gnulte-go/internal/discover"
)

// DeltaStatus is how one host moved between two scans, shown live by the
// --watch mode of GNULTE 15 ("Live Interconnection": the network is a moving
// thing and the tool points at what changed).
type DeltaStatus int

const (
	DeltaAlive DeltaStatus = iota // present in both, unchanged detail
	DeltaNew                      // appeared since the previous scan
	DeltaGone                     // present before, missing now
	DeltaChanged                  // present in both, but MAC/vendor/type/host moved
)

func (s DeltaStatus) String() string {
	switch s {
	case DeltaNew:
		return "NEW"
	case DeltaGone:
		return "GONE"
	case DeltaChanged:
		return "CHANGED"
	default:
		return "ALIVE"
	}
}

// Mark is the compact one-character marker shown in delta-aware tables.
func (s DeltaStatus) Mark() string {
	switch s {
	case DeltaNew:
		return "▲"
	case DeltaGone:
		return "▼"
	case DeltaChanged:
		return "~"
	default:
		return "·"
	}
}

// Delta maps one IP to its movement status. Every IP seen in either sweep is
// present; GONE only applies to hosts that were in prev but not in next, so a
// host dropping off between scans is not silently forgotten.
type Delta map[string]DeltaStatus

// Diff compares two sweeps by IP. A host's identity is (MAC, Vendor, Type,
// Hostname) — a changed MAC on the same IP is a CHANGED host, not a new one,
// because an IP reassignment is exactly the kind of turnover a live watcher
// wants called out.
func Diff(prev, next []discover.Row) Delta {
	key := func(r discover.Row) (string, string, string, string, string) {
		return r.IP, r.MAC, r.Vendor, r.Type, r.Hostname
	}
	prevMap := map[string]discover.Row{}
	for _, r := range prev {
		prevMap[r.IP] = r
	}
	out := Delta{}
	for _, r := range next {
		p, ok := prevMap[r.IP]
		if !ok {
			out[r.IP] = DeltaNew
			continue
		}
		pi, pm, pv, pt, ph := key(p)
		ni, nm, nv, nt, nh := key(r)
		if pi != ni || pm != nm || pv != nv || pt != nt || ph != nh {
			out[r.IP] = DeltaChanged
			continue
		}
		out[r.IP] = DeltaAlive
	}
	for ip, p := range prevMap {
		if _, ok := out[ip]; !ok {
			_ = p
			out[ip] = DeltaGone
		}
	}
	return out
}

// Counts groups a delta into the headline numbers used by the summary line.
func (d Delta) Counts() (newN, goneN, changedN, aliveN int) {
	for _, s := range d {
		switch s {
		case DeltaNew:
			newN++
		case DeltaGone:
			goneN++
		case DeltaChanged:
			changedN++
		default:
			aliveN++
		}
	}
	return
}

// Summary renders the compact "Δ 2 new · 1 gone · 3 changed" line.
func (d Delta) Summary() string {
	newN, goneN, changedN, _ := d.Counts()
	if len(d) == 0 {
		return "no change"
	}
	parts := []string{}
	if newN > 0 {
		parts = append(parts, fmt.Sprintf("%d new", newN))
	}
	if goneN > 0 {
		parts = append(parts, fmt.Sprintf("%d gone", goneN))
	}
	if changedN > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", changedN))
	}
	if len(parts) == 0 {
		return "no change"
	}
	return "Δ " + joinParts(parts)
}

// Lines renders the per-host delta lines in a stable (IP) order, e.g.
//
//	▲ NEW     192.168.1.77   Xiaomi  phone      Mi 11
//	▼ GONE    192.168.1.12   (router)
//	~ CHANGED 192.168.1.50   ACME → Fastly   (vendor)
func (d Delta) Lines() []string {
	ips := make([]string, 0, len(d))
	for ip := range d {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		m := d[ip].Mark()
		name := d[ip].String()
		label := fmt.Sprintf("%s %-7s %-15s", m, name, ip)
		switch d[ip] {
		case DeltaNew:
			label += "  (new host)"
		case DeltaGone:
			label += "  (stopped answering)"
		case DeltaChanged:
			label += "  (identity changed)"
		}
		out = append(out, label)
	}
	return out
}

// Changes narrows Lines to the movement only — NEW, GONE and CHANGED — so a
// live watcher's console shows exactly what the network did, not the hundreds
// of hosts that simply stayed alive.
func (d Delta) Changes() []string {
	all := d.Lines()
	out := make([]string, 0, len(all)/8+1)
	for _, ln := range all {
		if strings.HasPrefix(ln, "▲") || strings.HasPrefix(ln, "▼") || strings.HasPrefix(ln, "~") {
			out = append(out, ln)
		}
	}
	return out
}

func joinParts(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " · "
		}
		out += p
	}
	return out
}