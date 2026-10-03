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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"gnulte-go/internal/engine"
)

// applyImpairment copies a saved/preset profile's values onto ec, leaving any
// field the operator set explicitly on the command line untouched (a profile is
// a set of defaults, not an override of an explicit flag).
func applyImpairment(ec *engine.Config, p engine.Impairment, explicit map[string]bool) {
	if !explicit["latency"] {
		ec.LatencyMS = p.LatencyMS
	}
	if !explicit["jitter"] {
		ec.JitterMS = p.JitterMS
	}
	if !explicit["loss"] {
		ec.LossPct = p.LossPct
	}
	if !explicit["duplicate"] {
		ec.DupPct = p.DupPct
	}
	if !explicit["reorder"] {
		ec.ReorderPct = p.ReorderPct
	}
	if !explicit["bandwidth"] {
		ec.BandwidthKbps = p.BandwidthKbps
	}
}

// setImpairment writes every field unconditionally. Scenario phases use it
// because a phase defines the whole impairment, not a delta.
func setImpairment(ec *engine.Config, p engine.Impairment) {
	ec.LatencyMS = p.LatencyMS
	ec.JitterMS = p.JitterMS
	ec.LossPct = p.LossPct
	ec.DupPct = p.DupPct
	ec.ReorderPct = p.ReorderPct
	ec.BandwidthKbps = p.BandwidthKbps
}

// perTargetOverride is the partial JSON shape accepted by --per-target: an IP
// keyed object where any omitted field keeps the session's global value. A
// bare number would otherwise be indistinguishable from "zero it".
type perTargetOverride struct {
	LatencyMS     *int `json:"latency"`
	JitterMS      *int `json:"jitter"`
	LossPct       *int `json:"loss"`
	DupPct        *int `json:"dup"`
	ReorderPct    *int `json:"reorder"`
	BandwidthKbps *int `json:"bandwidth"`
}

// loadPerTarget parses a --per-target file and merges each partial override
// over the session's global base values. Targets are not required to appear in
// the session; an override for an absent host is simply unused.
func loadPerTarget(path string, base engine.Impairment) (map[string]engine.Impairment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("per-target: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw map[string]perTargetOverride
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("per-target: %w", err)
	}
	out := make(map[string]engine.Impairment, len(raw))
	for ip, ov := range raw {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("per-target: invalid IP %q", ip)
		}
		merged := base
		if ov.LatencyMS != nil {
			merged.LatencyMS = *ov.LatencyMS
		}
		if ov.JitterMS != nil {
			merged.JitterMS = *ov.JitterMS
		}
		if ov.LossPct != nil {
			merged.LossPct = *ov.LossPct
		}
		if ov.DupPct != nil {
			merged.DupPct = *ov.DupPct
		}
		if ov.ReorderPct != nil {
			merged.ReorderPct = *ov.ReorderPct
		}
		if ov.BandwidthKbps != nil {
			merged.BandwidthKbps = *ov.BandwidthKbps
		}
		out[ip] = merged
	}
	return out, nil
}
