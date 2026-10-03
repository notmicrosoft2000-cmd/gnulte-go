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
	"os"
	"path/filepath"
	"testing"

	"gnulte-go/internal/engine"
)

func TestApplyImpairmentRespectsExplicitFlags(t *testing.T) {
	ec := engine.Config{LatencyMS: 999, LossPct: 1}
	p := engine.Impairment{LatencyMS: 50, JitterMS: 10, LossPct: 5, DupPct: 1, ReorderPct: 2, BandwidthKbps: 512}
	applyImpairment(&ec, p, map[string]bool{"latency": true})
	if ec.LatencyMS != 999 {
		t.Errorf("explicit latency overwritten: %d", ec.LatencyMS)
	}
	if ec.JitterMS != 10 || ec.LossPct != 5 || ec.DupPct != 1 || ec.ReorderPct != 2 || ec.BandwidthKbps != 512 {
		t.Errorf("non-explicit fields not applied: %+v", ec)
	}
}

func TestSetImpairmentOverridesEverything(t *testing.T) {
	ec := engine.Config{LatencyMS: 999, LossPct: 1}
	p := engine.Impairment{LatencyMS: 0, JitterMS: 4, LossPct: 7, BandwidthKbps: 0}
	setImpairment(&ec, p)
	if ec.LatencyMS != 0 || ec.JitterMS != 4 || ec.LossPct != 7 || ec.BandwidthKbps != 0 {
		t.Errorf("setImpairment = %+v", ec)
	}
}

func TestLoadPerTargetMergesPartialOverBase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pt.json")
	doc := `{
	  "192.168.1.50": {"latency": 500},
	  "192.168.1.51": {"loss": 20, "bandwidth": 256}
	}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	base := engine.Impairment{LatencyMS: 100, JitterMS: 10, LossPct: 1, DupPct: 2, ReorderPct: 3, BandwidthKbps: 1000}
	got, err := loadPerTarget(path, base)
	if err != nil {
		t.Fatalf("loadPerTarget: %v", err)
	}
	a := got["192.168.1.50"]
	// Only latency changes; everything else inherits the base.
	if a.LatencyMS != 500 || a.JitterMS != 10 || a.LossPct != 1 || a.DupPct != 2 || a.ReorderPct != 3 || a.BandwidthKbps != 1000 {
		t.Errorf(".50 = %+v, want latency 500 over base", a)
	}
	b := got["192.168.1.51"]
	if b.LatencyMS != 100 || b.LossPct != 20 || b.BandwidthKbps != 256 {
		t.Errorf(".51 = %+v, want loss 20 / bw 256 over base", b)
	}
}

func TestLoadPerTargetRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	badIP := filepath.Join(dir, "badip.json")
	os.WriteFile(badIP, []byte(`{"not-an-ip": {"latency": 5}}`), 0o644)
	if _, err := loadPerTarget(badIP, engine.Impairment{}); err == nil {
		t.Error("expected an error for a non-IP key")
	}
	unknown := filepath.Join(dir, "unknown.json")
	os.WriteFile(unknown, []byte(`{"10.0.0.1": {"latancy": 5}}`), 0o644)
	if _, err := loadPerTarget(unknown, engine.Impairment{}); err == nil {
		t.Error("expected an error for an unknown field")
	}
	if _, err := loadPerTarget(filepath.Join(dir, "missing.json"), engine.Impairment{}); err == nil {
		t.Error("expected an error for a missing file")
	}
}
