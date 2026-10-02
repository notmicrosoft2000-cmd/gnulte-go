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
	"strings"
	"testing"

	"gnulte-go/internal/toptalk"
	"gnulte-go/internal/tui"
)

func sampleHosts() sample {
	return sample{
		rows: []toptalk.Row{
			{Host: "10.0.0.1", Down: 2048, Up: 1024, DownPkts: 20, UpPkts: 10, Peers: 2},
			{Host: "10.0.0.2", Down: 512, Peers: 1},
		},
		totalDown: 2560,
		totalUp:   1024,
	}
}

func TestTakeSampleWithoutCounterIsEmpty(t *testing.T) {
	s := takeSample(nil, 1, nil, false)
	if len(s.rows) != 0 || len(s.flows) != 0 || s.totalDown != 0 || s.totalUp != 0 {
		t.Fatalf("nil counter produced %+v, want an empty sample", s)
	}
}

func TestBuildDocHostsAndFlows(t *testing.T) {
	doc := buildDoc("wlan0", 2, false, sampleHosts())
	if doc.Mode != "hosts" || doc.Interface != "wlan0" || doc.IntervalSeconds != 2 {
		t.Fatalf("doc meta = %+v", doc)
	}
	if doc.TotalDownBps != 2560 || doc.TotalUpBps != 1024 {
		t.Fatalf("doc totals = %+v", doc)
	}
	if len(doc.Hosts) != 2 || doc.Hosts[0].Host != "10.0.0.1" || doc.Hosts[0].TotalBps != 3072 || doc.Hosts[0].Peers != 2 {
		t.Fatalf("doc hosts = %+v", doc.Hosts)
	}

	fdoc := buildDoc("eth0", 1, true, sample{
		flows: []toptalk.Flow{{A: "a:1", B: "b:2", AB: 100, BA: 50}},
	})
	if fdoc.Mode != "flows" || len(fdoc.Flows) != 1 || fdoc.Flows[0].TotalBps != 150 {
		t.Fatalf("flow doc = %+v", fdoc)
	}
	if len(fdoc.Hosts) != 0 {
		t.Fatalf("flow doc should not carry hosts: %+v", fdoc.Hosts)
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var b bytes.Buffer
	if err := writeJSON(&b, buildDoc("wlan0", 1, false, sampleHosts())); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	var got jsonDoc
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, b.String())
	}
	if got.Hosts[0].DownBps != 2048 || got.Hosts[0].Peers != 2 || got.Hosts[1].TotalBps != 512 {
		t.Fatalf("round-tripped doc = %+v", got)
	}
}

func TestWriteCSVHosts(t *testing.T) {
	var b bytes.Buffer
	if err := writeCSV(&b, sampleHosts(), false); err != nil {
		t.Fatalf("writeCSV: %v", err)
	}
	got := b.String()
	if !strings.HasPrefix(got, "host,down_bps,up_bps,down_pkts,up_pkts,peers,total_bps\n") {
		t.Fatalf("missing CSV header:\n%s", got)
	}
	if !strings.Contains(got, "10.0.0.1,2048,1024,20,10,2,3072\n") {
		t.Fatalf("missing first host row:\n%s", got)
	}
	if !strings.Contains(got, "10.0.0.2,512,0,0,0,1,512\n") {
		t.Fatalf("missing second host row:\n%s", got)
	}
}

func TestWriteCSVFlows(t *testing.T) {
	var b bytes.Buffer
	if err := writeCSV(&b, sample{flows: []toptalk.Flow{{A: "a:1", B: "b:2", AB: 100, BA: 50}}}, true); err != nil {
		t.Fatalf("writeCSV: %v", err)
	}
	got := b.String()
	if !strings.HasPrefix(got, "a,b,a_to_b_bps,b_to_a_bps,total_bps\n") {
		t.Fatalf("missing flow CSV header:\n%s", got)
	}
	if !strings.Contains(got, "a:1,b:2,100,50,150\n") {
		t.Fatalf("missing flow row:\n%s", got)
	}
}

func TestSampleLinesShowEmptyStates(t *testing.T) {
	hosts := strings.Join(sampleLines("wlan0", sample{}, false), "\n")
	if !strings.Contains(hosts, "no host traffic") {
		t.Fatalf("empty host view = %q", hosts)
	}
	flows := strings.Join(sampleLines("wlan0", sample{}, true), "\n")
	if !strings.Contains(flows, "no conversations") {
		t.Fatalf("empty flow view = %q", flows)
	}
}

func TestPlaceholderSaysMeasuring(t *testing.T) {
	if !strings.Contains(strings.Join(placeholder("wlan0", false), "\n"), "measuring") {
		t.Fatal("placeholder should say it is measuring")
	}
}

func TestIsQuitKeyTop(t *testing.T) {
	if !isQuitKey(tui.KeyRune, 'q') || !isQuitKey(tui.KeyEsc, 0) || !isQuitKey(tui.KeyEnter, 0) {
		t.Fatal("q, Esc and Enter should quit")
	}
	if isQuitKey(tui.KeyRune, 'x') {
		t.Fatal("x should not quit")
	}
}
