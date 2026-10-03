// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"encoding/json"
	"testing"
	"time"

	"gnulte-go/internal/history"
	"gnulte-go/internal/traffic"
)

// TestFeedTickSchema pins the per-tick JSON object: counts, per-host rates and
// latency, and the wire field names a --json consumer depends on.
func TestFeedTickSchema(t *testing.T) {
	hosts := []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}
	stats := map[string]*hostStat{
		"10.0.0.5": {color: 0},
		"10.0.0.6": {color: 1},
		"10.0.0.7": {color: 2}, // never probed
	}
	stats["10.0.0.5"].ping.add(42, 60)
	stats["10.0.0.6"].ping.add(-1, 60) // a miss, so it is up-count-wise silent
	stats["10.0.0.6"].alarm = true
	info := map[string]hostInfo{"10.0.0.5": {IP: "10.0.0.5", Host: "laptop"}}
	rates := map[string]traffic.Rate{"10.0.0.5": {RXBytes: 20000, TXBytes: 10000}}

	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tick := newFeedTick(hosts, stats, rates, info, 2, now)
	if tick.Kind != "tick" || tick.TS != "2026-10-03T12:00:00Z" {
		t.Fatalf("tick header = %+v", tick)
	}
	if tick.Up != 1 || tick.Alarms != 1 {
		t.Fatalf("counts = up %d alarms %d, want 1/1", tick.Up, tick.Alarms)
	}
	if len(tick.Hosts) != 3 {
		t.Fatalf("host rows = %d, want 3", len(tick.Hosts))
	}
	if h := tick.Hosts[0]; h.IP != "10.0.0.5" || h.Name != "laptop" || h.RTTMS != 42 ||
		h.DownBps != 10000 || h.UpBps != 5000 || h.Alarm {
		t.Fatalf("first host = %+v", h)
	}
	if h := tick.Hosts[1]; h.RTTMS != -1 || !h.Alarm {
		t.Fatalf("second host = %+v", h)
	}
	// A host that has not been probed yet reports the -2 sentinel, not 0ms.
	if h := tick.Hosts[2]; h.RTTMS != -2 || h.Alarm {
		t.Fatalf("third host = %+v", h)
	}

	// Round-trip to pin the wire field names (a renamed tag would silently
	// break every jq recipe).
	b, err := json.Marshal(tick)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["kind"] != "tick" || m["up"].(float64) != 1 || m["alarms"].(float64) != 1 {
		t.Fatalf("wire tick = %v", m)
	}
	rows, ok := m["hosts"].([]any)
	if !ok || len(rows) != 3 {
		t.Fatalf("wire hosts = %v", m["hosts"])
	}
	row := rows[0].(map[string]any)
	for _, k := range []string{"ip", "name", "rtt_ms", "loss_pct", "down_bps", "up_bps", "alarm"} {
		if _, ok := row[k]; !ok {
			t.Errorf("host object missing key %q: %v", k, row)
		}
	}
}

// TestFeedBaselineAndAlert pins the opening baseline and each alert record.
func TestFeedBaselineAndAlert(t *testing.T) {
	when := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	base := newFeedBaseline("wlan0", 4, 1, when)
	if base.Kind != "baseline" || base.Iface != "wlan0" || base.Hosts != 4 || base.Interval != 1 ||
		base.TS != "2026-10-03T12:00:00Z" {
		t.Fatalf("baseline = %+v", base)
	}
	down := newFeedAlert(watchEvent{when: when, ip: "10.0.0.9", name: "cam", up: false})
	if down.Kind != "alert" || down.Event != "down" || down.IP != "10.0.0.9" || down.Name != "cam" {
		t.Fatalf("down alert = %+v", down)
	}
	upAlert := newFeedAlert(watchEvent{when: when, ip: "10.0.0.9", up: true})
	if upAlert.Event != "up" {
		t.Fatalf("up alert event = %q, want up", upAlert.Event)
	}
}

// TestWatchEventsConversion drops snapshots and unparseable rows, keeping the
// up/down transitions in order.
func TestWatchEventsConversion(t *testing.T) {
	entries := []history.Entry{
		{Kind: history.KindSnapshot, TS: "2026-10-03T10:00:00Z", IP: "10.0.0.1"},
		{Kind: history.KindUp, TS: "2026-10-03T10:01:00Z", IP: "10.0.0.1", Name: "laptop"},
		{Kind: history.KindDown, TS: "2026-10-03T10:02:00Z", IP: "10.0.0.1"},
		{Kind: history.KindUp, TS: "not-a-time", IP: "10.0.0.1"},
	}
	ev := watchEvents(entries)
	if len(ev) != 2 {
		t.Fatalf("watchEvents = %d events, want 2", len(ev))
	}
	if !ev[0].up || ev[1].up {
		t.Fatalf("states = up %v then up %v, want up then down", ev[0].up, ev[1].up)
	}
	if ev[0].name != "laptop" || ev[0].ip != "10.0.0.1" {
		t.Fatalf("first event = %+v", ev[0])
	}
}
