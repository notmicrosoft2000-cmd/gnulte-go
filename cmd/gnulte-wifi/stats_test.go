// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.

package main

import (
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/airframes"
)

func TestParseStations(t *testing.T) {
	stations, err := ParseStations(" 00:0c:41:63:45:6a , aa-bb-cc-dd-ee-ff ")
	if err != nil {
		t.Fatal(err)
	}
	if len(stations) != 2 || stations[0].String() != "00:0c:41:63:45:6a" || stations[1].String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected stations: %v", stations)
	}
	// A broadcast target stays a valid single entry.
	bc, err := ParseStations(airframes.Broadcast)
	if err != nil || len(bc) != 1 || !bc[0].IsBroadcast() {
		t.Fatalf("broadcast parse = %v, %v", bc, err)
	}
	for _, bad := range []string{"", "aa:bb:cc:dd:ee:ff,", ",aa:bb:cc:dd:ee:ff", "not-a-mac"} {
		if _, err := ParseStations(bad); err == nil {
			t.Errorf("ParseStations(%q) should fail", bad)
		}
	}
}

func TestStationForBurstStreer(t *testing.T) {
	stations := []airframes.MAC{
		mustMAC(t, "00:00:00:00:00:01"),
		mustMAC(t, "00:00:00:00:00:02"),
		mustMAC(t, "00:00:00:00:00:03"),
	}
	// Streak 1 alternates each burst; streak 2 holds each station for two.
	want1 := []int{0, 1, 2, 0, 1}
	for burst, idx := range want1 {
		if got := stationForBurst(stations, burst, 1); got != stations[idx] {
			t.Errorf("streak 1 burst %d = %s, want %s", burst, got, stations[idx])
		}
	}
	want2 := []int{0, 0, 1, 1, 2, 2, 0, 0}
	for burst, idx := range want2 {
		if got := stationForBurst(stations, burst, 2); got != stations[idx] {
			t.Errorf("streak 2 burst %d = %s, want %s", burst, got, stations[idx])
		}
	}
	// A single station is unaffected by streak, and streak 0 behaves as 1.
	if got := stationForBurst(stations[:1], 99, 5); got != stations[0] {
		t.Errorf("single station changed: %s", got)
	}
	if got := stationForBurst(stations, 1, 0); got != stations[1] {
		t.Errorf("streak 0 should act as 1, got %s", got)
	}
	if got := stationForBurst(nil, 0, 1); got != (airframes.MAC{}) {
		t.Errorf("empty stations should return zero MAC, got %s", got)
	}
}

func mustMAC(t *testing.T, s string) airframes.MAC {
	t.Helper()
	m, err := airframes.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestJitterStats(t *testing.T) {
	var j JitterStats
	if got := j.String(); got != "no frames" {
		t.Errorf("empty stats = %q", got)
	}
	for _, ms := range []int{1, 0, 3, 2, 0} {
		j.Add(ms)
	}
	if j.Frames() != 5 || j.Delayed() != 3 {
		t.Errorf("frames=%d delayed=%d, want 5/3", j.Frames(), j.Delayed())
	}
	if j.Min() != 0 || j.Max() != 3 {
		t.Errorf("min=%d max=%d, want 0/3", j.Min(), j.Max())
	}
	if j.Total() != 6*time.Millisecond {
		t.Errorf("total = %s, want 6ms", j.Total())
	}
	if mean := j.Mean(); mean < 1.19 || mean > 1.21 {
		t.Errorf("mean = %f, want ~1.2", mean)
	}
	got := j.String()
	for _, want := range []string{"3/5 frames delayed", "0-3 ms", "6ms"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() %q missing %q", got, want)
		}
	}
	// All-zero jitter still counts frames without claiming any were delayed.
	var zero JitterStats
	zero.Add(0)
	zero.Add(0)
	if zero.Delayed() != 0 || zero.Min() != 0 || zero.Max() != 0 {
		t.Errorf("zero jitter stats wrong: %s", zero.String())
	}
}

func TestDwellStats(t *testing.T) {
	var d DwellStats
	d.Record(11, 2, 10*time.Second)
	d.Record(1, 3, 15*time.Second)
	d.Record(11, 1, 5*time.Second)
	rows := d.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Channel != 1 || rows[0].Bursts != 3 || rows[0].Dwell != 15*time.Second {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Channel != 11 || rows[1].Bursts != 3 || rows[1].Dwell != 15*time.Second {
		t.Errorf("row 1 = %+v", rows[1])
	}
	got := FormatDwell(rows)
	if !strings.Contains(got, "ch 1: 3B / 15.0s") || !strings.Contains(got, "ch 11: 3B / 15.0s") {
		t.Errorf("FormatDwell = %q", got)
	}
	if empty := FormatDwell(nil); empty != "no channel data" {
		t.Errorf("empty FormatDwell = %q", empty)
	}
}
