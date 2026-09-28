package main

import (
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
)

func testHosts() ([]string, map[string]*hostStat) {
	hosts := []string{"192.168.100.13", "192.168.100.40", "192.168.100.207"}
	stats := map[string]*hostStat{}
	for _, ip := range hosts {
		stats[ip] = &hostStat{}
	}
	stats["192.168.100.13"].ping.add(23, 60)
	stats["192.168.100.13"].alarm = true
	stats["192.168.100.40"].ping.add(180, 60)
	stats["192.168.100.207"].ping.add(55, 60)
	return hosts, stats
}

// TestVrowsTrafficSort orders busy hosts first.
func TestVrowsTrafficSort(t *testing.T) {
	hosts, stats := testHosts()
	st := &viewState{sortMode: sortTraffic}
	rates := map[string]traffic.Rate{
		"192.168.100.13":  {RXBytes: 5_000_000, TXBytes: 10_000},
		"192.168.100.40":  {RXBytes: 50_000, TXBytes: 500_000},
		"192.168.100.207": {RXBytes: 2_000_000, TXBytes: 800_000},
	}
	rows := vrows(st, hosts, nil, rates, stats, 1, false)
	want := []string{"192.168.100.13", "192.168.100.207", "192.168.100.40"}
	for i, w := range want {
		if rows[i].ip != w {
			t.Fatalf("sortTraffic row %d = %s, want %s (order %v)", i, rows[i].ip, w, rowsIPs(rows))
		}
	}
}

// TestVrowsLatencySort puts the slowest host first.
func TestVrowsLatencySort(t *testing.T) {
	hosts, stats := testHosts()
	st := &viewState{sortMode: sortPing}
	rows := vrows(st, hosts, nil, map[string]traffic.Rate{}, stats, 1, false)
	if rows[0].ip != "192.168.100.40" {
		t.Fatalf("sortPing first = %s, want the 180ms host", rows[0].ip)
	}
}

// TestVrowsCursorClamp keeps the cursor inside the filtered set.
func TestVrowsCursorClamp(t *testing.T) {
	hosts, stats := testHosts()
	// Only one host alarms; with the alarm filter, cursor 5 must clamp to 0.
	st := &viewState{alarmOnly: true, cursor: 5}
	rows := vrows(st, hosts, nil, map[string]traffic.Rate{}, stats, 1, false)
	if len(rows) != 1 || rows[0].ip != "192.168.100.13" {
		t.Fatalf("alarm-only filter rows = %v, want just the alarming host", rowsIPs(rows))
	}
	if st.cursor != 0 {
		t.Fatalf("cursor = %d, want clamped to 0", st.cursor)
	}
}

// TestHostRowLinesDenseMarksAlarm checks the ⚠ badge lands on one line in
// dense layout.
func TestHostRowLinesDenseMarksAlarm(t *testing.T) {
	_, stats := testHosts()
	lines := hostRowLines("192.168.100.13", hostInfo{IP: "192.168.100.13", MAC: "A4:83:E7:12:34:56", Vendor: "Apple"}, traffic.Rate{}, stats["192.168.100.13"], 1, true)
	if len(lines) != 1 {
		t.Fatalf("dense lines = %d, want 1", len(lines))
	}
	if !strings.Contains(lines[0], "⚠") {
		t.Fatalf("dense alarm badge missing: %q", lines[0])
	}
}

// TestBuildViewHasCursorAndFooter renders a frame and checks the cursor
// marker and the key hints footer are present.
func TestBuildViewHasCursorAndFooter(t *testing.T) {
	hosts, stats := testHosts()
	st := &viewState{}
	out := buildView(st, hosts, nil, map[string]traffic.Rate{}, nil, nil, stats,
		"wlan0", "192.168.100.0/24", 1, time.Now(), true, true, 24)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "▸") {
		t.Fatalf("frame missing cursor marker:\n%s", all)
	}
	if !strings.Contains(all, "↑↓ host · ⏎ detail · s sort") {
		t.Fatalf("frame missing key hints:\n%s", all)
	}
	if !strings.Contains(all, "LIVE WATCH") {
		t.Fatalf("frame missing header:\n%s", all)
	}
}

// TestBuildViewDetailPane shows the identity and latency of the cursor host.
func TestBuildViewDetailPane(t *testing.T) {
	hosts, stats := testHosts()
	info := map[string]hostInfo{
		"192.168.100.13": {IP: "192.168.100.13", MAC: "A4:83:E7:12:34:56", Vendor: "Apple, Inc.", Type: "phone", Host: "cassie-phone"},
	}
	st := &viewState{detail: true, cursor: 0}
	out := buildView(st, hosts, info, map[string]traffic.Rate{}, nil, nil, stats,
		"wlan0", "", 1, time.Now(), false, true, 30)
	all := strings.Join(out, "\n")
	for _, want := range []string{"DETAIL", "cassie-phone", "Apple, Inc."} {
		if !strings.Contains(all, want) {
			t.Fatalf("detail pane missing %q:\n%s", want, all)
		}
	}
}

// TestHostSliceKeepsCursor ensures the window always includes the cursor row,
// even on a terminal too short for every row.
func TestHostSliceKeepsCursor(t *testing.T) {
	rows := make([]vrow, 20)
	for i := range rows {
		rows[i].lines = []string{" a", " b", " c"}
	}
	// Huge LAN, budget for ~5 rows (15 lines), cursor near the end.
	start, end := hostSlice(rows, 17, 15)
	if start > 17 || end <= 17 {
		t.Fatalf("hostSlice(17,15) window = [%d,%d), cursor 17 lost", start, end)
	}
	// Budget that fits only the cursor row alone.
	start, end = hostSlice(rows, 10, 2)
	if start != 10 || end != 11 {
		t.Fatalf("tiny budget window = [%d,%d), want [10,11)", start, end)
	}
	// Empty sets return an empty window.
	if s, e := hostSlice(nil, 0, 10); s != 0 || e != 0 {
		t.Fatalf("empty rows window = [%d,%d), want [0,0)", s, e)
	}
}

// TestBuildViewNeverExceedsHeight is the overflow guard: no matter how many
// panes are open, the frame must fit the terminal height.
func TestBuildViewNeverExceedsHeight(t *testing.T) {
	hosts, stats := testHosts()
	st := &viewState{detail: true, showTalk: true, showHelp: true, alarmOnly: true}
	flows := []traffic.Flow{{A: "192.168.100.13:443", B: "151.101.1.69:443", AB: 1000, BA: 200}}
	for _, h := range []int{10, 12, 18, 24, 40} {
		out := buildView(st, hosts, nil, map[string]traffic.Rate{}, flows, nil, stats,
			"wlan0", "192.168.100.0/24", 1, time.Now(), true, false, h)
		if len(out) > h {
			t.Fatalf("height %d: frame has %d lines, want ≤ %d:\n%v", h, len(out), h, out)
		}
	}
}

// TestSparkRatesRelativeScale clamps and scales to the window max.
func TestSparkRatesRelativeScale(t *testing.T) {
	got := []rune(sparkRates([]int64{0, 100, 200, 400}, 4))
	if len(got) != 4 {
		t.Fatalf("spark length = %d, want 4", len(got))
	}
	if got[0] != '▁' {
		t.Fatalf("idle sample = %q, want ▁", got[0])
	}
	if got[3] != '█' {
		t.Fatalf("max sample = %q, want █", got[3])
	}
}

// TestElapsedAndPlural sanity-check the small formatters.
func TestElapsedAndPlural(t *testing.T) {
	if plural(1) != "" || plural(2) != "s" {
		t.Fatalf("plural broken: %q / %q", plural(1), plural(2))
	}
	if e := elapsed(time.Now().Add(-95 * time.Second)); !strings.HasPrefix(e, "01:") {
		t.Fatalf("elapsed 95s = %q, want 01:…", e)
	}
	// CursorLines: first line keeps its alignment when the marker replaces the
	// leading spaces.
	lines := cursorLines([]string{"  192.0.2.1   ↓ 1.2MB/s", "   A4:83:E7"})
	if !strings.HasPrefix(lines[0], "▸ ") {
		t.Fatalf("cursor marker missing: %q", lines[0])
	}
}

func rowsIPs(rows []vrow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ip
	}
	return out
}
