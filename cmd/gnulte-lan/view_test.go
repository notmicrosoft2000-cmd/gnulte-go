package main

import (
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
	"gnulte-go/internal/ux"
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
	rows := vrows(st, hosts, nil, rates, stats, 1, layoutNormal)
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
	rows := vrows(st, hosts, nil, map[string]traffic.Rate{}, stats, 1, layoutNormal)
	if rows[0].ip != "192.168.100.40" {
		t.Fatalf("sortPing first = %s, want the 180ms host", rows[0].ip)
	}
}

// TestVrowsCursorClamp keeps the cursor inside the filtered set.
func TestVrowsCursorClamp(t *testing.T) {
	hosts, stats := testHosts()
	// Only one host alarms; with the alarm filter, cursor 5 must clamp to 0.
	st := &viewState{alarmOnly: true, cursor: 5}
	rows := vrows(st, hosts, nil, map[string]traffic.Rate{}, stats, 1, layoutNormal)
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

// TestWatchRowStableHeight pins the invariant behind the "no jumping" fix:
// every host occupies exactly three lines no matter how little is known, so
// rows arriving (or an identity resolving mid-watch) never resizes the frame.
func TestWatchRowStableHeight(t *testing.T) {
	cases := map[string]*hostStat{
		"bare": &hostStat{},
		"pings": func() *hostStat {
			s := &hostStat{}
			s.ping.add(20, 60)
			return s
		}(),
		"alarmed": func() *hostStat {
			s := &hostStat{}
			s.ping.add(120, 60)
			s.alarm = true
			return s
		}(),
	}
	for name, st := range cases {
		rows := watchRow("192.0.2.10", hostInfo{Host: "cassie-phone"}, traffic.Rate{TXBytes: 5000}, st, 1)
		if len(rows) != 3 {
			t.Fatalf("%s: %d lines, want 3\n%v", name, len(rows), rows)
		}
		for _, ln := range rows {
			if ux.RuneLen(ux.StripAnsi(ln)) > 80 {
				t.Fatalf("%s: row over 80 cols: %q", name, ln)
			}
		}
	}
	// An alarming host must not push its rate columns right (the badge column
	// is reserved): the "↓" of both rows must start at the same column.
	quiet := watchRow("192.0.2.10", hostInfo{}, traffic.Rate{TXBytes: 1}, &hostStat{}, 1)
	loud := watchRow("192.0.2.10", hostInfo{}, traffic.Rate{TXBytes: 1}, func() *hostStat {
		s := &hostStat{}
		s.ping.add(20, 60)
		s.alarm = true
		return s
	}(), 1)
	col := func(s string) int { return strings.Index(s, "↓") }
	if col(quiet[0]) != col(loud[0]) {
		t.Fatalf("alarm badge shifts rate column: quiet ↓ at %d, loud at %d\n%q\n%q",
			col(quiet[0]), col(loud[0]), quiet[0], loud[0])
	}
}

// TestBuildViewHasCursorAndFooter renders a frame and checks the cursor
// marker and the key hints footer are present.
func TestBuildViewHasCursorAndFooter(t *testing.T) {
	hosts, stats := testHosts()
	st := &viewState{}
	env := watchEnv{
		nic: "wlan0", subnet: "192.168.100.0/24",
		selfIP: "192.168.100.207", gwIP: "192.168.100.1", gwRTT: 3,
		iv: 1, start: time.Now(), alarmOn: true, hasCounter: true,
	}
	out := buildView(st, hosts, nil, map[string]traffic.Rate{}, nil, nil, stats, env, 24)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "▸") {
		t.Fatalf("frame missing cursor marker:\n%s", all)
	}
	if !strings.Contains(all, "↑↓ host · ⏎ test with gnulte") {
		t.Fatalf("frame missing key hints:\n%s", all)
	}
	if !strings.Contains(all, "LIVE LAN WATCH") {
		t.Fatalf("frame missing header:\n%s", all)
	}
	if !strings.Contains(all, "self 192.168.100.207") {
		t.Fatalf("frame missing self line:\n%s", all)
	}
	if !strings.Contains(all, "gw 192.168.100.1") || !strings.Contains(all, "↔ 3ms") {
		t.Fatalf("frame missing gateway latency:\n%s", all)
	}
}

// TestBuildViewDetailPane shows the identity and latency of the cursor host,
// plus the gnulte test recipe.
func TestBuildViewDetailPane(t *testing.T) {
	hosts, stats := testHosts()
	info := map[string]hostInfo{
		"192.168.100.13": {IP: "192.168.100.13", MAC: "A4:83:E7:12:34:56", Vendor: "Apple, Inc.", Type: "phone", Host: "cassie-phone"},
	}
	st := &viewState{detail: true, cursor: 0}
	env := watchEnv{nic: "wlan0", iv: 1, start: time.Now(), hasCounter: true, gwRTT: -2}
	out := buildView(st, hosts, info, map[string]traffic.Rate{}, nil, nil, stats, env, 30)
	all := strings.Join(out, "\n")
	for _, want := range []string{"DETAIL", "cassie-phone", "Apple, Inc.", "test with: gnulte -t 192.168.100.13"} {
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
// screens and panes are open, the frame must fit the terminal height.
func TestBuildViewNeverExceedsHeight(t *testing.T) {
	hosts, stats := testHosts()
	flows := []traffic.Flow{
		{A: "192.168.100.13:443", B: "151.101.1.69:443", AB: 1000, BA: 200, ABp: 5, BAp: 2},
		{A: "192.168.100.13:443", B: "192.168.100.40:53", AB: 400, BA: 300, ABp: 4, BAp: 4},
	}
	for _, sc := range []int{scrHosts, scrTalkers, scrFlows, scrArp, scrMap, scrHistory} {
		for _, h := range []int{10, 12, 18, 24, 40} {
			st := &viewState{detail: true, showHelp: true, screen: sc}
			env := watchEnv{nic: "wlan0", subnet: "192.168.100.0/24", iv: 1, start: time.Now(),
				alarmOn: true, gwRTT: -2, hasCounter: true, width: 120,
				neigh: map[string]string{"192.168.100.13": "A4:83:E7:12:34:56"}}
			out := buildView(st, hosts, nil, map[string]traffic.Rate{}, flows, map[string]bool{}, stats, env, h)
			if len(out) > h {
				t.Fatalf("screen %d height %d: frame has %d lines, want ≤ %d:\n%v",
					sc, h, len(out), h, out)
			}
		}
	}
}

// TestIpCellUsesHostHue pins the per-IP colouring: the IP cell is wrapped in
// the host's stable hue (padded to width), so a device stays recognisable by
// colour on every screen.
func TestIpCellUsesHostHue(t *testing.T) {
	got := ipCell("192.168.100.13", 3, 15)
	if got != ux.C(ux.Hue(3), ux.TruncPad("192.168.100.13", 15)) {
		t.Fatalf("ipCell = %q, want the host's hue wrapper", got)
	}
	// The hue index rides on the hostStat, wired in vrows rows.
	s := &hostStat{color: 2}
	rows := watchRow("10.0.0.1", hostInfo{}, traffic.Rate{}, s, 1)
	got = strings.TrimSpace(ux.StripAnsi(rows[0]))
	if !strings.HasPrefix(got, "10.0.0.1") {
		t.Fatalf("row must lead with the coloured IP cell, got %q", got)
	}
}

// TestWatchRowCompactTwoLines and the wide variant pin the width-scaled row
// shapes: each band is internally stable and never wider than its terminal.
func TestWatchRowCompactTwoLines(t *testing.T) {
	st := &hostStat{color: 1}
	st.ping.add(12, 60)
	rows := watchRowCompact("192.0.2.7", hostInfo{Host: "radio"}, traffic.Rate{RXBytes: 9000}, st, 1)
	if len(rows) != 2 {
		t.Fatalf("compact row = %d lines, want 2:\n%v", len(rows), rows)
	}
	for _, ln := range rows {
		if ux.RuneLen(ux.StripAnsi(ln)) > 78 {
			t.Fatalf("compact line over 78 cols: %q", ln)
		}
	}
	// A bare host still fills both lines (stable height).
	bare := watchRowCompact("192.0.2.7", hostInfo{}, traffic.Rate{}, &hostStat{color: 1}, 1)
	if len(bare) != 2 {
		t.Fatalf("compact bare row = %d lines, want 2", len(bare))
	}
}

func TestWatchRowWideFourLines(t *testing.T) {
	st := &hostStat{color: 4}
	for _, rtt := range []int{10, 20, 30, 40, 50} {
		st.ping.add(rtt, 60)
	}
	st.addRate(2_000_000, 300_000, 60)
	rows := watchRowWide("192.0.2.9", hostInfo{Host: "printer-lobby"}, traffic.Rate{TXBytes: 5000}, st, 1)
	if len(rows) != 4 {
		t.Fatalf("wide row = %d lines, want 4:\n%v", len(rows), rows)
	}
	all := strings.Join(rows, "\n")
	if !strings.Contains(all, "p50 30ms") || !strings.Contains(all, "p95 50ms") {
		t.Fatalf("wide row missing percentiles:\n%s", all)
	}
	if !strings.Contains(all, "session ↓") || !strings.Contains(all, "bytes ↓") {
		t.Fatalf("wide row missing session-total line:\n%s", all)
	}
	for _, ln := range rows {
		if ux.RuneLen(ux.StripAnsi(ln)) > 116 {
			t.Fatalf("wide line over 116 cols: %q", ln)
		}
	}
}

// TestLayoutForBands pins the width thresholds of the scaled TUI.
func TestLayoutForBands(t *testing.T) {
	cases := []struct {
		w    int
		want int
	}{
		{40, layoutCompact}, {77, layoutCompact},
		{78, layoutNormal}, {115, layoutNormal},
		{116, layoutWide}, {200, layoutWide},
		{0, layoutNormal}, // unknown width (non-TTY/tests) defaults to normal
	}
	for _, tc := range cases {
		if got := layoutFor(tc.w); got != tc.want {
			t.Fatalf("layoutFor(%d) = %d, want %d", tc.w, got, tc.want)
		}
	}
}

// TestTalkersScreenRanksByRate builds screen 2: busiest host first, bars
// scaled to the max, peer counts, and the LAN-internal communicators block.
func TestTalkersScreenRanksByRate(t *testing.T) {
	hosts, stats := testHosts()
	rates := map[string]traffic.Rate{
		"192.168.100.13":  {RXBytes: 5_000_000, TXBytes: 10_000},
		"192.168.100.40":  {RXBytes: 50_000, TXBytes: 500_000},
		"192.168.100.207": {RXBytes: 2_000_000, TXBytes: 800_000},
	}
	flows := []traffic.Flow{
		{A: "192.168.100.13:443", B: "8.8.8.8:443", AB: 1000, BA: 200},
		{A: "192.168.100.13:443", B: "192.168.100.40:53", AB: 400, BA: 300},
	}
	hostSet := map[string]bool{}
	for _, ip := range hosts {
		hostSet[ip] = true
	}
	env := watchEnv{iv: 1, subnet: "192.168.100.0/24", hasCounter: true, width: 120}
	out := talkersLines(hosts, nil, rates, stats, flows, hostSet, env, 30)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "TOP TALKERS") {
		t.Fatalf("talkers header missing:\n%s", all)
	}
	// Busiest (13: 5,010,000) must rank #1 and lead its row.
	if !strings.Contains(out[1], "192.168.100.13") {
		t.Fatalf("busiest host not first:\n%v", out[:3])
	}
	if !strings.Contains(all, "▁") && !strings.Contains(all, "█") {
		t.Fatalf("rate bars missing:\n%s", all)
	}
	if !strings.Contains(all, "COMMUNICATORS") || !strings.Contains(all, "⟷LAN") {
		t.Fatalf("LAN-internal communicators block missing:\n%s", all)
	}
	if !strings.Contains(all, "peers 2") {
		t.Fatalf("peer count missing (13 talks to 8.8.8.8 and 40):\n%s", all)
	}
}

// TestFlowsScreenListsPairsAndGates: with the capture socket the pair table
// renders; without it the screen explains the root requirement instead.
func TestFlowsScreenListsPairsAndGates(t *testing.T) {
	_, stats := testHosts()
	flows := []traffic.Flow{
		{A: "192.168.100.13:443", B: "8.8.8.8:443", AB: 1200, BA: 900, ABp: 7, BAp: 5},
	}
	hostSet := map[string]bool{"192.168.100.13": true, "192.168.100.40": true, "192.168.100.207": true}
	env := watchEnv{iv: 1, subnet: "192.168.100.0/24", hasCounter: true, width: 120}
	out := flowsLines(flows, hostSet, stats, env, 30)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "8.8.8.8:443") || !strings.Contains(all, "A→B") {
		t.Fatalf("flow pair missing:\n%s", all)
	}

	env.hasCounter = false
	out = flowsLines(flows, hostSet, stats, env, 30)
	all = strings.Join(out, "\n")
	if !strings.Contains(all, "⛔") || !strings.Contains(all, "sudo gnulte-lan") {
		t.Fatalf("root gate missing:\n%s", all)
	}
}

// TestArpScreenShowsNeighbours: the ARP screen renders watched hosts with
// ping/grade and unknown neighbours dimmed, and recovers the vendor from the
// MAC even for hosts outside the watch list.
func TestArpScreenShowsNeighbours(t *testing.T) {
	hosts, stats := testHosts()
	stats["192.168.100.13"].ping.add(23, 60)
	info := map[string]hostInfo{
		"192.168.100.13": {IP: "192.168.100.13", MAC: "A4:83:E7:12:34:56", Vendor: "Apple, Inc.", Type: "phone", Host: "cassie-phone"},
	}
	env := watchEnv{iv: 1, width: 120, hasCounter: true,
		neigh: map[string]string{
			"192.168.100.13": "A4:83:E7:12:34:56",
			"192.168.100.1":  "00:11:22:33:44:55", // the router, not watched
		}}
	st := &viewState{}
	out := arpLines(st, hosts, info, stats, env, 30)
	all := strings.Join(out, "\n")
	for _, want := range []string{"NEIGHBOURS", "A4:83:E7:12:34:56", "Apple, Inc.", "ping 23ms", "192.168.100.1", "00:11:22:33:44:55"} {
		if !strings.Contains(all, want) {
			t.Fatalf("ARP screen missing %q:\n%s", want, all)
		}
	}
}

// TestBarFillsLeftToRight spot-checks the talkers scale bars.
func TestBarFillsLeftToRight(t *testing.T) {
	if got := bar(0, 1000, 4); got != "    " {
		t.Fatalf("bar(0) = %q, want blank", got)
	}
	if got := bar(800, 1000, 4); !strings.HasPrefix(got, "█") {
		t.Fatalf("bar(800/1000,4) = %q, want full cells at the left", got)
	}
	if got := bar(1000, 1000, 4); got != "████" {
		t.Fatalf("bar(max) = %q, want full", got)
	}
	full := bar(1000, 1000, 6)
	if ux.RuneLen(full) != 6 {
		t.Fatalf("bar width = %d, want 6", ux.RuneLen(full))
	}
}

// TestLanPair classifies LAN-internal conversation pairs.
func TestLanPair(t *testing.T) {
	if !lanPair("192.168.100.13:443", "192.168.100.40:53", "192.168.100.0/24") {
		t.Fatal("two LAN hosts should be an internal pair")
	}
	if lanPair("192.168.100.13:443", "8.8.8.8:443", "192.168.100.0/24") {
		t.Fatal("a host and the internet should not be tagged LAN-internal")
	}
	if lanPair("192.168.100.13:443", "192.168.99.40:53", "192.168.100.0/24") {
		t.Fatal("a host outside the subnet should not match")
	}
}

// TestEnvHeaderShowsNetRates verifies the header's LAN-wide net line.
func TestEnvHeaderShowsNetRates(t *testing.T) {
	hosts, _ := testHosts()
	rates := map[string]traffic.Rate{
		"192.168.100.13":  {RXBytes: 1024 * 1024 * 2},
		"192.168.100.40":  {RXBytes: 1024 * 512},
		"192.168.100.207": {TXBytes: 1024 * 1024},
	}
	env := watchEnv{nic: "wlan0", subnet: "192.168.100.0/24", iv: 1, start: time.Now(),
		selfIP: "192.168.100.207", gwIP: "192.168.100.1", gwRTT: 3, hasCounter: true}
	out := envHeader(&viewState{screen: scrHosts}, hosts, rates, env)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "net ↓ 2") || !strings.Contains(all, "↑ 1") {
		t.Fatalf("header net totals missing:\n%s", all)
	}
	if !strings.Contains(all, "HOSTS") {
		t.Fatalf("screen tag missing:\n%s", all)
	}
	env.hasCounter = false
	out = envHeader(&viewState{screen: scrFlows}, hosts, rates, env)
	if !strings.Contains(strings.Join(out, "\n"), "speeds-free") {
		t.Fatalf("speeds-free marker missing on no-socket runs:\n%v", out)
	}
}

// TestFooterHintsPerScreen confirms every screen explains its own keys.
func TestFooterHintsPerScreen(t *testing.T) {
	if !strings.Contains(footerHint(&viewState{screen: scrHosts}), "↑↓ host") {
		t.Fatal("hosts footer lost the host navigation hints")
	}
	for _, sc := range []int{scrTalkers, scrFlows, scrArp, scrMap, scrHistory} {
		if !strings.Contains(footerHint(&viewState{screen: sc}), "q quit") {
			t.Fatalf("screen %d footer missing quit hint", sc)
		}
	}
}

// mapTestEnv builds a small watched world for the map tests: three hosts
// (self .207, gateway .1, one device), hues assigned in appearance order.
func mapTestEnv(width int, counter bool) (hosts []string, info map[string]hostInfo,
	rates map[string]traffic.Rate, stats map[string]*hostStat, flows []traffic.Flow,
	hostSet map[string]bool, env watchEnv) {

	hosts = []string{"192.168.100.13", "192.168.100.40"}
	info = map[string]hostInfo{
		"192.168.100.13": {IP: "192.168.100.13", MAC: "A4:83:E7:12:34:56", Vendor: "Xiaomi", Host: "phone", Type: "Phone"},
		"192.168.100.40": {IP: "192.168.100.40", MAC: "B4:2E:99:11:22:33", Vendor: "ACME", Host: "laptop", Type: "Laptop"},
	}
	rates = map[string]traffic.Rate{}
	stats = map[string]*hostStat{
		"192.168.100.13": {color: 0},
		"192.168.100.40": {color: 1},
	}
	flows = []traffic.Flow{
		{A: "192.168.100.13:443", B: "192.168.100.40:12345", AB: 5_000_000, BA: 300_000, ABp: 50, BAp: 30},
		{A: "192.168.100.13:443", B: "192.168.100.1:443", AB: 100_000, BA: 400_000, ABp: 10, BAp: 8},
	}
	hostSet = map[string]bool{"192.168.100.13": true, "192.168.100.40": true}
	env = watchEnv{nic: "wlan0", subnet: "192.168.100.0/24", selfIP: "192.168.100.207",
		gwIP: "192.168.100.1", gwRTT: 3, iv: 1, hasCounter: counter, width: width,
		neigh: map[string]string{"192.168.100.1": "28:30:AC:AA:BB:CC"}}
	return
}

// TestMapLinesGatesWithoutSocket: the map needs the capture socket for its
// edges and must explain itself with the same gate the FLOWS screen uses.
func TestMapLinesGatesWithoutSocket(t *testing.T) {
	hosts, info, rates, stats, flows, hostSet, env := mapTestEnv(100, false)
	out := mapLines(hosts, info, rates, stats, flows, hostSet, env, 30)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "⛔") || !strings.Contains(all, "sudo gnulte-lan") {
		t.Fatalf("map without socket must gate:\n%s", all)
	}
	if strings.Contains(all, "LIVE EDGES") {
		t.Fatal("gated map must not render edges")
	}
}

// TestMapLinesRendersNodesAndEdges: with the socket live the map draws the
// gateway + self hub cards, every device as a hue node, and the interval's
// pairs as edges with the busiest one pulsing.
func TestMapLinesRendersNodesAndEdges(t *testing.T) {
	hosts, info, rates, stats, flows, hostSet, env := mapTestEnv(120, true)
	env.pulse = true
	out := mapLines(hosts, info, rates, stats, flows, hostSet, env, 40)
	all := strings.Join(out, "\n")
	for _, want := range []string{
		"INTERCONNECTION MAP", "192.168.100.1", "192.168.100.207",
		"192.168.100.13", "192.168.100.40", "LIVE EDGES", "phone", "laptop",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("map missing %q:\n%s", want, all)
		}
	}
	if !strings.Contains(all, "▸") {
		t.Errorf("busiest edge should pulse with ▸:\n%s", all)
	}
	if len(out) > 40 {
		t.Fatalf("map exceeded budget: %d lines", len(out))
	}
}

// TestMapGridColumns scales the node cards to the terminal width.
func TestMapGridColumns(t *testing.T) {
	hosts, info, _, stats, _, _, _ := mapTestEnv(120, true)
	nodes := mapNodes(hosts, info, stats, watchEnv{selfIP: "192.168.100.207", gwIP: "192.168.100.1"})
	if len(nodes) != 2 {
		t.Fatalf("node set = %d, want 2 (self and gateway excluded)", len(nodes))
	}
	for _, n := range nodes {
		if n.hue != 0 && n.hue != 1 {
			t.Errorf("node hue = %d, want the hostStat slot", n.hue)
		}
	}
	// 3 columns on a wide terminal: 2 nodes → single row, 2 lines per card.
	wide := mapGrid(nodes, watchEnv{width: 120})
	if len(wide) != 2 {
		t.Fatalf("wide grid lines = %d, want 2 (one row of 2-line cards)", len(wide))
	}
	// 1 column on a narrow terminal: compact one-line cards.
	narrow := mapGrid(nodes, watchEnv{width: 70})
	if len(narrow) != 2 {
		t.Fatalf("narrow grid lines = %d, want 2 (one per node)", len(narrow))
	}
	for _, line := range narrow {
		if ux.RuneLen(ux.StripAnsi(line)) > 78 {
			t.Fatalf("narrow grid line over 78 cols: %q", line)
		}
	}
}

// TestMapLinksPulseFree: without the pulse flag every edge line is plain.
func TestMapLinksPulseFree(t *testing.T) {
	_, _, _, stats, flows, hostSet, env := mapTestEnv(100, true)
	env.pulse = false
	edges := []traffic.Flow{}
	for _, f := range flows {
		if mapEndpHost(f.A, hostSet, env) && mapEndpHost(f.B, hostSet, env) {
			edges = append(edges, f)
		}
	}
	if len(edges) == 0 {
		t.Fatal("expected at least one map edge")
	}
	lines := mapLinks(edges, stats, env)
	if strings.Contains(strings.Join(lines, "\n"), "▸") {
		t.Fatalf("pulse must be off without the flag:\n%v", lines)
	}
}

// TestMapEndpHost filters edges to the map's own world.
func TestMapEndpHost(t *testing.T) {
	_, _, _, _, _, hostSet, env := mapTestEnv(100, true)
	if !mapEndpHost("192.168.100.13:443", hostSet, env) {
		t.Fatal("watched host must be on the map")
	}
	if !mapEndpHost("192.168.100.1:443", hostSet, env) {
		t.Fatal("gateway must be on the map")
	}
	if !mapEndpHost("192.168.100.207:80", hostSet, env) {
		t.Fatal("self must be on the map")
	}
	if mapEndpHost("8.8.8.8:53", hostSet, env) {
		t.Fatal("an outside host must not be on the map")
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
