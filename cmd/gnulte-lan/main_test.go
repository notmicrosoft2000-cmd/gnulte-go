package main

import (
	"strconv"
	"strings"
	"testing"

	"gnulte-go/internal/traffic"
)

func TestBuildLinesSparseShowsIdentityAndPing(t *testing.T) {
	hosts := []string{"192.0.2.1", "192.0.2.2"}
	info := map[string]hostInfo{
		"192.0.2.1": {IP: "192.0.2.1", MAC: "00:11:22:33:44:55", Vendor: "Acme", Type: "phone", Host: "andrew-phone"},
	}
	rates := map[string]traffic.Rate{
		"192.0.2.1": {RXBytes: 1200, RXPkts: 4, TXBytes: 600, TXPkts: 2},
	}
	flows := []traffic.Flow{
		{A: "192.0.2.1:443", B: "8.8.8.8:443", AB: 1400, BA: 200, ABp: 3, BAp: 1},
	}
	watched := map[string]bool{"192.0.2.1": true, "192.0.2.2": true}
	stats := map[string]*hostStat{hosts[0]: {}, hosts[1]: {}}
	for i := 0; i < 40; i++ {
		stats[hosts[0]].ping.add(14, 30)
	}
	stats[hosts[0]].ping.add(-1, 30)
	stats[hosts[0]].addRate(1200, 600, 60)

	lines := buildLines(hosts, info, rates, flows, watched, stats, "eth0", 1)
	joined := strings.Join(lines, "\n")

	if !strings.Contains(joined, "1.2KB/s") || !strings.Contains(joined, "↑ 600B/s") {
		t.Fatalf("down/up rates missing:\n%s", joined)
	}
	if !strings.Contains(joined, "00:11:22:33:44:55") || !strings.Contains(joined, "andrew-phone") {
		t.Fatalf("identity row missing:\n%s", joined)
	}
	if !strings.Contains(joined, "avg 14ms") {
		t.Fatalf("ping average missing:\n%s", joined)
	}
	if !strings.Contains(joined, "loss 2%") {
		t.Fatalf("loss missing (41 pings, 1 drop):\n%s", joined)
	}
	if !strings.Contains(joined, "▂") {
		t.Fatalf("sparkline blocks missing:\n%s", joined)
	}
	if !strings.Contains(joined, "TOP TALKERS") || !strings.Contains(joined, "8.8.8.8:443") {
		t.Fatalf("top-talkers pane missing:\n%s", joined)
	}
	// The second host has no identity: the fallback note appears, not a gap.
	if !strings.Contains(joined, "no identity") {
		t.Fatalf("no-identity fallback missing:\n%s", joined)
	}
}

func TestBuildLinesDenseOneRowPerHost(t *testing.T) {
	hosts := make([]string, 10)
	info := map[string]hostInfo{}
	stats := map[string]*hostStat{}
	watched := map[string]bool{}
	for i := range hosts {
		ip := "10.0.0." + strconv.Itoa(i+1)
		hosts[i] = ip
		stats[ip] = &hostStat{ping: pinger{count: 5, total: 100, last: 20}}
		watched[ip] = true
		info[ip] = hostInfo{IP: ip, MAC: "00:11:22:33:44:55", Vendor: "Acme", Type: "phone", Host: "dev-" + ip}
	}
	rates := map[string]traffic.Rate{}
	for _, ip := range hosts {
		rates[ip] = traffic.Rate{RXBytes: 100, TXBytes: 50}
	}
	lines := buildLines(hosts, info, rates, nil, watched, stats, "eth0", 1)
	// 10 hosts × 1 dense row + rule/header/blank(3) + blank/rule/total/time(4) = 17.
	if len(lines) != 17 {
		t.Fatalf("dense frame has %d lines, want 17:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "MAC") || strings.Contains(joined, "avg ") {
		t.Fatalf("dense mode leaked a two-line identity/ping row:\n%s", joined)
	}
	for _, ip := range hosts {
		if !strings.Contains(joined, ip) {
			t.Fatalf("dense frame lost host %s", ip)
		}
	}
}

func TestBuildLinesAlarmMarker(t *testing.T) {
	hosts := []string{"192.0.2.1"}
	stats := map[string]*hostStat{hosts[0]: {alarm: true}}
	lines := buildLines(hosts, nil, map[string]traffic.Rate{}, nil,
		map[string]bool{hosts[0]: true}, stats, "eth0", 1)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "⚠") {
		t.Fatalf("alarm marker missing:\n%s", joined)
	}
}

func TestFlowViewPicksWatchedEnd(t *testing.T) {
	f := traffic.Flow{A: "8.8.8.8:443", B: "192.0.2.1:49321", AB: 1000, BA: 500}
	watched := map[string]bool{"192.0.2.1": true}

	// B is the watched host: local=B, down = AB (1000B into B), up = BA.
	ip, peer, down, up := flowView(f, watched)
	if ip != "192.0.2.1" || peer != "8.8.8.8" {
		t.Fatalf("flowView local/peer = %q/%q, want 192.0.2.1/8.8.8.8", ip, peer)
	}
	if down != 1000 || up != 500 {
		t.Fatalf("flowView down/up = %d/%d, want 1000/500 from B's view", down, up)
	}

	// Neither watched: A's view, down = BA.
	ip, _, down, up = flowView(f, map[string]bool{})
	if ip != "8.8.8.8" {
		t.Fatalf("flowView default local = %q, want A", ip)
	}
	if down != 500 || up != 1000 {
		t.Fatalf("flowView default down/up = %d/%d, want 500/1000 from A's view", down, up)
	}

	// Both watched: A's view wins.
	ip, _, down, up = flowView(f, map[string]bool{"192.0.2.1": true, "8.8.8.8": true})
	if ip != "8.8.8.8" || down != 500 || up != 1000 {
		t.Fatalf("flowView both-watched = %s %d/%d, want A 500/1000", ip, down, up)
	}
}

func TestFlowLineRendersBothEndpoints(t *testing.T) {
	got := flowLine(traffic.Flow{A: "8.8.8.8:443", B: "192.0.2.1:49321", AB: 1000, BA: 500},
		map[string]bool{"192.0.2.1": true}, 1)
	if !strings.Contains(got, "8.8.8.8:443") || !strings.Contains(got, "192.0.2.1:49321") {
		t.Fatalf("flowLine missing endpoints: %q", got)
	}
	if !strings.Contains(got, "↓") || !strings.Contains(got, "↑") {
		t.Fatalf("flowLine missing direction markers: %q", got)
	}
	if got[3] != '1' {
		t.Fatalf("flowLine should lead with the watched endpoint, got %q", got)
	}
}

func TestPingLineEmptyUntilFirstPing(t *testing.T) {
	if got := pingLine("192.0.2.1", pinger{}); got != "" {
		t.Fatalf("pingLine should be empty before any ping, got %q", got)
	}
	h := pinger{}
	h.add(20, 60)
	if got := pingLine("192.0.2.1", h); !strings.Contains(got, "ping 20ms") {
		t.Fatalf("pingLine = %q, want last RTT shown", got)
	}
}

func TestPingerRingCap(t *testing.T) {
	h := pinger{}
	for i := 0; i < 100; i++ {
		h.add(5, 10)
	}
	if len(h.samples) != 10 {
		t.Fatalf("ring not capped: %d samples", len(h.samples))
	}
	if h.count != 100 || h.drops != 0 {
		t.Fatalf("running totals wrong: count=%d drops=%d", h.count, h.drops)
	}
	if h.min != 5 || h.max != 5 {
		t.Fatalf("min/max wrong: %d/%d", h.min, h.max)
	}
}
