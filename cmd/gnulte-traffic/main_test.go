package main

import (
	"strings"
	"testing"

	"gnulte-go/internal/traffic"
)

func TestRenderPingHistoryLine(t *testing.T) {
	hosts := []string{"192.0.2.1"}
	rates := map[string]traffic.Rate{
		"192.0.2.1": {RXBytes: 1200, RXPkts: 4, TXBytes: 600, TXPkts: 2},
	}
	hist := make([]pinger, 1)
	for i := 0; i < 40; i++ {
		hist[0].add(14, 30)
	}
	hist[0].add(-1, 30)

	lines := render(hosts, rates, "eth0", 1, hist)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "ping") {
		t.Fatalf("ping history row missing:\n%s", joined)
	}
	if !strings.Contains(joined, "avg 14ms") {
		t.Fatalf("average missing:\n%s", joined)
	}
	if !strings.Contains(joined, "loss 2%") {
		t.Fatalf("loss missing (41 pings, 1 drop):\n%s", joined)
	}
	// The sparkline must be capped at the history window (30) even though the
	// host has been watched longer.
	if !strings.Contains(joined, "▂") {
		t.Fatalf("sparkline blocks missing:\n%s", joined)
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
