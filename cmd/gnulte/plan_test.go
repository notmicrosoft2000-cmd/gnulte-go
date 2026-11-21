// GNULTE — network testing toolkit (Go).
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL v3.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gnulte-go/internal/engine"
)

func planConfig() engine.Config {
	return engine.Config{
		Interface:     "eth0",
		Gateway:       "192.168.1.1",
		Targets:       []string{"192.168.1.50"},
		LatencyMS:     300,
		JitterMS:      100,
		LossPct:       5,
		DupPct:        2,
		ReorderPct:    3,
		BandwidthKbps: 512,
	}
}

func TestBuildPlanContainsExactCommands(t *testing.T) {
	lines := buildPlan(planConfig(), "eth0")
	joined := strings.Join(lines, "\n")
	if lines[0] != "GNULTE plan — no changes will be made" {
		t.Errorf("plan header = %q", lines[0])
	}
	if lines[len(lines)-1] != "No packets were sent and no settings were changed." {
		t.Errorf("plan footer = %q", lines[len(lines)-1])
	}
	for _, want := range []string{
		"interface: eth0",
		"gateway: 192.168.1.1",
		"target: 192.168.1.50",
		"tc qdisc add dev eth0 root handle 1: htb default 999",
		"tc class add dev eth0 parent 1: classid 1:10 htb rate 512kbit ceil 512kbit",
		"tc qdisc add dev eth0 parent 1:10 handle 10: netem delay 300ms 100ms loss 5% duplicate 2% reorder 3% gap 5",
		"tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dst 192.168.1.50/32 flowid 1:10",
		"tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip src 192.168.1.50/32 flowid 1:10",
		"tc class change dev eth0 parent 1: classid 1:10 htb rate 512kbit ceil 512kbit",
		"tc qdisc change dev eth0 parent 1:10 handle 10: netem delay 300ms 100ms loss 5% duplicate 2% reorder 3% gap 5",
		"iptables -I FORWARD -d 192.168.1.50 -m comment --comment GNULTE -j DROP",
		"echo 1 > /proc/sys/net/ipv4/ip_forward",
		"arpspoof -i eth0 -t 192.168.1.50 192.168.1.1",
		"arpspoof -i eth0 -t 192.168.1.1 192.168.1.50",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan missing %q\nfull plan:\n%s", want, joined)
		}
	}
}

func TestBuildPlanBlockMode(t *testing.T) {
	c := planConfig()
	c.Mode = engine.ModeBlock
	joined := strings.Join(buildPlan(c, "eth0"), "\n")
	if !strings.Contains(joined, "mode: block (100% DROP)") {
		t.Errorf("block mode not shown:\n%s", joined)
	}
	if !strings.Contains(joined, "iptables -I FORWARD -s 192.168.1.50 -m comment --comment GNULTE -j DROP") {
		t.Errorf("block DROP rules not shown:\n%s", joined)
	}
	if strings.Contains(joined, "only inserted in block mode") {
		t.Errorf("block plan still carries the shape-mode note:\n%s", joined)
	}
}

// TestBuildPlanHasNoSideEffects pins the dry-run guarantee: buildPlan must
// only format strings. A capture file configured on the config is never
// created and the verbose (command-execution transcript) hook is never called.
func TestBuildPlanHasNoSideEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "should-not-exist.pcap")
	c := planConfig()
	c.CaptureFile = path
	captured := 0
	c.Verbose = func(string) { captured++ }

	_ = buildPlan(c, "eth0")
	_ = buildPlan(c, "eth0")

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("buildPlan created capture file %s (stat err = %v)", path, err)
	}
	if captured != 0 {
		t.Errorf("buildPlan invoked the command transcript %d time(s)", captured)
	}
}

func TestPlanTargetsFromExplicitFlags(t *testing.T) {
	got := planTargets(" 192.168.1.50,example.local,,192.168.1.50 ", "aa:bb:cc:dd:ee:ff", "192.168.2.0/24")
	want := []string{"192.168.1.50", "example.local", "aa:bb:cc:dd:ee:ff", "192.168.2.0/24"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("planTargets = %q, want %q", got, want)
	}
	if got := planTargets("", "", ""); len(got) != 0 {
		t.Errorf("no explicit flags should yield no targets, got %q", got)
	}
}
