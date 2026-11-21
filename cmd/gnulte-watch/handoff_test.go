package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
)

// handoffEnv is a minimal frame environment: one gateway, no counter, and a
// neighbour table that deliberately disagrees with the host list so the ARP
// screen's row order is distinguishable from the address order.
func handoffEnv(neigh map[string]string) watchEnv {
	return watchEnv{
		nic: "wlan0", subnet: "192.168.100.0/24",
		selfIP: "192.168.100.207", gwIP: "192.168.100.1", gwRTT: 3,
		iv: 1, start: time.Now(), hasCounter: true, neigh: neigh,
	}
}

// handoffRates ranks the three test hosts .40 > .13 > .207 by combined rate,
// which is deliberately *not* the address order the hosts screen defaults to.
func handoffRates() map[string]traffic.Rate {
	return map[string]traffic.Rate{
		"192.168.100.13":  {RXBytes: 900_000, TXBytes: 0},
		"192.168.100.40":  {RXBytes: 5_000_000, TXBytes: 4_000_000},
		"192.168.100.207": {RXBytes: 100, TXBytes: 100},
	}
}

// TestBuildViewCursorIPPerScreen pins which host the cursor names on every
// screen, because that value is what ⏎/g hands to gnulte.
//
// The bug this guards: only the hosts screen ever set currentIP. Switching to
// talkers, flows, ARP or the map left the previous screen's value in place,
// so moving the cursor and pressing ⏎ launched gnulte against a host the
// cursor was not on — a wrong-target impairment run.
func TestBuildViewCursorIPPerScreen(t *testing.T) {
	hosts, stats := testHosts()
	neigh := map[string]string{
		"192.168.100.5":  "aa:bb:cc:dd:ee:01",
		"192.168.100.40": "aa:bb:cc:dd:ee:02",
	}
	rates := handoffRates()
	hostSet := map[string]bool{}
	for _, ip := range hosts {
		hostSet[ip] = true
	}

	cases := []struct {
		name   string
		screen int
		cursor int
		want   string
	}{
		// hosts: address order (the default sort, a string compare, so .207
		// precedes .40), so the cursor names .13 then .207 then .40.
		{"hosts row 0", scrHosts, 0, "192.168.100.13"},
		{"hosts row 1", scrHosts, 1, "192.168.100.207"},
		{"hosts row 2", scrHosts, 2, "192.168.100.40"},
		// talkers: ranked by combined rate, so the same cursor names .40 —
		// this is exactly the value the hosts screen would have left behind.
		{"talkers rank 0", scrTalkers, 0, "192.168.100.40"},
		{"talkers rank 1", scrTalkers, 1, "192.168.100.13"},
		{"talkers rank 2", scrTalkers, 2, "192.168.100.207"},
		// flows: a row is a pair, so there is no single host to name.
		{"flows has no host", scrFlows, 0, ""},
		// ARP: neighbour table ∪ hosts, IP-ordered — .5, .13, .40, .207.
		{"arp row 0", scrArp, 0, "192.168.100.5"},
		{"arp row 1", scrArp, 1, "192.168.100.13"},
		{"arp row 2", scrArp, 2, "192.168.100.40"},
		{"arp row 3", scrArp, 3, "192.168.100.207"},
		// map: the last row is the gateway hub, not a host to test.
		{"map has no host", scrMap, 0, ""},
		// PATH: a target card is a diagram node; ⏎/g must never launch.
		{"path has no host", scrPath, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &viewState{screen: c.screen, cursor: c.cursor}
			buildView(st, hosts, nil, rates, nil, hostSet, stats, handoffEnv(neigh), 40)
			if st.currentIP != c.want {
				t.Fatalf("currentIP = %q, want %q", st.currentIP, c.want)
			}
		})
	}
}

// TestPendingHandoffLaunchesOnceAndHintStaysStable pins both sides of the
// draw-time handoff fix: the first frame launches against its own cursor row
// (PTY B1 drift), and later 1 Hz frames must NOT re-launch — handoffGNULTE
// really spawns a terminal, so one key press may open exactly one window.
func TestPendingHandoffLaunchesOnceAndHintStaysStable(t *testing.T) {
	// TERMINAL is honoured first by ux.LaunchTerminal. Point it at a tiny
	// logging script instead of a terminal: no window, but every call is
	// counted. /bin/false would hide a repeated launch.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "launches.log")
	termPath := filepath.Join(dir, "fake-terminal")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$HANDOFF_LOG\"\n"
	if err := os.WriteFile(termPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake terminal: %v", err)
	}
	t.Setenv("TERMINAL", termPath)
	t.Setenv("HANDOFF_LOG", logPath)

	hosts, stats := testHosts()
	const (
		firstIP  = "192.168.100.207"
		secondIP = "192.168.100.40"
	)
	st := &viewState{screen: scrHosts, cursor: 1, sortMode: sortTraffic, handoffPending: true}

	// First frame: .40 is busiest, then .207 at the cursor, then .13. This
	// frame resolves and launches against the cursor row it actually prints.
	rates := map[string]traffic.Rate{
		"192.168.100.13":  {RXBytes: 100},
		"192.168.100.40":  {RXBytes: 9_000_000},
		"192.168.100.207": {RXBytes: 5_000_000},
	}
	buildView(st, hosts, nil, rates, nil, nil, stats, handoffEnv(nil), 40)
	if st.currentIP != firstIP {
		t.Fatalf("first frame cursor row = %q, want %q", st.currentIP, firstIP)
	}
	if st.handoffLaunchedIP != firstIP {
		t.Fatalf("launched IP = %q, want first frame cursor row %q", st.handoffLaunchedIP, firstIP)
	}
	if !strings.Contains(st.gCmd, "gnulte -t "+firstIP) {
		t.Fatalf("first frame hint = %q, want launched target %q", st.gCmd, firstIP)
	}

	// A live traffic sort reorders rows, so the same cursor index now names a
	// different host. The next tick must reuse the original hint and must not
	// launch again against the new row.
	rates = map[string]traffic.Rate{
		"192.168.100.13":  {RXBytes: 9_000_000},
		"192.168.100.40":  {RXBytes: 5_000_000},
		"192.168.100.207": {RXBytes: 100},
	}
	buildView(st, hosts, nil, rates, nil, nil, stats, handoffEnv(nil), 40)
	if st.currentIP != secondIP {
		t.Fatalf("second frame cursor row = %q, want %q", st.currentIP, secondIP)
	}
	if st.handoffLaunchedIP != firstIP {
		t.Fatalf("launched IP drifted to %q, want %q", st.handoffLaunchedIP, firstIP)
	}
	if !strings.Contains(st.gCmd, "gnulte -t "+firstIP) || strings.Contains(st.gCmd, "gnulte -t "+secondIP) {
		t.Fatalf("second frame hint = %q, want the launched target %q only", st.gCmd, firstIP)
	}

	// The fake terminal is detached; wait briefly for its single append, then
	// give any (buggy) second launch time to show up before counting lines.
	var log []byte
	deadline := time.Now().Add(2 * time.Second)
	for {
		log, _ = os.ReadFile(logPath)
		if strings.Count(string(log), "\n") >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read launch log: %v", err)
	}
	if n := strings.Count(string(log), "\n"); n != 1 {
		t.Fatalf("handoff launched %d times, want exactly one: %q", n, log)
	}
	if !strings.Contains(string(log), "-t "+firstIP) || strings.Contains(string(log), secondIP) {
		t.Fatalf("launch args = %q, want only the first frame's target %q", log, firstIP)
	}
}

// A cursor carried over from a bigger screen (or from a list that has since
// shrunk) must be clamped, so currentIP names a row that actually exists.
func TestBuildViewClampsCursorPerScreen(t *testing.T) {
	hosts, stats := testHosts()
	hostSet := map[string]bool{}
	for _, ip := range hosts {
		hostSet[ip] = true
	}
	for _, c := range []struct {
		screen int
		want   string
	}{
		{scrTalkers, "192.168.100.207"}, // 3 ranked rows, cursor 9 → last
		{scrArp, "192.168.100.207"},     // .5/.13/.40/.207, cursor 9 → last
	} {
		st := &viewState{screen: c.screen, cursor: 9}
		neigh := map[string]string{
			"192.168.100.5":  "aa:bb:cc:dd:ee:01",
			"192.168.100.40": "aa:bb:cc:dd:ee:02",
		}
		buildView(st, hosts, nil, handoffRates(), nil, hostSet, stats, handoffEnv(neigh), 40)
		if st.cursor != st.count-1 {
			t.Errorf("screen %d: cursor = %d, want clamped to %d", c.screen, st.cursor, st.count-1)
		}
		if st.currentIP != c.want {
			t.Errorf("screen %d: currentIP = %q, want %q", c.screen, st.currentIP, c.want)
		}
	}
}

// An empty host set must leave nothing to hand off, on every screen.
func TestBuildViewEmptyHostsHasNoHandoff(t *testing.T) {
	for _, screen := range []int{scrHosts, scrTalkers, scrFlows, scrArp, scrMap, scrHistory, scrPath} {
		st := &viewState{screen: screen}
		buildView(st, nil, nil, handoffRates(), nil, nil, map[string]*hostStat{}, handoffEnv(nil), 40)
		if st.currentIP != "" {
			t.Errorf("screen %d: currentIP = %q with no hosts, want empty", screen, st.currentIP)
		}
	}
}

// TestHandoffIPGate is the launch-side guard. buildView clearing currentIP is
// the first line of defence; this is the second — flows (pairs) and the map
// (gateway hub) refuse a handoff even if a stale IP reaches them.
func TestHandoffIPGate(t *testing.T) {
	const stale = "192.168.100.13"
	for _, c := range []struct {
		screen int
		want   string
	}{
		{scrHosts, stale},
		{scrTalkers, stale},
		{scrArp, stale},
		{scrFlows, ""},
		{scrMap, ""},
		{scrHistory, ""},
		{scrPath, ""},
	} {
		if got := handoffIP(c.screen, stale); got != c.want {
			t.Errorf("handoffIP(screen=%d, %q) = %q, want %q", c.screen, stale, got, c.want)
		}
	}
	// And a named host on a handoff-capable screen still needs an IP.
	if got := handoffIP(scrTalkers, ""); got != "" {
		t.Errorf("handoffIP with no cursor host = %q, want empty", got)
	}
}
