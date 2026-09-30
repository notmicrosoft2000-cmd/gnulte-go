package main

import (
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
	for _, screen := range []int{scrHosts, scrTalkers, scrFlows, scrArp, scrMap} {
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
