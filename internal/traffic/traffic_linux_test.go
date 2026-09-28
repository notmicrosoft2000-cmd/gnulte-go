// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package traffic

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// frame builds a minimal Ethernet/IPv4 frame (with an 8-byte L4 header carrying
// TCP/UDP ports) so parse() can be exercised without a raw socket. The IP
// checksum is deliberately left unwritten — the counter never validates it.
func frame(src, dst net.IP, proto byte, sport, dport uint16, payload int) []byte {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00 // IPv4
	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, IHL=5
	ip[9] = proto
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	total := 20 + 8 + payload
	ip[2], ip[3] = byte(total>>8), byte(total)
	l4 := make([]byte, 8+payload)
	if proto == 6 || proto == 17 {
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
	}
	out := make([]byte, 0, 14+total)
	out = append(out, eth...)
	out = append(out, ip...)
	out = append(out, l4...)
	return out
}

func newTestCounter() *Counter {
	return &Counter{
		host:     map[string]*counts{},
		prev:     map[string]*counts{},
		flows:    map[string]*fcounts{},
		prevFlow: map[string]*fcounts{},
	}
}

func TestParseCountsHostsAndFlows(t *testing.T) {
	c := newTestCounter()
	a := net.ParseIP("192.168.1.10")
	b := net.ParseIP("192.168.1.20")

	// One TCP conversation, both directions, plus an ICMP exchange.
	c.parse(frame(a, b, 6, 443, 12345, 100))
	c.parse(frame(b, a, 6, 12345, 443, 200))
	c.parse(frame(a, b, 1, 0, 0, 64))

	// Per-host totals: A sent 2 frames (tcp 142B + icmp 106B), B sent 1.
	byIP := c.Snapshot()
	if r := byIP["192.168.1.10"]; r.TXBytes != 142+106 {
		t.Fatalf("host A tx = %d, want %d", r.TXBytes, 142+106)
	}
	if r := byIP["192.168.1.10"]; r.RXBytes != 242 {
		t.Fatalf("host A rx = %d, want 242", r.RXBytes)
	}
	if r := byIP["192.168.1.20"]; r.TXBytes != 242 || r.RXBytes != 248 {
		t.Fatalf("host B tx/rx = %d/%d, want 242/248 (both A→B frames land on B)", r.TXBytes, r.RXBytes)
	}

	// Flows: the TCP pair is ONE conversation with both directions folded in;
	// the ICMP pair is a second one (ports 0).
	flows := c.SnapshotFlows()
	if len(flows) != 2 {
		t.Fatalf("got %d flows, want 2", len(flows))
	}
	var tcpFl, icmpFl *Flow
	for i := range flows {
		// Distinctly: the TCP conversation carries port 443, the ICMP one
		// carries port 0 on both ends.
		if strings.Contains(flows[i].A, ":443") || strings.Contains(flows[i].B, ":443") {
			tcpFl = &flows[i]
		} else {
			icmpFl = &flows[i]
		}
	}
	if tcpFl == nil {
		t.Fatal("TCP conversation flow missing")
	}
	if tcpFl.A != "192.168.1.10:443" || tcpFl.B != "192.168.1.20:12345" {
		t.Fatalf("tcp endpoints A=%q B=%q", tcpFl.A, tcpFl.B)
	}
	// A→B carried 142B, B→A carried 242B.
	if tcpFl.AB != 142 || tcpFl.BA != 242 {
		t.Fatalf("tcp AB/BA = %d/%d, want 142/242", tcpFl.AB, tcpFl.BA)
	}
	if tcpFl.ABp != 1 || tcpFl.BAp != 1 {
		t.Fatalf("tcp packet counts AB/BA = %d/%d, want 1/1", tcpFl.ABp, tcpFl.BAp)
	}
	if icmpFl == nil {
		t.Fatal("ICMP conversation flow missing")
	}
	if icmpFl.A != "192.168.1.10:0" || icmpFl.B != "192.168.1.20:0" {
		t.Fatalf("icmp endpoints A=%q B=%q", icmpFl.A, icmpFl.B)
	}
	if icmpFl.Total() != 106 {
		t.Fatalf("icmp total = %d, want 106", icmpFl.Total())
	}
}

func TestSnapshotFlowsDeltas(t *testing.T) {
	c := newTestCounter()
	a := net.ParseIP("192.168.1.10")
	b := net.ParseIP("192.168.1.20")

	c.parse(frame(a, b, 6, 443, 12345, 100))
	c.SnapshotFlows() // baseline consumed; only "prev" delta logic matters

	// Nothing since the baseline: no flow should be reported.
	if got := c.SnapshotFlows(); len(got) != 0 {
		t.Fatalf("expected no interval flow, got %d", len(got))
	}

	// New bytes on the same conversation appear as a pure delta.
	c.parse(frame(a, b, 6, 443, 12345, 300))
	c.parse(frame(b, a, 6, 12345, 443, 50))
	got := c.SnapshotFlows()
	if len(got) != 1 {
		t.Fatalf("got %d flow(s), want 1", len(got))
	}
	if got[0].AB != 342 || got[0].BA != 92 {
		t.Fatalf("delta AB/BA = %d/%d, want 342/92 (42B headers + payloads)", got[0].AB, got[0].BA)
	}
}

func TestSnapshotHostDeltas(t *testing.T) {
	// Regression: the baseline must be a copy — if Snapshot stores the live
	// counters pointer in prev, parse() mutates both and every later delta
	// reads zero (which made the old dashboard show a static readout).
	c := newTestCounter()
	a := net.ParseIP("192.168.1.10")
	b := net.ParseIP("192.168.1.20")
	c.parse(frame(a, b, 6, 443, 12345, 100))
	c.Snapshot() // baseline consumed
	c.parse(frame(a, b, 6, 443, 12345, 100))
	got := c.Snapshot()
	if r := got["192.168.1.10"]; r.TXBytes != 142 {
		t.Fatalf("second-interval host tx = %d, want 142 (delta of the new frame)", r.TXBytes)
	}
	if r := got["192.168.1.20"]; r.RXBytes != 142 {
		t.Fatalf("second-interval host rx = %d, want 142", r.RXBytes)
	}
}

func TestFlowTotalsCumulative(t *testing.T) {
	c := newTestCounter()
	a := net.ParseIP("192.168.1.10")
	b := net.ParseIP("192.168.1.20")

	c.parse(frame(a, b, 6, 443, 12345, 100))
	c.SnapshotFlows() // advance the baseline
	c.parse(frame(a, b, 6, 443, 12345, 300))

	totals := c.FlowTotals()
	if len(totals) != 1 {
		t.Fatalf("got %d total flows, want 1", len(totals))
	}
	// Cumulative includes everything since the counter started:
	// 142B on the baseline + 342B on the second frame.
	if totals[0].AB != 484 {
		t.Fatalf("cumulative AB = %d, want 484", totals[0].AB)
	}
}

func TestNonRouteProtoSkipsFlow(t *testing.T) {
	c := newTestCounter()
	// An ARP frame (ethertype 0x0806) must be ignored entirely.
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	c.parse(arp)
	if len(c.host) != 0 {
		t.Fatalf("ARP frame counted %d hosts", len(c.host))
	}
	if len(c.flows) != 0 {
		t.Fatalf("ARP frame counted %d flows", len(c.flows))
	}
}

func TestEndpointFormatting(t *testing.T) {
	if got := endpoint("192.168.1.5", 0); got != "192.168.1.5:0" {
		t.Fatalf("endpoint() with port 0 = %q", got)
	}
	if got := endpoint("192.168.1.5", 53); got != "192.168.1.5:53" {
		t.Fatalf("endpoint() with port 53 = %q", got)
	}
}
