// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package discover

import (
	"net"
	"testing"
)

var (
	selfMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	devA    = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	devB    = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
)

// newTestSet builds a probeSet the way the sweep does, without a socket.
func newTestSet(targets ...string) *probeSet {
	return newProbeSet(targets, selfMAC, "192.168.99.132")
}

// TestNoteCreditsOnlyRealAnswers is the discriminating test for the sweep's
// answer logic: of the replies a live segment throws at a who-has sweep — our
// own echo, a repeat, a stranger, and three MACs that identify nobody — exactly
// the first answer from a target we asked may be counted.
func TestNoteCreditsOnlyRealAnswers(t *testing.T) {
	ps := newTestSet("192.168.99.1", "192.168.99.5")

	cases := []struct {
		name string
		mac  net.HardwareAddr
		ip   string
		want bool
	}{
		{"first answer from a target", devA, "192.168.99.1", true},
		{"repeat from the same target", devB, "192.168.99.1", false},
		{"answer from a second target", devB, "192.168.99.5", true},
		{"repeat from the second target", devA, "192.168.99.5", false},
		{"our own echo", selfMAC, "192.168.99.1", false},
		{"a host nobody asked about", devA, "192.168.99.30", false},
		{"all-zero MAC", net.HardwareAddr{0, 0, 0, 0, 0, 0}, "192.168.99.5", false},
		{"broadcast MAC", broadcastMAC, "192.168.99.1", false},
		{"multicast MAC", net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}, "192.168.99.1", false},
		{"truncated MAC", net.HardwareAddr{0xaa, 0xbb}, "192.168.99.1", false},
		{"garbage IP", devA, "not-an-ip", false},
		{"empty IP", devA, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ps.note(c.mac, net.ParseIP(c.ip)); got != c.want {
				t.Fatalf("note(%s, %s) = %v, want %v", c.mac, c.ip, got, c.want)
			}
		})
	}
	if n := ps.live(); n != 2 {
		t.Fatalf("live() = %d, want 2 (only real first answers count)", n)
	}
	if !ps.settled() {
		t.Fatal("settled() = false, want true: both targets answered")
	}
	// One target left silent must keep the sweep listening for a second round.
	quiet := newTestSet("192.168.99.1", "192.168.99.5")
	quiet.note(devA, net.ParseIP("192.168.99.1"))
	if quiet.settled() {
		t.Fatal("settled() = true, want false: 192.168.99.5 never answered")
	}
	if n := quiet.live(); n != 1 {
		t.Fatalf("live() = %d, want 1", n)
	}
}

// TestNoteKeepsFirstAnswerIsLastAnswer pins the MAC the sweep reports: a device
// that answers twice must not have its address re-pointed at a later reply, or
// the scan would attribute a host's traffic to whoever answered next.
func TestNoteKeepsFirstAnswerIsLastAnswer(t *testing.T) {
	ps := newTestSet("192.168.99.1")
	if !ps.note(devA, net.ParseIP("192.168.99.1")) {
		t.Fatal("first answer was not credited")
	}
	if ps.note(devB, net.ParseIP("192.168.99.1")) {
		t.Fatal("second answer was credited")
	}
	if got := ps.probes["192.168.99.1"].mac; !sameMAC(got, devA) {
		t.Fatalf("recorded MAC = %s, want %s (the first answer)", got, devA)
	}
}

// TestNewProbeSetSkipsUnusableTargets covers the input filtering: a sweep must
// not spend a question on a malformed address, must not ask itself, and must
// not double-ask a target that was listed twice.
func TestNewProbeSetSkipsUnusableTargets(t *testing.T) {
	ps := newTestSet("192.168.99.1", "192.168.99.132", "192.168.99.1", "garbage", "", "::1")
	want := []string{"192.168.99.1"}
	if len(ps.order) != len(want) {
		t.Fatalf("order = %v, want %v", ps.order, want)
	}
	if ps.order[0] != want[0] {
		t.Fatalf("order[0] = %s, want %s", ps.order[0], want[0])
	}
}

// TestNewProbeSetNormalisesAddresses ensures 192.168.99.001-style and
// equivalent spellings collapse to one probe rather than two questions for the
// same host.
func TestNewProbeSetNormalisesAddresses(t *testing.T) {
	a := newTestSet("192.168.99.1")
	b := newTestSet("  192.168.99.1  ")
	if len(a.order) != 1 || len(b.order) != 1 {
		t.Fatalf("order sizes = %d and %d, want 1 each", len(a.order), len(b.order))
	}
	if a.order[0] != b.order[0] {
		t.Fatalf("normalised addresses differ: %q vs %q", a.order[0], b.order[0])
	}
}

// TestPendingOnlyAsksAgainForQuietAddresses is the retry discipline: a second
// asking round must cover exactly the addresses that stayed silent.
func TestPendingOnlyAsksAgainForQuietAddresses(t *testing.T) {
	ps := newTestSet("192.168.99.1", "192.168.99.5", "192.168.99.13")
	if got := len(ps.pending()); got != 3 {
		t.Fatalf("pending() = %d, want 3 before any answer", got)
	}
	ps.note(devA, net.ParseIP("192.168.99.5"))
	pending := ps.pending()
	if len(pending) != 2 {
		t.Fatalf("pending() = %v, want the two unanswered addresses", pending)
	}
	for _, ip := range pending {
		if ip == "192.168.99.5" {
			t.Fatal("an answered address is still queued for re-asking")
		}
	}
}

// TestCollectSortsAndMapsMACs pins the sweep's output shape: sorted addresses
// with the MAC each answered with, which is what gnulte-scan reports per host.
func TestCollectSortsAndMapsMACs(t *testing.T) {
	ps := newTestSet("192.168.99.13", "192.168.99.1", "192.168.99.5")
	ps.note(devB, net.ParseIP("192.168.99.5"))
	ps.note(devA, net.ParseIP("192.168.99.1"))

	res := ps.collect("lo") // an interface with no matching proc entry
	want := []string{"192.168.99.1", "192.168.99.5"}
	if len(res.live) != len(want) {
		t.Fatalf("live = %v, want %v", res.live, want)
	}
	for i, ip := range want {
		if res.live[i] != ip {
			t.Fatalf("live = %v, want %v (numeric order)", res.live, want)
		}
	}
	if got := res.macs["192.168.99.1"]; got != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("mac for .1 = %q, want upper-case AA:BB:CC:DD:EE:01", got)
	}
	if got := res.macs["192.168.99.5"]; got != "AA:BB:CC:DD:EE:02" {
		t.Fatalf("mac for .5 = %q, want upper-case AA:BB:CC:DD:EE:02", got)
	}
	if _, ok := res.macs["192.168.99.13"]; ok {
		t.Fatal("an unanswered target has a MAC in the result")
	}
}

// TestCollectSortsDeterministically pins the ordering of the sweep's output to
// the same lexicographic string sort the rest of the toolkit uses (so ".13"
// sorts before ".5", matching sortAddr elsewhere). The point of the assertion is
// that the order does not depend on which reply arrived first — a sweep whose
// list reordered run to run would make two scans of one LAN incomparable.
func TestCollectSortsDeterministically(t *testing.T) {
	build := func(order []string) sweepResult {
		ps := newTestSet("192.168.99.5", "192.168.99.13", "192.168.99.1")
		for _, ip := range order {
			ps.note(devA, net.ParseIP(ip))
		}
		return ps.collect("lo")
	}
	ascending := build([]string{"192.168.99.1", "192.168.99.5", "192.168.99.13"})
	shuffled := build([]string{"192.168.99.13", "192.168.99.1", "192.168.99.5"})
	want := []string{"192.168.99.1", "192.168.99.13", "192.168.99.5"}
	for i := range want {
		if ascending.live[i] != want[i] {
			t.Fatalf("live = %v, want %v", ascending.live, want)
		}
		if shuffled.live[i] != want[i] {
			t.Fatalf("live = %v, want %v (reply order must not leak into output)", shuffled.live, want)
		}
	}
}

// TestUsableMACIsDiscriminating covers the address sanity check directly: the
// three MAC forms that identify no host must be rejected, and a real NIC
// accepted.
func TestUsableMACIsDiscriminating(t *testing.T) {
	bad := []net.HardwareAddr{
		{0, 0, 0, 0, 0, 0},                   // unanswered who-has placeholder
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // broadcast
		{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}, // multicast
		{0xaa, 0xbb},                         // truncated
	}
	for _, mac := range bad {
		if usableMAC(mac) {
			t.Fatalf("usableMAC(%s) = true, want false", mac)
		}
	}
	if !usableMAC(devA) {
		t.Fatalf("usableMAC(%s) = false, want true", devA)
	}
}

// TestHostsInNetExpandsOnlySweepableSubnets is the safety rail on the implicit
// sweep inside DiscoverNeighbors: a neighbour lookup must never become a
// segment-wide flood. The cap is what decides, so each shape is asserted
// directly against a synthetic network rather than whatever this machine has.
func TestHostsInNetExpandsOnlySweepableSubnets(t *testing.T) {
	mustNet := func(cidr string) *net.IPNet {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", cidr, err)
		}
		return n
	}

	// A /24 is the shape this toolkit is actually used on: every host but the
	// network and broadcast addresses, no .0 and no .255.
	hosts := hostsInNet(mustNet("192.168.99.0/24"))
	if len(hosts) != 254 {
		t.Fatalf("/24 gave %d hosts, want 254", len(hosts))
	}
	if hosts[0] != "192.168.99.1" {
		t.Fatalf("first host = %s, want 192.168.99.1", hosts[0])
	}
	if hosts[len(hosts)-1] != "192.168.99.254" {
		t.Fatalf("last host = %s, want 192.168.99.254", hosts[len(hosts)-1])
	}
	for _, ip := range hosts {
		if ip == "192.168.99.0" || ip == "192.168.99.255" {
			t.Fatalf("/24 expansion included the %s address", ip)
		}
	}

	// Anything wider than the cap is refused outright, not truncated: a partial
	// sweep would report a segment as half-empty, which is worse than not trying.
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if got := hostsInNet(mustNet(cidr)); got != nil {
			t.Fatalf("hostsInNet(%s) = %d hosts, want nil (over the %d cap)", cidr, len(got), maxNeighborSweep)
		}
	}

	// A /22 is the largest allowed shape, and must come back whole.
	if got := hostsInNet(mustNet("10.1.0.0/22")); len(got) != maxNeighborSweep {
		t.Fatalf("/22 gave %d hosts, want %d", len(got), maxNeighborSweep)
	}
	// Degenerate prefixes have nobody to ask.
	for _, cidr := range []string{"192.168.99.5/32", "192.168.99.4/31"} {
		if got := hostsInNet(mustNet(cidr)); got != nil {
			t.Fatalf("hostsInNet(%s) = %v, want nil", cidr, got)
		}
	}
}

// TestSubnetTargetsIgnoresUnknownInterfaces keeps the caller honest: a name
// that does not exist yields nothing rather than panicking or sweeping.
func TestSubnetTargetsIgnoresUnknownInterfaces(t *testing.T) {
	if got := subnetTargets("definitely-not-an-iface"); got != nil {
		t.Fatalf("subnetTargets(bogus) = %v, want nil", got)
	}
	if got := subnetTargets(""); got != nil {
		t.Fatalf("subnetTargets(\"\") = %v, want nil", got)
	}
}

// TestARPSweepNeedsNothingWithoutPrivilege documents the honest degradation: off
// root the sweep reports no hosts instead of shelling out or erroring, so
// gnulte-scan simply merges nothing extra.
func TestARPSweepNeedsNothingWithoutPrivilege(t *testing.T) {
	// Not gated on privilege here: an empty target list or a missing interface
	// must be a no-op on any platform.
	if got := ARPSweep(nil, nil, "lo", 4); got != nil {
		t.Fatalf("ARPSweep(no targets) = %v, want nil", got)
	}
	if got := ARPSweep(nil, []string{"192.168.99.1"}, "", 4); got != nil {
		t.Fatalf("ARPSweep(no interface) = %v, want nil", got)
	}
}

// TestResolveMACRejectsBadInput checks the guards before any socket is opened,
// so a bad address gives a clear error rather than a silent nil.
func TestResolveMACRejectsBadInput(t *testing.T) {
	if _, err := ResolveMAC(nil, "", "192.168.99.1"); err == nil {
		t.Fatal("ResolveMAC with no interface returned no error")
	}
	if _, err := ResolveMAC(nil, "lo", "not-an-ip"); err == nil {
		t.Fatal("ResolveMAC with a malformed address returned no error")
	}
	if _, err := ResolveMAC(nil, "lo", "::1"); err == nil {
		t.Fatal("ResolveMAC with an IPv6 address returned no error")
	}
}

// A parser that credited every frame on the socket would pass the happy path
// above and invent hosts on a busy segment. This asserts the negative cases
// still hold when the sweeper is handed a full frame stream.
func TestNoteAgainstAMixedFrameStream(t *testing.T) {
	ps := newTestSet("192.168.99.1", "192.168.99.5")
	stream := []struct {
		mac net.HardwareAddr
		ip  string
	}{
		{devA, "192.168.99.1"},               // counts
		{devB, "192.168.99.1"},               // repeat, must not count
		{selfMAC, "192.168.99.5"},            // our own echo, must not count
		{devA, "192.168.99.30"},              // stranger, must not count
		{net.HardwareAddr{}, "192.168.99.5"}, // placeholder MAC, must not count
		{devB, "192.168.99.5"},               // counts, finally
	}
	want := 0
	for _, f := range stream {
		if ps.note(f.mac, net.ParseIP(f.ip)) {
			want++
		}
	}
	if want != 2 {
		t.Fatalf("%d replies credited, want 2", want)
	}
	if !ps.settled() {
		t.Fatalf("both targets answered, settled() = false")
	}
	if got := ps.probes["192.168.99.1"].mac; !sameMAC(got, devA) {
		t.Fatalf("MAC for .1 = %s, want the first answer %s", got, devA)
	}
	if got := ps.probes["192.168.99.5"].mac; !sameMAC(got, devB) {
		t.Fatalf("MAC for .5 = %s, want %s", got, devB)
	}
}
