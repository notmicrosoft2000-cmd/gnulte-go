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

package arpspoof

import (
	"net"
	"testing"
)

var (
	localMAC = net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	localIP  = net.ParseIP("192.168.99.132")
	peerMAC  = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

// TestBuildARPRequestIsAValidWhoHas pins the on-the-wire shape of the frame the
// sweep now sends instead of shelling to arping(8). A host only answers a
// who-has that is framed exactly like every other host's, so each field the
// sweep depends on is asserted: broadcast destination, us as sender, our IP as
// the address to answer, the asked address as the target, and no pretence of
// knowing the target's hardware address.
func TestBuildARPRequestIsAValidWhoHas(t *testing.T) {
	askIP := net.ParseIP("192.168.99.1")
	frame := BuildARPRequest(localMAC, localIP, askIP)

	if len(frame) < 42 {
		t.Fatalf("frame is %d bytes, too short to be an ARP frame", len(frame))
	}
	if len(frame) != 60 {
		t.Fatalf("frame is %d bytes, want the 60-byte Ethernet minimum", len(frame))
	}
	if !equalMAC(net.HardwareAddr(frame[0:6]), BroadcastMAC) {
		t.Fatalf("eth dst = %s, want broadcast %s", frame[0:6], BroadcastMAC)
	}
	if !equalMAC(net.HardwareAddr(frame[6:12]), localMAC) {
		t.Fatalf("eth src = %s, want %s", frame[6:12], localMAC)
	}
	// sha/spa must be us, or the answer comes back to the real gateway.
	if !equalMAC(net.HardwareAddr(frame[22:28]), localMAC) {
		t.Fatalf("arp sha = %s, want %s", frame[22:28], localMAC)
	}
	if got := net.IP(frame[28:32]).String(); got != localIP.String() {
		t.Fatalf("arp spa = %s, want %s", got, localIP)
	}
	// tha is the all-zero placeholder: we are asking, we do not know.
	if !equalMAC(net.HardwareAddr(frame[32:38]), net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		t.Fatalf("arp tha = %s, want all zeros (the question must not claim to know)", frame[32:38])
	}
	if got := net.IP(frame[38:42]).String(); got != "192.168.99.1" {
		t.Fatalf("arp tpa = %s, want 192.168.99.1", got)
	}
	// The parser the sweep's own reply path uses must accept it as a request.
	fromMAC, fromIP, askedIP, ok := ParseARPRequest(frame)
	if !ok {
		t.Fatal("ParseARPRequest rejected the frame BuildARPRequest just built")
	}
	if !equalMAC(fromMAC, localMAC) || fromIP.String() != localIP.String() || askedIP.String() != "192.168.99.1" {
		t.Fatalf("round trip = (%s, %s, %s), want (%s, %s, 192.168.99.1)",
			fromMAC, fromIP, askedIP, localMAC, localIP)
	}
}

// TestParseARPReplyReadsTheAnswer is the sweep's read path: given the reply a
// real host emits, it must report who answered, for which address, and which
// address the reply was aimed at — the last of which is how a caller knows the
// answer belongs to its own question.
func TestParseARPReplyReadsTheAnswer(t *testing.T) {
	frame := BuildARPReply(peerMAC, net.ParseIP("192.168.99.1"), localIP, localMAC)

	fromMAC, fromIP, targetIP, ok := ParseARPReply(frame)
	if !ok {
		t.Fatal("ParseARPReply rejected a reply frame built by BuildARPReply")
	}
	if !equalMAC(fromMAC, peerMAC) {
		t.Fatalf("fromMAC = %s, want %s", fromMAC, peerMAC)
	}
	if fromIP.String() != "192.168.99.1" {
		t.Fatalf("fromIP = %s, want 192.168.99.1 (the address that answered)", fromIP)
	}
	if targetIP.String() != localIP.String() {
		t.Fatalf("targetIP = %s, want %s (the asker)", targetIP, localIP)
	}
}

// TestParseARPReplyRejectsWhatIsNotAReply is the discriminating check on the
// read path. A sweep shares its socket with every ARP frame on the segment, so
// the parser has to decline requests, non-ARP traffic, and truncated frames —
// crediting any of them would invent hosts that never answered.
func TestParseARPReplyRejectsWhatIsNotAReply(t *testing.T) {
	request := BuildARPRequest(localMAC, localIP, net.ParseIP("192.168.99.1"))
	if _, _, _, ok := ParseARPReply(request); ok {
		t.Fatal("ParseARPReply accepted a who-has request as a reply")
	}
	ipFrame := make([]byte, 60)
	ipFrame[12], ipFrame[13] = 0x08, 0x00 // ethertype IPv4
	if _, _, _, ok := ParseARPReply(ipFrame); ok {
		t.Fatal("ParseARPReply accepted a non-ARP frame")
	}
	reply := BuildARPReply(peerMAC, net.ParseIP("192.168.99.1"), localIP, localMAC)
	if _, _, _, ok := ParseARPReply(reply[:41]); ok {
		t.Fatal("ParseARPReply accepted a truncated frame")
	}
	if _, _, _, ok := ParseARPReply(nil); ok {
		t.Fatal("ParseARPReply accepted an empty frame")
	}
	// A frame claiming to be ARP but with the wrong address sizes is not a frame
	// any real NIC emits, and must not be credited.
	bad := append([]byte(nil), reply...)
	bad[18], bad[19] = 4, 4 // hlen/plen -> 4 bytes each
	if _, _, _, ok := ParseARPReply(bad); ok {
		t.Fatal("ParseARPReply accepted an ARP frame with the wrong address sizes")
	}
	// An ARP frame for a non-IPv4 protocol type must not be treated as IPv4 ARP.
	badProto := append([]byte(nil), reply...)
	badProto[16], badProto[17] = 0x08, 0x06 // ptype -> IPv6
	if _, _, _, ok := ParseARPReply(badProto); ok {
		t.Fatal("ParseARPReply accepted a non-IPv4 ARP frame")
	}
}

// TestParseARPRequestRejectsAReply is the mirror image: the spoofing path must
// not answer a reply, or the engine would start a reply storm.
func TestParseARPRequestRejectsAReply(t *testing.T) {
	reply := BuildARPReply(peerMAC, net.ParseIP("192.168.99.1"), localIP, localMAC)
	if _, _, _, ok := ParseARPRequest(reply); ok {
		t.Fatal("ParseARPRequest accepted a reply as a request")
	}
}

// TestBuildARPReplyStillRoundTrips guards the pre-existing spoofing frame
// against the changes made here: teardown correctness depends on the corrective
// announcement being framed exactly as before.
func TestBuildARPReplyStillRoundTrips(t *testing.T) {
	claimed := net.ParseIP("192.168.99.1")
	frame := BuildARPReply(localMAC, claimed, net.ParseIP("192.168.99.55"), peerMAC)

	if !equalMAC(net.HardwareAddr(frame[0:6]), peerMAC) {
		t.Fatalf("eth dst = %s, want the asker %s", frame[0:6], peerMAC)
	}
	if !equalMAC(net.HardwareAddr(frame[6:12]), localMAC) {
		t.Fatalf("eth src = %s, want the real router %s", frame[6:12], localMAC)
	}
	if got := net.IP(frame[28:32]).String(); got != claimed.String() {
		t.Fatalf("spa = %s, want the claimed address %s", got, claimed)
	}
	// It must read back as a reply, since the sweep's socket sees these too.
	fromMAC, fromIP, targetIP, ok := ParseARPReply(frame)
	if !ok || !equalMAC(fromMAC, localMAC) || fromIP.String() != claimed.String() ||
		targetIP.String() != "192.168.99.55" {
		t.Fatalf("reply round trip = (%s, %s, %s, %v)", fromMAC, fromIP, targetIP, ok)
	}
}
