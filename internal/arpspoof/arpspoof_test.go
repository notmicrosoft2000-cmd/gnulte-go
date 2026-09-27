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

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func ip4(s string) net.IP { return net.ParseIP(s).To4() }

// BuildARPReply must produce a frame ParseARPRequest recognizes only when it
// is a request, and whose fields round-trip to what we sent.
func TestReplyIsNotARequest(t *testing.T) {
	our := mac("aa:bb:cc:dd:ee:ff")
	victimMAC := mac("11:22:33:44:55:66")
	frame := BuildARPReply(our, ip4("192.168.1.1"), ip4("192.168.1.50"), victimMAC)

	// A reply must not be treated as a request.
	if _, _, _, ok := ParseARPRequest(frame); ok {
		t.Fatal("BuildARPReply output parsed as an ARP request")
	}
	// Ethernet framing check.
	if len(frame) != 60 {
		t.Errorf("frame length %d, want 60 (padded)", len(frame))
	}
	for i, b := range victimMAC {
		if frame[i] != b {
			t.Fatalf("dst mismatch at %d: %02x != %02x", i, frame[i], b)
		}
	}
	for i, b := range our {
		if frame[6+i] != b {
			t.Fatalf("src mismatch at %d: %02x != %02x", 6+i, frame[6+i], b)
		}
	}
	if frame[12] != 0x08 || frame[13] != 0x06 {
		t.Errorf("ethertype = %02x%02x, want 0806", frame[12], frame[13])
	}
}

func TestParseARPRequestFields(t *testing.T) {
	// Hand-built request: who has 192.168.1.1? tell 192.168.1.50.
	frame := make([]byte, 60)
	copy(frame[0:6], mac("ff:ff:ff:ff:ff:ff"))
	copy(frame[6:12], mac("11:22:33:44:55:66"))
	frame[12], frame[13] = 0x08, 0x06
	arp := frame[14:]
	arp[0], arp[1] = 0x00, 0x01 // htype: Ethernet
	arp[2], arp[3] = 0x08, 0x00 // ptype: IPv4
	arp[4], arp[5] = 6, 4
	arp[6], arp[7] = 0x00, 0x01 // op: request
	copy(arp[8:14], mac("11:22:33:44:55:66"))
	copy(arp[14:18], ip4("192.168.1.50"))
	copy(arp[18:24], mac("00:00:00:00:00:00"))
	copy(arp[24:28], ip4("192.168.1.1"))

	fromMAC, fromIP, asked, ok := ParseARPRequest(frame)
	if !ok {
		t.Fatal("expected a request to parse")
	}
	if fromMAC.String() != "11:22:33:44:55:66" {
		t.Errorf("fromMAC = %s", fromMAC)
	}
	if !fromIP.Equal(ip4("192.168.1.50")) {
		t.Errorf("fromIP = %s", fromIP)
	}
	if !asked.Equal(ip4("192.168.1.1")) {
		t.Errorf("askedIP = %s", asked)
	}
}

func TestParseARPRequestRejectsNonARP(t *testing.T) {
	frame := make([]byte, 60)
	frame[12], frame[13] = 0x08, 0x00 // IP, not ARP
	if _, _, _, ok := ParseARPRequest(frame); ok {
		t.Error("IPv4 frame parsed as ARP request")
	}
}

func TestIsLocal(t *testing.T) {
	sp := &Spoofer{ourMAC: mac("aa:aa:aa:aa:aa:aa")}
	if !sp.IsLocal(mac("aa:aa:aa:aa:aa:aa")) {
		t.Error("own MAC must be local")
	}
	if sp.IsLocal(mac("bb:bb:bb:bb:bb:bb")) {
		t.Error("foreign MAC must not be local")
	}
}
