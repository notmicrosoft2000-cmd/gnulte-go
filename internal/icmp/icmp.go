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

// Package icmp implements IPv4 ICMP echo in-process: the frames are built and
// checksummed here and the replies are decoded and matched here, so the toolkit
// can measure reachability without a ping(8) subprocess. The socket I/O is
// Linux-only (icmp_linux.go); the frame logic is platform-neutral so it is
// unit-testable everywhere, and so a later traceroute can reuse the reply
// decoder and the TTL it reports.
package icmp

import (
	"encoding/binary"
)

// The ICMPv4 message types this package cares about.
const (
	echoReply   = 0
	echoRequest = 8
)

// headerLen is the fixed ICMP header: type, code, checksum, identifier,
// sequence number.
const headerLen = 8

// Checksum is the RFC 1071 Internet checksum over b: the one's-complement of
// the one's-complement sum of 16-bit words, with a zero pad on an odd length.
func Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// buildEcho crafts an ICMPv4 echo message of the given type. Everything shares
// the same layout, so the request and reply paths cannot drift apart.
func buildEcho(typ byte, id, seq uint16, payload []byte) []byte {
	msg := make([]byte, headerLen+len(payload))
	msg[0] = typ
	// msg[1] (code) stays 0 for echo.
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[headerLen:], payload)
	binary.BigEndian.PutUint16(msg[2:4], Checksum(msg))
	return msg
}

// BuildEcho crafts an ICMPv4 echo request. The identifier and sequence number
// are the caller's: a raw ICMP socket sees every ICMP message on the host, so a
// reply is only ours when both match what we sent. The payload normally carries
// a send timestamp, echoed back untouched.
func BuildEcho(id, seq uint16, payload []byte) []byte {
	return buildEcho(echoRequest, id, seq, payload)
}

// Reply is a decoded ICMPv4 echo reply.
type Reply struct {
	ID      uint16
	Seq     uint16
	TTL     int // from the IPv4 header when the socket supplied it, else 0
	Payload []byte
}

// Decode finds the echo reply carried by a received packet. Raw ICMP sockets on
// Linux usually hand back the IPv4 header in front of the message, but not
// always, so Decode accepts both and tells them apart by the version nibble. It
// declines anything that is not a well-formed echo reply: a request, a
// non-ICMP packet, a truncated message, or a message whose checksum does not
// verify (a corrupt reply is not evidence that a host is alive).
func Decode(pkt []byte) (Reply, bool) {
	ttl := 0
	if len(pkt) > 0 && pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+headerLen {
			return Reply{}, false
		}
		if pkt[9] != 1 { // protocol: not ICMP
			return Reply{}, false
		}
		ttl = int(pkt[8])
		pkt = pkt[ihl:]
	}
	if len(pkt) < headerLen {
		return Reply{}, false
	}
	if pkt[0] != echoReply || pkt[1] != 0 {
		return Reply{}, false
	}
	if Checksum(pkt) != 0 {
		return Reply{}, false
	}
	return Reply{
		ID:      binary.BigEndian.Uint16(pkt[4:6]),
		Seq:     binary.BigEndian.Uint16(pkt[6:8]),
		TTL:     ttl,
		Payload: append([]byte(nil), pkt[headerLen:]...),
	}, true
}
