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

package icmp

import (
	"encoding/binary"
	"net"
)

// The extra ICMPv4 message types a traceroute has to recognise.
const (
	destUnreachable = 3
	timeExceeded    = 11
)

// TraceKind classifies what answered a traceroute probe.
type TraceKind int

const (
	// NoReply is a probe that timed out; nothing came back.
	NoReply TraceKind = iota
	// HopReply is a router on the path reporting that the TTL expired. It
	// proves the probe travelled at least this many hops.
	HopReply
	// TargetReply is an echo reply from the destination itself: the trace ends.
	TargetReply
	// Unreachable is a destination-unreachable from a router or the host; the
	// path ends here too.
	Unreachable
)

// String names the kind for the live table, the JSON and the report.
func (k TraceKind) String() string {
	switch k {
	case HopReply:
		return "hop"
	case TargetReply:
		return "reply"
	case Unreachable:
		return "unreachable"
	}
	return "timeout"
}

// TraceReply is the classification of a received packet for an echo probe.
type TraceReply struct {
	Kind TraceKind
	Addr string // the responder's IPv4 address ("" when the packet had no IP header)
	TTL  int    // TTL of the encapsulating IPv4 header, 0 when absent
}

// Terminal reports whether this reply ends the trace: the destination answered,
// or the path reported it unreachable.
func (r TraceReply) Terminal() bool {
	return r.Kind == TargetReply || r.Kind == Unreachable
}

// DecodeTrace classifies a received packet as the answer to the echo request
// with (id, seq). It understands a plain echo reply (the target) and the ICMP
// errors that quote our request — time exceeded (a router) and destination
// unreachable. Anything else is rejected: another host's traffic, our own
// outgoing echo request, a truncated message, or one whose checksum does not
// verify.
func DecodeTrace(pkt []byte, id, seq uint16) (TraceReply, bool) {
	addr := ""
	ttl := 0
	if len(pkt) >= 20 && pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+headerLen {
			return TraceReply{}, false
		}
		if pkt[9] != 1 { // protocol: not ICMP
			return TraceReply{}, false
		}
		addr = ipString(pkt[12:16])
		ttl = int(pkt[8])
		pkt = pkt[ihl:]
	}
	if len(pkt) < headerLen || Checksum(pkt) != 0 {
		return TraceReply{}, false
	}
	switch pkt[0] {
	case echoReply:
		if pkt[1] != 0 || binary.BigEndian.Uint16(pkt[4:6]) != id || binary.BigEndian.Uint16(pkt[6:8]) != seq {
			return TraceReply{}, false
		}
		return TraceReply{Kind: TargetReply, Addr: addr, TTL: ttl}, true
	case timeExceeded, destUnreachable:
		// An ICMP error quotes the datagram that caused it: the original IPv4
		// header plus at least its first eight bytes, which for an echo carry
		// the identifier and sequence number we have to match.
		inner, ok := quotedEcho(pkt[headerLen:])
		if !ok || inner.id != id || inner.seq != seq {
			return TraceReply{}, false
		}
		kind := Unreachable
		if pkt[0] == timeExceeded {
			kind = HopReply
		}
		return TraceReply{Kind: kind, Addr: addr, TTL: ttl}, true
	}
	return TraceReply{}, false
}

type echoIDs struct{ id, seq uint16 }

// quotedEcho extracts the identifier and sequence from the echo request quoted
// inside an ICMP error message.
func quotedEcho(b []byte) (echoIDs, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return echoIDs{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+headerLen || b[9] != 1 {
		return echoIDs{}, false
	}
	inner := b[ihl:]
	if inner[0] != echoRequest {
		return echoIDs{}, false
	}
	return echoIDs{
		id:  binary.BigEndian.Uint16(inner[4:6]),
		seq: binary.BigEndian.Uint16(inner[6:8]),
	}, true
}

// ipString renders four network-order bytes as dotted quad.
func ipString(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}
