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
	"testing"
)

// TestChecksumMatchesRFC1071 pins the checksum to the worked example in RFC
// 1071 (the 8 bytes 00 01 f2 03 f4 f5 f6 f7 sum to the complement 0x220d). A
// wrong checksum makes every echo request we send invisible to the target, so
// this is the one arithmetic result worth asserting against a fixed vector.
func TestChecksumMatchesRFC1071(t *testing.T) {
	got := Checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7})
	if got != 0x220d {
		t.Fatalf("Checksum = 0x%04x, want 0x220d", got)
	}
}

// TestChecksumHandlesOddLength covers the padded tail: an odd number of bytes
// still has to checksum, and the padding is a zero high byte, not a lost byte.
func TestChecksumHandlesOddLength(t *testing.T) {
	// Same message with a trailing byte: sum += 0x0800 instead of nothing.
	if got := Checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x08}); got == 0x220d {
		t.Fatal("odd-length checksum ignored the final byte")
	}
	// A message and the same message with a zero pad are equivalent.
	a := Checksum([]byte{0x12, 0x34, 0x56})
	b := Checksum([]byte{0x12, 0x34, 0x56, 0x00})
	if a != b {
		t.Fatalf("zero pad changed the checksum: 0x%04x vs 0x%04x", a, b)
	}
}

// TestBuildEchoVerifiesAndCarriesFields is the send path: the built request must
// be a well-formed echo request (type 8, code 0) with the caller's id and
// sequence and a payload that survived intact, and its own checksum must verify
// to zero when the receiver runs the checksum over the whole message.
func TestBuildEchoVerifiesAndCarriesFields(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	msg := BuildEcho(0x1234, 0xbeef, payload)

	if len(msg) != headerLen+len(payload) {
		t.Fatalf("message is %d bytes, want %d", len(msg), headerLen+len(payload))
	}
	if msg[0] != echoRequest || msg[1] != 0 {
		t.Fatalf("type/code = %d/%d, want 8/0 (echo request)", msg[0], msg[1])
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 0x1234 {
		t.Fatalf("id = 0x%04x, want 0x1234", got)
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != 0xbeef {
		t.Fatalf("seq = 0x%04x, want 0xbeef", got)
	}
	if Checksum(msg) != 0 {
		t.Fatal("the message does not verify against its own checksum")
	}
	for i, b := range payload {
		if msg[headerLen+i] != b {
			t.Fatalf("payload byte %d = 0x%02x, want 0x%02x", i, msg[headerLen+i], b)
		}
	}
}

// ipHeader builds a minimal IPv4 header in front of icmpMsg, so the tests can
// cover both shapes a raw socket may hand back.
func ipHeader(ttl, proto byte, icmpMsg []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // IPv4, 5 words of header
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(icmpMsg)))
	h[8] = ttl
	h[9] = proto
	return append(h, icmpMsg...)
}

// TestDecodeReadsABareReply covers the shape where the socket hands back the
// ICMP message on its own: the decoder must still find it and report the fields.
func TestDecodeReadsABareReply(t *testing.T) {
	msg := buildEcho(echoReply, 0x4321, 7, []byte("nonce"))
	reply, ok := Decode(msg)
	if !ok {
		t.Fatal("Decode rejected a well-formed bare echo reply")
	}
	if reply.ID != 0x4321 || reply.Seq != 7 {
		t.Fatalf("id/seq = 0x%04x/%d, want 0x4321/7", reply.ID, reply.Seq)
	}
	if string(reply.Payload) != "nonce" {
		t.Fatalf("payload = %q, want %q", reply.Payload, "nonce")
	}
	if reply.TTL != 0 {
		t.Fatalf("TTL = %d, want 0 without an IP header", reply.TTL)
	}
}

// TestDecodeReadsTheIPHeader covers the other socket shape: when the IPv4 header
// is present the decoder must skip it correctly and surface its TTL, which the
// console prints and a later traceroute depends on.
func TestDecodeReadsTheIPHeader(t *testing.T) {
	msg := buildEcho(echoReply, 0x0011, 9, []byte{1, 2, 3})
	reply, ok := Decode(ipHeader(57, 1, msg))
	if !ok {
		t.Fatal("Decode rejected an echo reply behind an IPv4 header")
	}
	if reply.TTL != 57 {
		t.Fatalf("TTL = %d, want 57", reply.TTL)
	}
	if reply.ID != 0x0011 || reply.Seq != 9 {
		t.Fatalf("id/seq = 0x%04x/%d, want 0x0011/9", reply.ID, reply.Seq)
	}
	if len(reply.Payload) != 3 {
		t.Fatalf("payload len = %d, want 3 (the IP header must not leak in)", len(reply.Payload))
	}
}

// TestDecodeRejectsWhatIsNotAnEchoReply is the discriminating half: a raw ICMP
// socket sees every ICMP message on the host, so mistaking a request, another
// protocol, a truncated frame or a corrupt reply for an answer would report a
// host as reachable on evidence that never arrived.
func TestDecodeRejectsWhatIsNotAnEchoReply(t *testing.T) {
	reply := buildEcho(echoReply, 1, 1, []byte("x"))

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"an echo request", buildEcho(echoRequest, 1, 1, []byte("x"))},
		{"an empty packet", nil},
		{"a truncated ICMP header", reply[:headerLen-1]},
		{"a truncated message behind an IP header", ipHeader(64, 1, reply[:4])},
		{"a non-ICMP protocol", ipHeader(64, 6, reply)},
		{"a corrupt checksum", func() []byte {
			bad := append([]byte(nil), reply...)
			bad[2] ^= 0xff // flip a checksum bit
			return bad
		}()},
		{"a reply with a nonzero code", func() []byte {
			bad := append([]byte(nil), reply...)
			bad[1] = 3
			bad[2], bad[3] = 0, 0
			binary.BigEndian.PutUint16(bad[2:4], Checksum(bad))
			return bad
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := Decode(c.pkt); ok {
				t.Fatalf("Decode accepted %s as an echo reply", c.name)
			}
		})
	}
}

// TestDecodeCopiesPayload guards the buffer reuse that the socket loop relies
// on: the same read buffer is handed back on every iteration, so the decoder
// must return its own copy or a later read would rewrite the payload the caller
// is still holding.
func TestDecodeCopiesPayload(t *testing.T) {
	pkt := buildEcho(echoReply, 1, 1, []byte("payload"))
	reply, ok := Decode(pkt)
	if !ok {
		t.Fatal("Decode rejected a valid reply")
	}
	for i := range pkt {
		pkt[i] = 0
	}
	if string(reply.Payload) != "payload" {
		t.Fatalf("payload = %q after the source buffer was reused, want %q", reply.Payload, "payload")
	}
}
