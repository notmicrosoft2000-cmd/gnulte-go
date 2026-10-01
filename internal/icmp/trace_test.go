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

// ipv4Frame wraps an ICMP message in a minimal IPv4 header, the way a raw ICMP
// socket hands it back.
func ipv4Frame(src [4]byte, ttl byte, msg []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[8] = ttl
	h[9] = 1 // protocol: ICMP
	copy(h[12:16], src[:])
	return append(h, msg...)
}

// errorFrame builds an ICMP error (time exceeded or destination unreachable)
// that quotes an echo request, as a router would send it.
func errorFrame(typ byte, id, seq uint16) []byte {
	quote := ipv4Frame([4]byte{192, 168, 1, 50}, 64, BuildEcho(id, seq, nil))
	msg := make([]byte, headerLen+len(quote))
	msg[0] = typ
	copy(msg[headerLen:], quote)
	binary.BigEndian.PutUint16(msg[2:4], Checksum(msg))
	return msg
}

func TestDecodeTraceEchoReply(t *testing.T) {
	reply := buildEcho(echoReply, idOf(), seqOf(), []byte("hi"))

	got, ok := DecodeTrace(ipv4Frame([4]byte{10, 0, 0, 9}, 57, reply), idOf(), seqOf())
	if !ok {
		t.Fatal("a matching echo reply was rejected")
	}
	if got.Kind != TargetReply {
		t.Fatalf("Kind = %v, want TargetReply", got.Kind)
	}
	if got.Addr != "10.0.0.9" {
		t.Fatalf("Addr = %q, want 10.0.0.9", got.Addr)
	}
	if got.TTL != 57 {
		t.Fatalf("TTL = %d, want 57", got.TTL)
	}
	if !got.Terminal() {
		t.Fatal("a target reply must be terminal")
	}
}

func TestDecodeTraceTimeExceededNamesTheRouter(t *testing.T) {
	pkt := ipv4Frame([4]byte{10, 0, 0, 1}, 63, errorFrame(timeExceeded, idOf(), seqOf()))
	got, ok := DecodeTrace(pkt, idOf(), seqOf())
	if !ok {
		t.Fatal("a matching time-exceeded was rejected")
	}
	if got.Kind != HopReply {
		t.Fatalf("Kind = %v, want HopReply", got.Kind)
	}
	if got.Addr != "10.0.0.1" {
		t.Fatalf("Addr = %q, want the router 10.0.0.1", got.Addr)
	}
	if got.Terminal() {
		t.Fatal("an intermediate hop must not end the trace")
	}
}

func TestDecodeTraceUnreachableIsTerminal(t *testing.T) {
	pkt := ipv4Frame([4]byte{192, 168, 1, 1}, 64, errorFrame(destUnreachable, idOf(), seqOf()))
	got, ok := DecodeTrace(pkt, idOf(), seqOf())
	if !ok {
		t.Fatal("a matching destination-unreachable was rejected")
	}
	if got.Kind != Unreachable || !got.Terminal() {
		t.Fatalf("Kind = %v terminal=%v, want Unreachable/true", got.Kind, got.Terminal())
	}
}

// TestDecodeTraceBareErrorHasNoAddress: a raw socket that omits the outer IP
// header still classifies the error, it just cannot name the router.
func TestDecodeTraceBareErrorHasNoAddress(t *testing.T) {
	got, ok := DecodeTrace(errorFrame(timeExceeded, idOf(), seqOf()), idOf(), seqOf())
	if !ok || got.Kind != HopReply {
		t.Fatalf("bare error decoded to %+v ok=%v, want HopReply", got, ok)
	}
	if got.Addr != "" {
		t.Fatalf("Addr = %q, want empty with no outer header", got.Addr)
	}
}

func TestDecodeTraceRejectsForeignPackets(t *testing.T) {
	reply := buildEcho(echoReply, idOf(), seqOf(), []byte{0xde, 0xad, 0xbe, 0xef})

	corrupt := append([]byte(nil), reply...)
	corrupt[headerLen] ^= 0xff // payload byte flips, so the checksum no longer matches

	cases := []struct {
		name string
		pkt  []byte
		id   uint16
		seq  uint16
	}{
		{"wrong id", reply, idOf() + 1, seqOf()},
		{"wrong seq", reply, idOf(), seqOf() + 1},
		{"our own request", BuildEcho(idOf(), seqOf(), nil), idOf(), seqOf()},
		{"corrupt checksum", corrupt, idOf(), seqOf()},
		{"truncated reply", reply[:6], idOf(), seqOf()},
		{"empty", nil, idOf(), seqOf()},
		{"error quoting another probe", errorFrame(timeExceeded, idOf()+7, seqOf()), idOf(), seqOf()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := DecodeTrace(tc.pkt, tc.id, tc.seq); ok {
				t.Fatalf("accepted %+v, want rejection", got)
			}
		})
	}
}

func TestTraceKindString(t *testing.T) {
	want := map[TraceKind]string{
		NoReply:     "timeout",
		HopReply:    "hop",
		TargetReply: "reply",
		Unreachable: "unreachable",
	}
	for k, s := range want {
		if k.String() != s {
			t.Errorf("TraceKind(%d).String() = %q, want %q", k, k.String(), s)
		}
	}
}

// idOf/seqOf are the probe identity the fixtures are built with.
func idOf() uint16  { return 0x4242 }
func seqOf() uint16 { return 0x0101 }
