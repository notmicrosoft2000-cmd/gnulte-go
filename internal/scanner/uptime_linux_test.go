// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

//go:build linux

package scanner

import (
	"encoding/binary"
	"testing"
)

func TestParseSynAckTimestamp(t *testing.T) {
	// IPv4 header (IHL=5) + TCP header (data offset 8 → has options).
	// The timestamp kind lives at TCP offset 20.
	pkt := make([]byte, 20+32)
	pkt[0] = 0x45
	pkt[9] = 6
	pkt[20+13] = 0x12 // SYN+ACK (flags live in the low byte of the 16-bit field)
	hdr := (8) << 4   // data offset = 8 words
	pkt[20+12] = byte(hdr)
	pkt[20+20] = 8  // kind: timestamp
	pkt[20+21] = 10 // length
	pkt[20+22] = 0xde
	pkt[20+23] = 0xad
	pkt[20+24] = 0xbe
	pkt[20+25] = 0xef
	ts, ok := parseSynAckTimestamp(pkt)
	if !ok || ts != 0xdeadbeef {
		t.Errorf("parseSynAckTimestamp = %#x,%v want 0xdeadbeef,true", ts, ok)
	}
	// No timestamp option → not ok.
	pkt[20+20] = 1 // NOP
	ts, ok = parseSynAckTimestamp(pkt)
	if ok {
		t.Errorf("parseSynAckTimestamp(nop) = %#x,%v want 0,false", ts, ok)
	}
	if _, ok := parseSynAckTimestamp([]byte{1}); ok {
		t.Error("parseSynAckTimestamp(short) should fail")
	}
}

// checksumSum is the internet-checksum accumulator over 16-bit big-endian
// words. A header that carries a correct checksum sums to 0xffff.
func checksumSum(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return s
}

// TestBuildSyncPacketSourceIPAndChecksums: the raw socket sets IP_HDRINCL, so
// the kernel only fills a zero source address and never fixes our TCP checksum.
// A 0.0.0.0 source in the pseudo-header would fail the peer's checksum and no
// SYN-ACK would ever return, so the packet must carry a real local source and
// checksums consistent with it.
func TestBuildSyncPacketSourceIPAndChecksums(t *testing.T) {
	src := [4]byte{192, 168, 1, 50}
	dst := [4]byte{10, 0, 0, 7}
	pkt := buildSyncPacket(src, dst, 443)
	if len(pkt) != 52 {
		t.Fatalf("packet length = %d, want 52", len(pkt))
	}
	gotSrc := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}
	gotDst := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}
	if gotSrc != src {
		t.Errorf("IP source = %v, want %v", gotSrc, src)
	}
	if gotDst != dst {
		t.Errorf("IP destination = %v, want %v", gotDst, dst)
	}
	if port := binary.BigEndian.Uint16(pkt[22:24]); port != 443 {
		t.Errorf("TCP dst port = %d, want 443", port)
	}
	if s := checksumSum(pkt[:20]); s != 0xffff {
		t.Errorf("IPv4 header checksum invalid (sum = %#x)", s)
	}
	// TCP checksum covers the pseudo-header (src, dst, zero, proto, length)
	// plus the TCP segment.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 6 // IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(pkt)-20))
	full := append(pseudo, pkt[20:]...)
	if s := checksumSum(full); s != 0xffff {
		t.Errorf("TCP checksum invalid (sum = %#x)", s)
	}
}
