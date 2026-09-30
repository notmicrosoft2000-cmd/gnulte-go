// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

//go:build linux

package scanner

import "testing"

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
