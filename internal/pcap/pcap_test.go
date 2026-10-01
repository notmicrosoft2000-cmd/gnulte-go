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

package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

// frame builds a plausible Ethernet frame with the given ethertype and payload,
// so the round-trip carries real link-layer bytes rather than a bare buffer.
func frame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14+len(payload))
	copy(f[0:6], []byte{0, 1, 2, 3, 4, 5})
	copy(f[6:12], []byte{6, 7, 8, 9, 10, 11})
	binary.BigEndian.PutUint16(f[12:14], etherType)
	copy(f[14:], payload)
	return f
}

// TestWriterRoundTrip is the core promise: what we write is a valid libpcap file
// that reads back byte for byte, with the standard magic, version, snaplen and
// Ethernet link type. If any field were written in the wrong place or order a
// reader (Wireshark, tcpdump) would reject the capture.
func TestWriterRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	f1 := frame(0x0800, []byte("first packet body"))
	f2 := frame(0x0806, []byte("arp"))
	ts1 := time.Unix(1_700_000_000, 123_456_000)
	ts2 := time.Unix(1_700_000_001, 7_000)
	for _, p := range []struct {
		ts   time.Time
		data []byte
	}{{ts1, f1}, {ts2, f2}} {
		if err := w.WritePacket(p.ts, p.data); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.Header.Magic != Magic || r.Header.Major != VersionMajor || r.Header.Minor != VersionMinor {
		t.Fatalf("header = %+v, want magic %#x version %d.%d", r.Header, Magic, VersionMajor, VersionMinor)
	}
	if r.Header.SnapLen != SnapLen {
		t.Fatalf("snaplen = %d, want %d", r.Header.SnapLen, SnapLen)
	}
	if r.Header.Network != LinkTypeEthernet {
		t.Fatalf("link type = %d, want %d (Ethernet)", r.Header.Network, LinkTypeEthernet)
	}

	for i, want := range []struct {
		ts   time.Time
		data []byte
	}{{ts1, f1}, {ts2, f2}} {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		if !bytes.Equal(got.Data, want.data) {
			t.Fatalf("packet #%d data mismatch", i)
		}
		if uint32(len(got.Data)) != got.OrigLen {
			t.Fatalf("packet #%d orig_len = %d, want %d", i, got.OrigLen, len(got.Data))
		}
		if !got.Time.Equal(want.ts.Truncate(time.Microsecond)) {
			t.Fatalf("packet #%d time = %v, want %v", i, got.Time, want.ts)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last packet: err = %v, want io.EOF", err)
	}
}

// TestReaderAcceptsBigEndian proves the reader is not hard-wired to our writer's
// little-endian order: a file produced on a big-endian host must decode too.
func TestReaderAcceptsBigEndian(t *testing.T) {
	var buf bytes.Buffer
	bo := binary.BigEndian
	h := make([]byte, 24)
	bo.PutUint32(h[0:4], Magic)
	bo.PutUint16(h[4:6], VersionMajor)
	bo.PutUint16(h[6:8], VersionMinor)
	bo.PutUint32(h[16:20], SnapLen)
	bo.PutUint32(h[20:24], uint32(LinkTypeEthernet))
	buf.Write(h)

	data := frame(0x0800, []byte("big endian"))
	var rec [16]byte
	bo.PutUint32(rec[0:4], 1_700_000_000)
	bo.PutUint32(rec[4:8], 42)
	bo.PutUint32(rec[8:12], uint32(len(data)))
	bo.PutUint32(rec[12:16], uint32(len(data)))
	buf.Write(rec[:])
	buf.Write(data)

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader(big endian): %v", err)
	}
	p, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if !bytes.Equal(p.Data, data) {
		t.Fatalf("data = %q, want %q", p.Data, data)
	}
	if p.Time.Unix() != 1_700_000_000 || p.Time.Nanosecond() != 42000 {
		t.Fatalf("time = %v, want 1700000000.000042", p.Time)
	}
}

// TestWriterTruncatesToSnapLen checks the one place the record can diverge from
// the wire: a frame past the snaplen is cut in the record, and orig_len keeps the
// full size so a reader can still see that bytes were dropped.
func TestWriterTruncatesToSnapLen(t *testing.T) {
	big := make([]byte, SnapLen+100)
	for i := range big {
		big[i] = byte(i)
	}
	var buf bytes.Buffer
	w, err := NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WritePacket(time.Unix(1, 0), big); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	p, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(p.Data) != SnapLen {
		t.Fatalf("included len = %d, want %d", len(p.Data), SnapLen)
	}
	if p.OrigLen != uint32(len(big)) {
		t.Fatalf("orig_len = %d, want %d", p.OrigLen, len(big))
	}
}

// TestEmptyCaptureIsAValidFile: the global header is written up front, so a
// capture stopped before any packet arrived is still a file a reader accepts.
func TestEmptyCaptureIsAValidFile(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewWriter(&buf); err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader on a header-only file: %v", err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next on empty capture: err = %v, want io.EOF", err)
	}
}

// TestReaderRejectsGarbage: a file that is not libpcap must fail loudly at the
// header rather than be misread as packets.
func TestReaderRejectsGarbage(t *testing.T) {
	if _, err := NewReader(bytes.NewReader([]byte("not a pcap file at all!!"))); err == nil {
		t.Fatal("NewReader accepted a non-pcap file")
	}
	if _, err := NewReader(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("NewReader accepted a truncated header")
	}
}
