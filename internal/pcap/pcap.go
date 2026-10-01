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

// Package pcap writes and reads the classic libpcap capture format — the file
// tcpdump and Wireshark read — using only the standard library. It is the file
// layer behind the engine's in-process --capture; the framing is platform
// neutral, so it is unit-testable without a raw socket.
package pcap

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// Magic is the microsecond-resolution libpcap magic number. A writer stores it
// in its own byte order; a reader uses which way round it finds the magic to
// pick the order for the rest of the file.
const Magic = 0xa1b2c3d4

// Version numbers every libpcap file declares: 2.4 is the classic format.
const (
	VersionMajor = 2
	VersionMinor = 4
)

// LinkType is the link-layer type recorded in the file header (the DLT_* value).
type LinkType uint32

const (
	// LinkTypeEthernet is DLT_EN10MB: an Ethernet frame with a 14-byte header.
	LinkTypeEthernet LinkType = 1
)

// SnapLen caps the bytes stored per packet. The classic 65535 covers any
// Ethernet frame without truncation.
const SnapLen = 65535

// FileHeader is the 24-byte global header at the start of a libpcap file.
type FileHeader struct {
	Magic    uint32
	Major    uint16
	Minor    uint16
	ThisZone int32
	SigFigs  uint32
	SnapLen  uint32
	Network  LinkType
}

// Packet is one decoded capture record.
type Packet struct {
	Time    time.Time
	Data    []byte
	OrigLen uint32 // the on-wire length, which may exceed len(Data)
}

// Writer streams packets as a libpcap file in little-endian byte order (the
// order whose on-disk magic is the familiar d4 c3 b2 a1). The global header is
// written by NewWriter, so even a capture with no packets is a valid file.
type Writer struct {
	w     io.Writer
	order binary.ByteOrder
}

// NewWriter writes the global header to w and returns a writer for the records.
func NewWriter(w io.Writer) (*Writer, error) {
	bo := binary.LittleEndian
	h := make([]byte, 24)
	bo.PutUint32(h[0:4], Magic)
	bo.PutUint16(h[4:6], VersionMajor)
	bo.PutUint16(h[6:8], VersionMinor)
	bo.PutUint32(h[8:12], 0) // thiszone
	bo.PutUint32(h[12:16], 0)
	bo.PutUint32(h[16:20], SnapLen)
	bo.PutUint32(h[20:24], uint32(LinkTypeEthernet))
	if _, err := w.Write(h); err != nil {
		return nil, err
	}
	return &Writer{w: w, order: bo}, nil
}

// WritePacket appends one frame with the given capture time. A frame longer
// than SnapLen is truncated in the record but its full length is preserved in
// orig_len, exactly as libpcap requires.
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	incl := len(data)
	if incl > SnapLen {
		incl = SnapLen
	}
	var hdr [16]byte
	w.order.PutUint32(hdr[0:4], uint32(ts.Unix()))
	w.order.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000))
	w.order.PutUint32(hdr[8:12], uint32(incl))
	w.order.PutUint32(hdr[12:16], uint32(len(data)))
	if _, err := w.w.Write(hdr[:]); err != nil {
		return err
	}
	if incl > 0 {
		if _, err := w.w.Write(data[:incl]); err != nil {
			return err
		}
	}
	return nil
}

// Reader decodes a libpcap stream in either byte order. It exists so a capture
// can be verified by reopening it, and so the two orders can be tested against
// each other.
type Reader struct {
	r      io.Reader
	order  binary.ByteOrder
	Header FileHeader
}

// NewReader consumes the global header and fixes the byte order from the magic.
func NewReader(r io.Reader) (*Reader, error) {
	var h [24]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(h[0:4]) == Magic:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(h[0:4]) == Magic:
		order = binary.BigEndian
	default:
		return nil, errors.New("pcap: not a libpcap file (bad magic)")
	}
	return &Reader{
		r:     r,
		order: order,
		Header: FileHeader{
			Magic:    order.Uint32(h[0:4]),
			Major:    order.Uint16(h[4:6]),
			Minor:    order.Uint16(h[6:8]),
			ThisZone: int32(order.Uint32(h[8:12])),
			SigFigs:  order.Uint32(h[12:16]),
			SnapLen:  order.Uint32(h[16:20]),
			Network:  LinkType(order.Uint32(h[20:24])),
		},
	}, nil
}

// Next returns the next record, or io.EOF at a clean end of file.
func (r *Reader) Next() (Packet, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
		return Packet{}, err
	}
	sec := r.order.Uint32(hdr[0:4])
	usec := r.order.Uint32(hdr[4:8])
	incl := r.order.Uint32(hdr[8:12])
	orig := r.order.Uint32(hdr[12:16])
	if incl > SnapLen {
		return Packet{}, errors.New("pcap: record length exceeds snaplen")
	}
	data := make([]byte, incl)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return Packet{}, err
	}
	return Packet{
		Time:    time.Unix(int64(sec), int64(usec)*1000),
		Data:    data,
		OrigLen: orig,
	}, nil
}
