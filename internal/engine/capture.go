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

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"gnulte-go/internal/pcap"
)

// errNoFrame means the capture source has nothing right now; call again. It is
// how a source reports a socket read timeout.
var errNoFrame = errors.New("capture: no frame")

// frameSource is a link-layer capture source (AF_PACKET on Linux). readFrame
// blocks up to the source's own timeout and returns errNoFrame on a timeout; any
// other error (including io.EOF) means the source is finished. close releases the
// handle and unblocks a pending read.
type frameSource interface {
	readFrame(buf []byte) (int, error)
	close() error
}

// captureHandle is a running capture. cancel it and wait on done for the loop to
// close the source and the output.
type captureHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// captureLoop streams matching frames to dst as a libpcap capture until ctx is
// cancelled or the source fails. Both the source and dst are closed on the way
// out, so a stopped capture leaves a finished file behind.
func captureLoop(ctx context.Context, src frameSource, dst io.WriteCloser, targets map[string]bool) {
	defer src.close()
	defer dst.Close()
	w, err := pcap.NewWriter(dst)
	if err != nil {
		return
	}
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := src.readFrame(buf)
		if err == errNoFrame {
			continue
		}
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if !frameMatches(buf[:n], targets) {
			continue
		}
		if err := w.WritePacket(time.Now(), buf[:n]); err != nil {
			return
		}
	}
}

// writeCloser adapts a plain writer (stdout) to the closer captureLoop expects.
type writeCloser struct{ io.Writer }

func (writeCloser) Close() error { return nil }

// hostSet turns target address strings into the exact byte keys frameMatches
// tests. Unparseable entries are dropped: they can never match a frame.
func hostSet(targets []string) map[string]bool {
	set := make(map[string]bool, len(targets))
	for _, t := range targets {
		if k, ok := ipKey(t); ok {
			set[k] = true
		}
	}
	return set
}

// ipKey renders an address as its network-order bytes, IPv4 as four and IPv6 as
// sixteen, so a target and a frame address compare byte for byte instead of
// through string formatting.
func ipKey(s string) (string, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return string(v4), true
	}
	if v16 := ip.To16(); v16 != nil {
		return string(v16), true
	}
	return "", false
}

// frameMatches reports whether an Ethernet frame is traffic to or from one of
// targets. An empty set means capture everything. ARP and other non-IP frames
// are not attributed to a host, so they are skipped while a filter is active.
func frameMatches(frame []byte, targets map[string]bool) bool {
	if len(targets) == 0 {
		return true
	}
	off, etherType, ok := l3Offset(frame)
	if !ok {
		return false
	}
	switch etherType {
	case 0x0800: // IPv4
		if len(frame) < off+20 {
			return false
		}
		return targets[string(frame[off+12:off+16])] || targets[string(frame[off+16:off+20])]
	case 0x86dd: // IPv6
		if len(frame) < off+40 {
			return false
		}
		return targets[string(frame[off+8:off+24])] || targets[string(frame[off+24:off+40])]
	}
	return false
}

// l3Offset skips the Ethernet header (and up to two VLAN tags) and returns the
// offset of the network-layer header and its ethertype.
func l3Offset(frame []byte) (int, uint16, bool) {
	if len(frame) < 14 {
		return 0, 0, false
	}
	et := binary.BigEndian.Uint16(frame[12:14])
	off := 14
	for i := 0; i < 2 && (et == 0x8100 || et == 0x88a8); i++ {
		if len(frame) < off+4 {
			return 0, 0, false
		}
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	return off, et, true
}
