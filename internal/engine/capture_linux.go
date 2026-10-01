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

//go:build linux

package engine

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// ethPAll is ETH_P_ALL: receive frames of every protocol, the way tcpdump does
// before it applies a filter.
const ethPAll = 0x0003

// readWake bounds one capture read, so the loop notices cancellation within a
// fifth of a second rather than blocking on a quiet link.
const readWake = 200 * time.Millisecond

// packetSource is an AF_PACKET raw socket bound to one interface.
type packetSource struct{ fd int }

// newFrameSource opens a raw capture socket on iface. Opening it needs root and
// fails immediately otherwise (EPERM), so Start reports the problem instead of
// producing a capture that silently records nothing.
func newFrameSource(iface string) (frameSource, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, err
	}
	sll := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, sll); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	tv := syscall.NsecToTimeval(int64(readWake))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return &packetSource{fd: fd}, nil
}

// readFrame returns the next frame, or errNoFrame when nothing has arrived.
func (p *packetSource) readFrame(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(p.fd, buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
			return 0, errNoFrame
		}
		return 0, err
	}
	return n, nil
}

func (p *packetSource) close() error { return syscall.Close(p.fd) }

// htons converts a host-order 16-bit value to network order; the socket protocol
// and the link-layer sockaddr both want the big-endian form.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
