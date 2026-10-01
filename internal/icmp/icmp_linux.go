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

package icmp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// seqCounter makes each echo request's sequence number unique within the
// process, so back-to-back probes cannot be answered by each other's replies.
var seqCounter uint32

// readSlice bounds one socket read. A read that finds nothing returns EAGAIN and
// the loop re-checks the deadline and context, so a silent target costs only the
// caller's timeout rather than a blocked goroutine.
const readSlice = 100 * time.Millisecond

// Ping sends one ICMPv4 echo request to ip and waits up to timeout for its
// reply. rtt is measured from send to receipt; ttl is the reply's TTL (0 when
// the socket did not supply an IPv4 header).
//
// err is non-nil only when a raw socket cannot be opened at all — not Linux, or
// not root. A host that simply does not answer returns ok=false with a nil
// error, so a caller does not fall back to a subprocess just because a target is
// silent (only when this package cannot run here).
func Ping(ctx context.Context, ip string, timeout time.Duration) (rttMs int, ttl int, ok bool, err error) {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil {
		return -1, 0, false, errors.New("icmp: not an IPv4 address: " + ip)
	}
	if timeout <= 0 {
		timeout = time.Second
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return -1, 0, false, err
	}
	defer syscall.Close(fd)

	// Bound each read so the loop can honour the deadline and a cancelled
	// context instead of blocking forever on a quiet segment.
	tv := syscall.NsecToTimeval(int64(readSlice))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	id := uint16(os.Getpid())
	seq := uint16(atomic.AddUint32(&seqCounter, 1))
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().UnixNano()))
	msg := BuildEcho(id, seq, stamp[:])

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], addr.To4())
	start := time.Now()
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return -1, 0, false, err
	}

	deadline := start.Add(timeout)
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return -1, 0, false, nil
		}
		if !time.Now().Before(deadline) {
			return -1, 0, false, nil
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			return -1, 0, false, err
		}
		reply, ok := Decode(buf[:n])
		if !ok || reply.ID != id || reply.Seq != seq {
			// Some other ICMP traffic on the host: not our answer.
			continue
		}
		return int(time.Since(start).Milliseconds()), reply.TTL, true, nil
	}
}
