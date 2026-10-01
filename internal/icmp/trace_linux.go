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

// ipTTL is IP_TTL. It is spelled out because the standard syscall package does
// not export it on every architecture.
const ipTTL = 0x2

// TraceProbe sends one ICMPv4 echo request with the given IPv4 TTL and waits for
// the answer: an echo reply from the target, a time-exceeded from a router, or a
// destination-unreachable. rttMs is -1 when nothing answered in time. err is
// non-nil only when a raw socket cannot be used at all (not Linux, or not root);
// a silent probe is a NoReply, not an error.
func TraceProbe(ctx context.Context, ip string, ttl int, timeout time.Duration) (rttMs int, res TraceReply, err error) {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil {
		return -1, TraceReply{}, errors.New("icmp: not an IPv4 address: " + ip)
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if ttl < 1 {
		ttl = 1
	}
	if ttl > 255 {
		ttl = 255
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return -1, TraceReply{}, err
	}
	defer syscall.Close(fd)

	tv := syscall.NsecToTimeval(int64(readSlice))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipTTL, ttl); err != nil {
		return -1, TraceReply{}, err
	}

	id := uint16(os.Getpid())
	seq := uint16(atomic.AddUint32(&seqCounter, 1))
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().UnixNano()))
	msg := BuildEcho(id, seq, stamp[:])

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], addr.To4())
	start := time.Now()
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return -1, TraceReply{}, err
	}

	deadline := start.Add(timeout)
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return -1, TraceReply{Kind: NoReply}, nil
		}
		if !time.Now().Before(deadline) {
			return -1, TraceReply{Kind: NoReply}, nil
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			return -1, TraceReply{}, err
		}
		res, ok := DecodeTrace(buf[:n], id, seq)
		if !ok {
			// Some other ICMP message on the host: not our probe's answer.
			continue
		}
		return int(time.Since(start).Milliseconds()), res, nil
	}
}
