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

package scanner

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"
)

// rawUptime estimates host uptime from two TCP timestamp samples. It only runs
// where raw sockets are available (root/CAP_NET_RAW); otherwise it returns 0
// so SCANLTE's deep scan degrades gracefully on unprivileged shells.
func rawUptime(ip string, port int) int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return 0
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	raddr := syscall.SockaddrInet4{Port: port}
	copy(raddr.Addr[:], net.ParseIP(ip).To4()[:4])

	samp1, wall1, ok := tcpTimestampSample(fd, raddr, uint16(port))
	if !ok {
		return 0
	}
	time.Sleep(1200 * time.Millisecond)
	samp2, wall2, ok := tcpTimestampSample(fd, raddr, uint16(port))
	if !ok {
		return 0
	}

	dTicks := uint64(samp2-samp1) & 0xffffffff
	dWall := wall2.Sub(wall1)
	if dTicks == 0 || dWall <= 0 {
		return 0
	}
	// Ticks-per-second rate, then uptime at sample 2. Anything that resolved
	// to <1 minute is nonsense (the peer just rebooted mid-scan or the samples
	// were both "0"); drop it.
	rate := float64(dTicks) / dWall.Seconds()
	if rate <= 0 {
		return 0
	}
	sec := float64(samp2) / rate
	if sec < 60 || sec > 2*365*24*3600 {
		return 0
	}
	return int(sec)
}

// tcpTimestampSample sends one TCP SYN with a localStorage timestamp option and
// waits for the matching SYN-ACK, returning the peer's TSval and the wall-clock
// time the sample was taken. Fails on any platform error, a filtered port, or a
// peer that strips TCP timestamps.
func tcpTimestampSample(fd int, raddr syscall.SockaddrInet4, port uint16) (tsval uint32, wall time.Time, ok bool) {
	buf := buildSyncPacket(raddr.Addr, port)
	if len(buf) == 0 {
		return 0, time.Time{}, false
	}
	if err := syscall.Sendto(fd, buf, 0, &raddr); err != nil {
		return 0, time.Time{}, false
	}
	wall = time.Now()

	deadline := time.Now().Add(2500 * time.Millisecond)
	rx := make([]byte, 65536)
	for time.Now().Before(deadline) {
		if err := syscall.SetNonblock(fd, true); err == nil {
			// non-blocking recv with a tiny sleep poll is simplest across
			// kernels; 2.5s deadline covers the wait.
			n, from, herr := syscall.Recvfrom(fd, rx, 0)
			if herr == nil && n > 0 {
				if sa, ok := from.(*syscall.SockaddrInet4); ok && sa.Port == int(port) {
					if ts, good := parseSynAckTimestamp(rx[:n]); good {
						return ts, wall, true
					}
				}
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	return 0, time.Time{}, false
}

// buildSyncPacket crafts a minimal IPv4+TCP SYN with a timestamp option,
// targeting the given destination port. The source neither binds a listener
// nor matters to the estimator (we only read the reply).
func buildSyncPacket(dstIP [4]byte, dstPort uint16) []byte {
	// IP header (20) + TCP header: 20 bytes + a 10-byte timestamp option
	// padded with one NOP to a 12-byte boundary.
	const ipLen, tcpLen = 20, 32
	pkt := make([]byte, ipLen+tcpLen)

	// --- IPv4 header ---
	pkt[0] = 0x45 // v4, IHL=5 words
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = 64 // TTL
	pkt[9] = syscall.IPPROTO_TCP
	copy(pkt[12:16], dstIP[:])

	// --- TCP header ---
	binary.BigEndian.PutUint16(pkt[20:22], 41234)      // src port
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)    // dst port
	binary.BigEndian.PutUint32(pkt[24:28], 1)          // seq
	binary.BigEndian.PutUint16(pkt[28:30], 0)          // ack
	binary.BigEndian.PutUint16(pkt[32:34], 8<<12|0x02) // header len 8 words + SYN
	binary.BigEndian.PutUint16(pkt[34:36], 64240)      // window
	binary.BigEndian.PutUint16(pkt[38:40], 0)          // urgent (checksum stays 0 for now)

	// --- TCP options: NOP + timestamp (kind 8, len 10, TSval=1, TSecr=0) ---
	pkt[40] = 1 // NOP
	pkt[41] = 8
	pkt[42] = 10
	binary.BigEndian.PutUint32(pkt[43:47], 1) // TSval
	// TSecr bytes 47-51 remain 0.

	// TCP checksum (pseudo-header + segment).
	pseudo := make([]byte, 12+len(pkt[20:]))
	copy(pseudo[0:4], dstIP[:])
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(pkt[20:])))
	copy(pseudo[12:], pkt[20:])
	cksum := ^onesComplement(pseudo)
	binary.BigEndian.PutUint16(pkt[36:38], uint16(cksum))

	// IP checksum.
	cksum = ^onesComplement(pkt)
	binary.BigEndian.PutUint16(pkt[10:12], uint16(cksum))
	return pkt
}

func onesComplement(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum
}

// parseSynAckTimestamp extracts the peer's TSval from a raw packet that must
// be an IPv4 TCP SYN-ACK. Returns ok=false for non-matching packets.
func parseSynAckTimestamp(pkt []byte) (uint32, bool) {
	if len(pkt) < 40 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if int(pkt[9]) != syscall.IPPROTO_TCP || ihl < 20 || len(pkt) < ihl+20 {
		return 0, false
	}
	tcp := pkt[ihl:]
	flags := binary.BigEndian.Uint16(tcp[12:14])
	if flags&0x12 != 0x12 { // SYN+ACK
		return 0, false
	}
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < 20 || len(tcp) < dataOffset {
		return 0, false
	}
	// Walk the options for kind=8 (timestamp).
	for i := 20; i+1 < dataOffset; {
		kind := tcp[i]
		switch {
		case kind == 0: // EOL
			return 0, false
		case kind == 1: // NOP
			i++
		default:
			if i+2 > dataOffset {
				return 0, false
			}
			l := int(tcp[i+1])
			if l < 2 || i+l > dataOffset {
				return 0, false
			}
			if kind == 8 && l == 10 {
				return binary.BigEndian.Uint32(tcp[i+2 : i+6]), true
			}
			i += l
		}
	}
	return 0, false
}
