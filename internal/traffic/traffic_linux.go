// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.
//
// This file is Linux-specific. It opens a raw AF_PACKET socket and parses the
// Ethernet/IPv4 headers itself, so per-host byte and packet counters need no
// external helper.

package traffic

import (
	"net"
	"sync"
	"syscall"
)

// Counter reads frames on an interface and accumulates per-host totals.
type Counter struct {
	fd      int
	ifindex int
	closed  chan struct{}

	mu   sync.Mutex
	host map[string]*counts
	prev map[string]*counts
}

// counts is the cumulative lifetime traffic of one host.
type counts struct {
	rxB, txB int64
	rxp, txp int64
}

// New opens an AF_PACKET socket bound to iface and starts the capture loop.
// It needs root (raw sockets); a regular user gets a descriptive error.
func New(iface string) (*Counter, error) {
	nif, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	if nif.Flags&net.FlagUp == 0 {
		return nil, nil // interface down: no traffic to count, no error either
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	ll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  nif.Index,
	}
	if err := syscall.Bind(fd, ll); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	c := &Counter{
		fd:      fd,
		ifindex: nif.Index,
		closed:  make(chan struct{}),
		host:    map[string]*counts{},
		prev:    map[string]*counts{},
	}
	go c.loop()
	return c, nil
}

// loop reads frames until the socket closes (or an error ends it).
func (c *Counter) loop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			select {
			case <-c.closed:
			default:
			}
			return
		}
		if n > 2 {
			c.parse(buf[:n])
		}
	}
}

// parse counts one Ethernet/IPv4 frame by source and destination host.
func (c *Counter) parse(frame []byte) {
	// Ethernet header: dst[0:6] src[6:12] ethertype[12:14].
	if len(frame) < 34 || frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}
	ip := 14
	src := net.IP(frame[ip+12 : ip+16]).String()
	dst := net.IP(frame[ip+16 : ip+20]).String()
	size := int64(len(frame))

	c.mu.Lock()
	out := c.host[src]
	if out == nil {
		out = &counts{}
		c.host[src] = out
	}
	out.txB += size
	out.txp++
	in := c.host[dst]
	if in == nil {
		in = &counts{}
		c.host[dst] = in
	}
	in.rxB += size
	in.rxp++
	c.mu.Unlock()
}

// Snapshot returns the traffic since the previous snapshot, per IPv4 host,
// clamping any discontinuity to zero.
func (c *Counter) Snapshot() map[string]Rate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]Rate{}
	keys := map[string]bool{}
	for k := range c.host {
		keys[k] = true
	}
	next := make(map[string]*counts, len(keys))
	for k := range keys {
		cur := c.host[k]
		p := c.prev[k]
		var r Rate
		if cur != nil {
			if p != nil {
				r.RXBytes = cur.rxB - p.rxB
				r.TXBytes = cur.txB - p.txB
				r.RXPkts = cur.rxp - p.rxp
				r.TXPkts = cur.txp - p.txp
			} else {
				r.RXBytes, r.TXBytes, r.RXPkts, r.TXPkts = cur.rxB, cur.txB, cur.rxp, cur.txp
			}
			r.clamp()
			next[k] = cur
		}
		out[k] = r
	}
	c.prev = next
	return out
}

func (r *Rate) clamp() {
	if r.RXBytes < 0 {
		r.RXBytes = 0
	}
	if r.TXBytes < 0 {
		r.TXBytes = 0
	}
	if r.RXPkts < 0 {
		r.RXPkts = 0
	}
	if r.TXPkts < 0 {
		r.TXPkts = 0
	}
}

// Close stops the capture loop and frees the socket.
func (c *Counter) Close() {
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	_ = syscall.Close(c.fd)
}

// htons swaps a 16-bit value to network byte order.
func htons(v uint16) uint16 {
	return v<<8&0xff00 | v>>8&0x00ff
}
