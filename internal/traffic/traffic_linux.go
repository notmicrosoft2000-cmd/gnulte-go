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
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
)

// Counter reads frames on an interface and accumulates per-host totals plus
// per-conversation flow totals.
type Counter struct {
	fd      int
	ifindex int

	closeOnce sync.Once
	closed    chan struct{}

	mu   sync.Mutex
	host map[string]*counts
	prev map[string]*counts
	// flows hold cumulative conversation totals keyed "a|b" where a and b are
	// canonical endpoints ("ip:port"); prevFlow snapshots them for deltas.
	flows    map[string]*fcounts
	prevFlow map[string]*fcounts
}

// counts is the cumulative lifetime traffic of one host.
type counts struct {
	rxB, txB int64
	rxp, txp int64
}

// fcounts is the cumulative lifetime traffic of one endpoint conversation.
type fcounts struct {
	ab, ba   int64
	abp, bap int64
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
		fd:       fd,
		ifindex:  nif.Index,
		closed:   make(chan struct{}),
		host:     map[string]*counts{},
		prev:     map[string]*counts{},
		flows:    map[string]*fcounts{},
		prevFlow: map[string]*fcounts{},
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

// parse counts one Ethernet/IPv4 frame by source and destination host, and
// folds it into the conversation between the two endpoints (TCP/UDP ports, or
// port 0 for other protocols).
func (c *Counter) parse(frame []byte) {
	// Ethernet header: dst[0:6] src[6:12] ethertype[12:14].
	if len(frame) < 34 || frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}
	ip := 14
	src := net.IP(frame[ip+12 : ip+16]).String()
	dst := net.IP(frame[ip+16 : ip+20]).String()
	size := int64(len(frame))

	// Transport ports: the IP header length field gives the L4 offset. Only
	// TCP (6) and UDP (17) have ports; everything else gets port 0.
	var sport, dport uint16
	proto := frame[ip+9]
	if proto == 6 || proto == 17 {
		if l4 := ip + int(frame[ip]&0x0f)*4; len(frame) >= l4+4 {
			sport = binary.BigEndian.Uint16(frame[l4 : l4+2])
			dport = binary.BigEndian.Uint16(frame[l4+2 : l4+4])
		}
	}

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

	se, de := endpoint(src, sport), endpoint(dst, dport)
	a, b := se, de
	if a > b {
		a, b = b, a
	}
	fc := c.flows[a+"|"+b]
	if fc == nil {
		fc = &fcounts{}
		c.flows[a+"|"+b] = fc
	}
	if se < de { // A is src: frame travels A→B
		fc.ab += size
		fc.abp++
	} else { // B is src: frame travels B→A
		fc.ba += size
		fc.bap++
	}
	c.mu.Unlock()
}

// endpoint names one side of a conversation as "ip:port".
func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip + ":0"
	}
	return fmt.Sprintf("%s:%d", ip, port)
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
			// prev must be a copy: parse() keeps mutating c.host[k] in place,
			// so sharing the struct would make every delta read zero.
			cp := *cur
			next[k] = &cp
		}
		out[k] = r
	}
	c.prev = next
	return out
}

// SnapshotFlows returns the traffic in each conversation since the previous
// call, fresh for each interval (this is what the dashboard paints). A flow
// only appears once it has carried bytes in the interval — quiet conversations
// drop out; use FlowTotals for the whole-session picture.
func (c *Counter) SnapshotFlows() []Flow {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Flow, 0, len(c.flows))
	next := make(map[string]*fcounts, len(c.flows))
	for k, cur := range c.flows {
		a, b := splitFlowKey(k)
		p := c.prevFlow[k]
		var f Flow
		if p != nil {
			f.AB, f.BA = cur.ab-p.ab, cur.ba-p.ba
			f.ABp, f.BAp = cur.abp-p.abp, cur.bap-p.bap
		} else {
			f.AB, f.BA = cur.ab, cur.ba
			f.ABp, f.BAp = cur.abp, cur.bap
		}
		f.A, f.B = a, b
		f.clamp()
		if f.Total() > 0 {
			out = append(out, f)
		}
		// prevFlow must be a copy (same aliasing hazard as Snapshot's host
		// map): parse() keeps mutating c.flows[k] in place.
		cp := *cur
		next[k] = &cp
	}
	c.prevFlow = next
	return out
}

// FlowTotals returns every conversation's cumulative volume for the whole
// session (this is what the end-of-session report tables with). Idle
// conversations are included — total bytes are total bytes.
func (c *Counter) FlowTotals() []Flow {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Flow, 0, len(c.flows))
	for k, cur := range c.flows {
		a, b := splitFlowKey(k)
		out = append(out, Flow{
			A: a, B: b,
			AB: cur.ab, BA: cur.ba,
			ABp: cur.abp, BAp: cur.bap,
		})
	}
	return out
}

// splitFlowKey undoes the "a|b" canonical flow key.
func splitFlowKey(k string) (a, b string) {
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

func (f *Flow) clamp() {
	if f.AB < 0 {
		f.AB = 0
	}
	if f.BA < 0 {
		f.BA = 0
	}
	if f.ABp < 0 {
		f.ABp = 0
	}
	if f.BAp < 0 {
		f.BAp = 0
	}
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

// Close stops the capture loop and frees the socket. It runs at most once,
// on any number of concurrent callers: gnulte-lan registers this method as a
// signal cleanup *and* defers the raw method, so both the tui goroutine and
// the main loop can reach it on the same Ctrl+C. The check-then-act select
// below was fine for one caller but panicked ("close of closed channel") when
// both passed the select before either closed.
func (c *Counter) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		syscall.Close(c.fd)
	})
}

// htons swaps a 16-bit value to network byte order.
func htons(v uint16) uint16 {
	return v<<8&0xff00 | v>>8&0x00ff
}
