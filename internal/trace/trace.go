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

// Package trace walks a path one TTL at a time and accumulates per-hop timing.
// The probing itself lives in internal/icmp (raw ICMP echo with a per-probe
// TTL); this package owns the walk — how many probes per hop, when the trace
// ends, and the min/avg/max/loss arithmetic — behind a probe seam so the walk
// is unit-testable without a raw socket.
package trace

import (
	"context"
	"math"
	"time"

	"gnulte-go/internal/icmp"
)

// ProbeFunc sends one probe to ip with the given IPv4 TTL. It returns the RTT in
// milliseconds (-1 when nothing answered), the classification of whatever
// answered, and an error only when the in-Go probe cannot run at all. The
// default is icmp.TraceProbe; tests inject a scripted fake.
type ProbeFunc func(ctx context.Context, ip string, ttl int, timeout time.Duration) (int, icmp.TraceReply, error)

// Options configures a trace.
type Options struct {
	MaxHops  int           // highest TTL to try
	Probes   int           // probes per hop
	Timeout  time.Duration // wait for each probe
	Interval time.Duration // pause between the probes of one hop
}

// Defaults fills in the conventional values for any unset field, so callers can
// pass a zero Options for a stock trace.
func (o *Options) Defaults() {
	if o.MaxHops <= 0 {
		o.MaxHops = 30
	}
	if o.Probes <= 0 {
		o.Probes = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.Interval < 0 {
		o.Interval = 0
	}
}

// Hop is the accumulated result for one TTL.
type Hop struct {
	TTL  int
	Addr string         // the responder that named this hop ("" when all probes were lost)
	RTTs []int          // one entry per probe, -1 for a lost probe
	Kind icmp.TraceKind // the most informative reply seen here
}

// Terminal reports whether the trace ends at this hop: the destination echoed
// back, or something reported it unreachable.
func (h Hop) Terminal() bool {
	return h.Kind == icmp.TargetReply || h.Kind == icmp.Unreachable
}

// Sent is the number of probes fired at this hop.
func (h Hop) Sent() int { return len(h.RTTs) }

// Recv is the number of probes that came back.
func (h Hop) Recv() int {
	n := 0
	for _, r := range h.RTTs {
		if r >= 0 {
			n++
		}
	}
	return n
}

// Loss is the loss percentage for this hop, rounded down. A hop with no probes
// is counted as fully lost.
func (h Hop) Loss() int {
	if len(h.RTTs) == 0 {
		return 100
	}
	return 100 * (len(h.RTTs) - h.Recv()) / len(h.RTTs)
}

// Min is the fastest reply at this hop, or -1 when all probes were lost.
func (h Hop) Min() int {
	m := -1
	for _, r := range h.RTTs {
		if r < 0 {
			continue
		}
		if m < 0 || r < m {
			m = r
		}
	}
	return m
}

// Max is the slowest reply at this hop, or -1 when all probes were lost.
func (h Hop) Max() int {
	m := -1
	for _, r := range h.RTTs {
		if r > m {
			m = r
		}
	}
	return m
}

// Avg is the mean reply time at this hop (rounded to the nearest millisecond),
// or -1 when all probes were lost.
func (h Hop) Avg() int {
	sum, n := 0, 0
	for _, r := range h.RTTs {
		if r < 0 {
			continue
		}
		sum += r
		n++
	}
	if n == 0 {
		return -1
	}
	return int(math.Round(float64(sum) / float64(n)))
}

// Result is a finished trace.
type Result struct {
	Target      string
	Hops        []Hop
	Reached     bool // the target answered with an echo reply
	Unreachable bool // a destination-unreachable ended the trace
}

// Walk probes hop by hop, sending Probes probes at each TTL. It stops when the
// destination answers, when a hop reports the path unreachable, when MaxHops is
// spent, or when ctx is cancelled. onHop, when non-nil, is called with each
// completed hop so a live view can redraw; it must not block indefinitely.
//
// The returned error is the probe's own: in practice "this build cannot open a
// raw socket", which the caller turns into a root/privilege message. Partial
// hops gathered before that point are still returned.
func Walk(ctx context.Context, target string, opts Options, probe ProbeFunc, onHop func(Hop)) (Result, error) {
	opts.Defaults()
	res := Result{Target: target}
	if probe == nil {
		probe = icmp.TraceProbe
	}
	for ttl := 1; ttl <= opts.MaxHops; ttl++ {
		hop := Hop{TTL: ttl}
		for i := 0; i < opts.Probes; i++ {
			if ctx.Err() != nil {
				break
			}
			rtt, reply, err := probe(ctx, target, ttl, opts.Timeout)
			if err != nil {
				return res, err
			}
			hop.RTTs = append(hop.RTTs, rtt)
			if hop.Addr == "" && reply.Addr != "" {
				hop.Addr = reply.Addr
			}
			if reply.Kind != icmp.NoReply {
				hop.Kind = reply.Kind
			}
			if i < opts.Probes-1 && opts.Interval > 0 && !sleepCtx(ctx, opts.Interval) {
				break
			}
		}
		if len(hop.RTTs) > 0 {
			res.Hops = append(res.Hops, hop)
			if onHop != nil {
				onHop(hop)
			}
		}
		if hop.Terminal() {
			res.Reached = hop.Kind == icmp.TargetReply
			res.Unreachable = hop.Kind == icmp.Unreachable
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	return res, nil
}

// sleepCtx waits for d, returning false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
