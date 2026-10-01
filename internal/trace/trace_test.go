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

package trace

import (
	"context"
	"errors"
	"testing"
	"time"

	"gnulte-go/internal/icmp"
)

// reply is a one-line TraceReply constructor for the scripts below.
func reply(kind icmp.TraceKind, addr string) icmp.TraceReply {
	return icmp.TraceReply{Kind: kind, Addr: addr}
}

// scriptProbe returns a ProbeFunc that plays back the replies keyed by TTL. A
// TTL with no script is a silent probe.
func scriptProbe(byTTL map[int][]struct {
	rtt int
	rep icmp.TraceReply
	err error
}) ProbeFunc {
	idx := map[int]int{}
	return func(ctx context.Context, ip string, ttl int, timeout time.Duration) (int, icmp.TraceReply, error) {
		seq := byTTL[ttl]
		if idx[ttl] >= len(seq) {
			return -1, reply(icmp.NoReply, ""), nil
		}
		r := seq[idx[ttl]]
		idx[ttl]++
		return r.rtt, r.rep, r.err
	}
}

func TestWalkStopsAtTheTarget(t *testing.T) {
	script := map[int][]struct {
		rtt int
		rep icmp.TraceReply
		err error
	}{
		1: {{5, reply(icmp.HopReply, "10.0.0.1"), nil}, {7, reply(icmp.HopReply, "10.0.0.1"), nil}},
		2: {{10, reply(icmp.HopReply, "10.0.0.2"), nil}, {12, reply(icmp.HopReply, "10.0.0.2"), nil}},
		3: {{20, reply(icmp.TargetReply, "203.0.113.5"), nil}, {22, reply(icmp.TargetReply, "203.0.113.5"), nil}},
	}
	opts := Options{MaxHops: 10, Probes: 2}
	var seen []Hop
	res, err := Walk(context.Background(), "203.0.113.5", opts, scriptProbe(script), func(h Hop) {
		seen = append(seen, h)
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Hops) != 3 {
		t.Fatalf("got %d hops, want 3 (must stop at the target): %+v", len(res.Hops), res.Hops)
	}
	if !res.Reached || res.Unreachable {
		t.Fatalf("Reached=%v Unreachable=%v, want true/false", res.Reached, res.Unreachable)
	}
	if len(seen) != 3 {
		t.Fatalf("onHop called %d times, want 3", len(seen))
	}
	h1 := res.Hops[0]
	if h1.Addr != "10.0.0.1" || h1.Min() != 5 || h1.Max() != 7 || h1.Avg() != 6 || h1.Loss() != 0 {
		t.Fatalf("hop 1 stats wrong: %+v min=%d max=%d avg=%d loss=%d", h1, h1.Min(), h1.Max(), h1.Avg(), h1.Loss())
	}
	last := res.Hops[2]
	if !last.Terminal() || last.Kind != icmp.TargetReply {
		t.Fatalf("last hop = %+v, want a terminal TargetReply", last)
	}
}

func TestWalkCountsLossAndSkipsSilentHopsIntoStats(t *testing.T) {
	script := map[int][]struct {
		rtt int
		rep icmp.TraceReply
		err error
	}{
		1: {{-1, reply(icmp.NoReply, ""), nil}, {-1, reply(icmp.NoReply, ""), nil}},
		2: {{30, reply(icmp.TargetReply, "203.0.113.5"), nil}, {-1, reply(icmp.NoReply, ""), nil}},
	}
	res, err := Walk(context.Background(), "203.0.113.5", Options{MaxHops: 5, Probes: 2}, scriptProbe(script), nil)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Hops) != 2 || !res.Reached {
		t.Fatalf("got %+v, want two hops ending in a reply", res)
	}
	if h := res.Hops[0]; h.Loss() != 100 || h.Min() != -1 || h.Max() != -1 || h.Avg() != -1 {
		t.Fatalf("silent hop = %+v, want full loss and no timings", h)
	}
	if h := res.Hops[1]; h.Loss() != 50 || h.Min() != 30 || h.Avg() != 30 {
		t.Fatalf("half-lost hop = %+v, want 50%% loss over one sample", h)
	}
}

func TestWalkStopsAtUnreachable(t *testing.T) {
	script := map[int][]struct {
		rtt int
		rep icmp.TraceReply
		err error
	}{
		1: {{4, reply(icmp.HopReply, "10.0.0.1"), nil}},
		2: {{9, reply(icmp.Unreachable, "192.0.2.1"), nil}},
	}
	res, err := Walk(context.Background(), "203.0.113.5", Options{MaxHops: 30, Probes: 1}, scriptProbe(script), nil)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Hops) != 2 {
		t.Fatalf("got %d hops, want 2 (unreachable must end the trace)", len(res.Hops))
	}
	if res.Reached || !res.Unreachable {
		t.Fatalf("Reached=%v Unreachable=%v, want false/true", res.Reached, res.Unreachable)
	}
}

func TestWalkHonoursMaxHops(t *testing.T) {
	script := map[int][]struct {
		rtt int
		rep icmp.TraceReply
		err error
	}{}
	// No script: every probe is silent, so only the hop limit can stop it.
	res, err := Walk(context.Background(), "203.0.113.5", Options{MaxHops: 4, Probes: 1}, scriptProbe(script), nil)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Hops) != 4 {
		t.Fatalf("got %d hops, want 4", len(res.Hops))
	}
	if res.Reached || res.Unreachable {
		t.Fatalf("a silent walk must not claim success: %+v", res)
	}
}

// TestWalkReturnsProbeError: when the raw socket cannot be opened at all, the
// error has to reach the caller so it can print a root/privilege message.
func TestWalkReturnsProbeError(t *testing.T) {
	boom := errors.New("operation not permitted")
	probe := func(ctx context.Context, ip string, ttl int, timeout time.Duration) (int, icmp.TraceReply, error) {
		return -1, icmp.TraceReply{}, boom
	}
	res, err := Walk(context.Background(), "203.0.113.5", Options{MaxHops: 3, Probes: 1}, probe, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if len(res.Hops) != 0 {
		t.Fatalf("a probe that never ran must leave no hops, got %+v", res.Hops)
	}
}

func TestWalkStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	probe := func(context.Context, string, int, time.Duration) (int, icmp.TraceReply, error) {
		called = true
		return -1, icmp.TraceReply{}, nil
	}
	res, err := Walk(ctx, "203.0.113.5", Options{MaxHops: 3, Probes: 1}, probe, nil)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if called {
		t.Fatal("a cancelled walk must not fire probes")
	}
	if len(res.Hops) != 0 {
		t.Fatalf("cancelled walk produced hops: %+v", res.Hops)
	}
}

func TestOptionsDefaults(t *testing.T) {
	var o Options
	o.Defaults()
	if o.MaxHops != 30 || o.Probes != 3 || o.Timeout != time.Second || o.Interval != 0 {
		t.Fatalf("Defaults = %+v", o)
	}
	// Explicit values are preserved.
	o = Options{MaxHops: 8, Probes: 1, Timeout: 2 * time.Second, Interval: 5 * time.Millisecond}
	o.Defaults()
	if o.MaxHops != 8 || o.Probes != 1 || o.Timeout != 2*time.Second || o.Interval != 5*time.Millisecond {
		t.Fatalf("Defaults clobbered explicit values: %+v", o)
	}
}

func TestHopStatsWithNoSamples(t *testing.T) {
	h := Hop{TTL: 9}
	if h.Sent() != 0 || h.Recv() != 0 || h.Loss() != 100 || h.Min() != -1 || h.Max() != -1 || h.Avg() != -1 {
		t.Fatalf("empty hop stats = %+v", h)
	}
	if h.Terminal() {
		t.Fatal("a hop with no reply must not be terminal")
	}
}
