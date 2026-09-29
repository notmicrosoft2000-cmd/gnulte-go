package ident

import (
	"context"
	"testing"
	"time"
)

// Every one of these network waits used to derive its bound from
// ctx.Deadline() alone, so a context that was cancelled but carried no
// deadline — exactly what signal.NotifyContext produces — still ran out the
// full fallback. Stacked per host, that made Ctrl+C unresponsive for many
// seconds in a live scan. Cancellation has to end the wait, not just bound it.
func TestWaitsEndOnCancel(t *testing.T) {
	const limit = 300 * time.Millisecond

	cases := []struct {
		name string
		wait func(ctx context.Context)
	}{
		{"Hostname", func(ctx context.Context) {
			Hostname(ctx, "192.0.2.1")
		}},
		{"BrowseMDNS", func(ctx context.Context) {
			BrowseMDNS(ctx, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
		}},
		{"NetBIOSName", func(ctx context.Context) {
			NetBIOSName(ctx, "192.0.2.1")
		}},
		{"ServiceLabels", func(ctx context.Context) {
			ServiceLabels(ctx, []string{"192.0.2.1", "192.0.2.2"})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 192.0.2.0/24 is TEST-NET-1: nothing answers, so every wait would
			// otherwise sit out its whole fallback.
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // already stopped before the call even starts

			start := time.Now()
			tc.wait(ctx)
			if elapsed := time.Since(start); elapsed > limit {
				t.Errorf("%s took %v on a cancelled context, want < %v", tc.name, elapsed, limit)
			}
		})
	}
}

// The same holds when the cancel lands mid-wait rather than before it.
func TestWaitsEndOnMidFlightCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	NetBIOSName(ctx, "192.0.2.1")
	Hostname(ctx, "192.0.2.2")
	ServiceLabels(ctx, []string{"192.0.2.3"})

	// Uncancelled these would cost 800 + (600 + 800) + 2*900 = ~4s.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("mid-flight cancel took %v to take effect", elapsed)
	}
}

// boundUntil is the shared guard: it must never hand back a later instant than
// the context's own deadline, and must refuse outright once the context is
// done.
func TestBoundUntil(t *testing.T) {
	live, cancel := context.WithCancel(context.Background())
	defer cancel()
	limit, ok := boundUntil(live, time.Second)
	if !ok {
		t.Fatal("boundUntil refused a live context")
	}
	if limit.After(time.Now().Add(time.Second + 100*time.Millisecond)) {
		t.Errorf("limit %v is later than the requested bound", limit)
	}

	withDeadline, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if l, ok := boundUntil(withDeadline, 10*time.Second); ok && l.After(time.Now().Add(time.Second)) {
		t.Errorf("limit %v ignored the earlier context deadline", l)
	}

	done, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if _, ok := boundUntil(done, time.Second); ok {
		t.Error("boundUntil accepted an already-cancelled context")
	}
}
