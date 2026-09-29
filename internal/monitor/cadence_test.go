package monitor

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// silence keeps the live console (which paints straight to os.Stdout) out of
// the test log, so a failure report is readable.
func silence(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	old := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() {
		os.Stdout = old
		devnull.Close()
	})
}

// The reported bug: in single-target mode, when a probe overran the interval,
// the next probe fired immediately instead of waiting its second. A ticker
// starts each sample on schedule, so a slow sample leaves its tick already
// queued and the gap the operator asked for silently disappears.
//
// The loops must read as "sample, show, then wait the full interval" — the
// rest is measured from when the sample lands, never from when it started.
func TestCadenceKeepsIntervalAfterSlowSample(t *testing.T) {
	const (
		interval = 120 * time.Millisecond
		slow     = 300 * time.Millisecond // 2.5x the interval
		// Scheduling slop: a timer never fires early, but a busy box can
		// hand the goroutine back a little late, and the probe itself is
		// allowed to overshoot. Well under the interval being asserted.
		slack = 20 * time.Millisecond
	)

	for _, mode := range []string{"single", "multi"} {
		t.Run(mode, func(t *testing.T) {
			// Per target, not one shared slice: the dashboard runs a
			// goroutine per target, so their samples interleave and a
			// combined list would compare one target's sample against
			// another's and read as a collapsed gap.
			var mu sync.Mutex
			starts := map[string][]time.Time{}
			m := &Monitor{
				Targets:  []string{"192.0.2.1"},
				Interval: interval,
				Quiet:    true,
			}
			if mode == "multi" {
				// Two targets so runMulti takes the dashboard path.
				m.Targets = append(m.Targets, "192.0.2.2")
			}
			m.sampleFn = func(ctx context.Context, ip string) (RTT, string, bool) {
				mu.Lock()
				starts[ip] = append(starts[ip], time.Now())
				mu.Unlock()
				select {
				case <-time.After(slow):
				case <-ctx.Done():
				}
				return 12, "ttl=64", true
			}

			silence(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = m.Run(ctx)

			mu.Lock()
			defer mu.Unlock()
			if len(starts) != len(m.Targets) {
				t.Fatalf("sampled %d target(s), want %d", len(starts), len(m.Targets))
			}
			// The gap has to be the probe time *plus* the interval. A plain
			// "at least the interval" check passes even on the old ticker,
			// because a slow probe's own duration already exceeds it — what
			// the ticker really does is drop the interval entirely, making a
			// 2s probe back-to-back with a 1s cadence.
			min := slow + interval - slack
			for ip, at := range starts {
				if len(at) < 2 {
					t.Errorf("%s: only %d samples in the window; cadence never ran", ip, len(at))
					continue
				}
				for i := 1; i < len(at); i++ {
					gap := at[i].Sub(at[i-1])
					if gap < min {
						t.Errorf("%s: sample %d started %v after the previous one, want >= %v "+
							"(probe %v + interval %v: the wait is being swallowed)",
							ip, i, gap, min, slow, interval)
					}
				}
			}
		})
	}
}

// The gap must be added, not subtracted: a target that never answers costs its
// timeout plus the interval, so the console still shows one reading per
// (timeout + interval) rather than running flat out.
func TestCadenceAddsIntervalToUnresponsiveTarget(t *testing.T) {
	const (
		interval = 80 * time.Millisecond
		never    = 200 * time.Millisecond // the target never answers
		slack    = 20 * time.Millisecond
	)

	var mu sync.Mutex
	var starts []time.Time
	m := &Monitor{
		Targets:  []string{"192.0.2.1"},
		Interval: interval,
		Quiet:    true,
		sampleFn: func(ctx context.Context, ip string) (RTT, string, bool) {
			mu.Lock()
			starts = append(starts, time.Now())
			mu.Unlock()
			select {
			case <-time.After(never):
			case <-ctx.Done():
			}
			return -1, "", false
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	silence(t)
	_ = m.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(starts) < 2 {
		t.Fatalf("only %d samples; the loop exited early", len(starts))
	}
	min := never + interval - slack
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < min {
			t.Errorf("sample %d followed the last by %v, want >= %v "+
				"(the timeout is running straight into the next probe)", i, gap, min)
		}
	}
}

// A first reading should not be held back by the interval: the operator is
// looking at a blank console and the target is already there.
func TestFirstSampleIsImmediate(t *testing.T) {
	first := make(chan time.Time, 1)
	m := &Monitor{
		Targets:  []string{"192.0.2.1"},
		Interval: 30 * time.Second, // far longer than this test may wait
		Quiet:    true,
		sampleFn: func(ctx context.Context, ip string) (RTT, string, bool) {
			select {
			case first <- time.Now():
			default:
			}
			return 7, "ttl=64", true
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	silence(t)
	start := time.Now()
	_ = m.Run(ctx)

	select {
	case at := <-first:
		// A loop that waited an interval before sampling would never get
		// here inside 2s, so this only has to catch the obvious regression.
		if d := at.Sub(start); d > time.Second {
			t.Errorf("first sample taken %v in, want immediately", d)
		}
	default:
		t.Fatal("no sample was taken at all")
	}
}

// waitInterval is the rest half of the cadence: it must wait, and it must give
// up the moment the context is done.
func TestWaitInterval(t *testing.T) {
	start := time.Now()
	if !waitInterval(context.Background(), 60*time.Millisecond) {
		t.Fatal("waitInterval reported a live context as done")
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Errorf("waitInterval returned after %v, want ~60ms", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if waitInterval(ctx, 5*time.Second) {
		t.Error("waitInterval did not report a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waitInterval took %v to notice the cancel", elapsed)
	}

	// A non-positive interval still has to wait rather than spin.
	start = time.Now()
	waitInterval(context.Background(), 0)
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("zero interval returned in %v, want the 1s floor", elapsed)
	}
}
