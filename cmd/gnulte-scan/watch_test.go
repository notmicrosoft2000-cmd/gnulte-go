package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recordingStep returns a step that takes `cost` and records the time it
// finished, under mu so a -race run is clean.
func recordingStep(cost time.Duration, finished *[]time.Time, mu *sync.Mutex) func() {
	return func() {
		time.Sleep(cost)
		mu.Lock()
		*finished = append(*finished, time.Now())
		mu.Unlock()
	}
}

// The cadence bug this guards: a sweep that costs more than the interval used
// to collapse the wait entirely (ticker had its tick already queued), so the
// gap between sweep completions equalled the sweep cost alone. Sampling, then
// waiting a full interval, guarantees a completion gap of at least
// cost + interval.
func TestWatchLoopHonoursIntervalAfterSlowSweep(t *testing.T) {
	const (
		cost     = 60 * time.Millisecond
		interval = 60 * time.Millisecond
		slack    = 15 * time.Millisecond
	)
	var mu sync.Mutex
	var done []time.Time
	// A bounded context ends the loop; cancel is deferred, so the timeout —
	// not the cancel — is what stops watchLoop here.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	watchLoop(ctx, interval, recordingStep(cost, &done, &mu))

	mu.Lock()
	gaps := make([]time.Duration, 0, len(done))
	for i := 1; i < len(done); i++ {
		gaps = append(gaps, done[i].Sub(done[i-1]))
	}
	mu.Unlock()
	if len(gaps) < 2 {
		t.Fatalf("want at least 3 completed sweeps, got %d", len(gaps))
	}
	for i, g := range gaps {
		if g < cost+interval-slack {
			t.Errorf("gap %d = %s, want >= cost+interval-slack = %s", i, g, cost+interval-slack)
		}
	}
}

// The first sweep must be immediate, not a silent dead interval after start
// (this is what an operator watches for: movement should show up right away).
func TestWatchLoopFirstSweepIsImmediate(t *testing.T) {
	var mu sync.Mutex
	var first time.Time
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	watchLoop(ctx, 60*time.Second, func() {
		mu.Lock()
		if first.IsZero() {
			first = time.Now()
		}
		mu.Unlock()
	})
	mu.Lock()
	elapsed := first.Sub(start)
	mu.Unlock()
	// interval 60s, but a 2s ctx — the first step must still have run.
	if elapsed > 500*time.Millisecond {
		t.Errorf("first sweep took %s to start; it should run immediately", elapsed)
	}
}

// Cancelling mid-wait must return promptly, not after a full interval.
func TestWatchLoopStopsOnCancel(t *testing.T) {
	var mu sync.Mutex
	steps := 0
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	watchLoop(ctx, 30*time.Second, func() { // 30s interval: only a cancel can end this
		mu.Lock()
		steps++
		mu.Unlock()
	})
	elapsed := time.Since(start)
	mu.Lock()
	n := steps
	mu.Unlock()
	if n != 1 {
		t.Errorf("want exactly 1 sweep before cancel, got %d", n)
	}
	if elapsed > 5*time.Second {
		t.Errorf("watchLoop took %s to notice cancel; should return immediately", elapsed)
	}
}
