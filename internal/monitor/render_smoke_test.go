package monitor

import (
	"context"
	"testing"
	"time"
)

// TestRunSingleRenders exercises the single-target console log against the
// loopback so the output format stays inspectable.
func TestRunSingleRenders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(3400 * time.Millisecond)
		cancel()
	}()
	m := &Monitor{
		Targets:    []string{"127.0.0.1"},
		Interval:   300 * time.Millisecond,
		Timeout:    time.Second,
		Sound:      false,
		Iface:      "lo",
		Impairment: "latency 1500ms · jitter 300ms · loss 2%",
	}
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(m.Results) != 1 {
		t.Fatalf("expected one result, got %d", len(m.Results))
	}
	if m.Results[0].Stats.Count == 0 {
		t.Log("warning: no replies recorded")
	}
}
