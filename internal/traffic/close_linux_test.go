// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package traffic

import (
	"sync"
	"testing"
)

// Close must be safe from any number of concurrent callers, and safe to call
// more than once: gnulte-lan registers counter.Close as a signal cleanup AND
// defers the same method, so a single Ctrl+C can reach it from both the tui
// goroutine and the main loop. The old check-then-act select could pass from
// two goroutines and then panic with "close of closed channel" (and close the
// fd twice, potentially freeing an unrelated descriptor). The loop volume
// below is what makes that reliably reproducible against the old code.
func TestCounterCloseIsIdempotentUnderConcurrency(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		c := &Counter{fd: -1, closed: make(chan struct{})} // -1: no real fd to close
		var wg sync.WaitGroup
		for g := 0; g < 32; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.Close()
			}()
		}
		wg.Wait()
		c.Close() // and a late sequential call
		select {
		case <-c.closed:
		default:
			t.Fatalf("iteration %d: Close never closed the closed channel", iter)
		}
	}
}
