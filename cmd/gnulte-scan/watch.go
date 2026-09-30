// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"context"
	"time"
)

// watchLoop runs repeated sweeps at the operator's requested cadence:
// sweep, show, then wait a full interval.
//
// A fixed ticker starts each sweep on schedule, so a sweep slower than the
// interval leaves its tick already queued and the gap collapses to the
// sweep's own duration — `--watch 1` on a /24 costs the ~11s sweep (and then
// fires immediately again), not 1s + 11s. The wait here is measured from the
// moment a sweep *ends*, so the requested interval is always honoured on top
// of the work.
//
// The first sweep runs immediately (the operator asked to watch; make the
// first result timely), matching the monitor's cadence in v16. Reports false
// once ctx is done; a nil step or a non-positive interval is a no-op.
func watchLoop(ctx context.Context, d time.Duration, step func()) bool {
	if step == nil {
		return false
	}
	if d <= 0 {
		d = time.Second
	}
	for {
		if ctx.Err() != nil {
			return false
		}
		step()
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
		}
	}
}
