package tui

import (
	"sync/atomic"
	"testing"
	"time"
)

// The registered cleanups are the last line of defence for a terminal that was
// switched to raw input / the alternate buffer. A forced interrupt drains the
// list, and a caller that also defers its own restore will hit it again, so
// each registration has to be a no-op the second time round.
func TestRunCleanupsRunsEachOnce(t *testing.T) {
	var a, b int32
	RegisterCleanup(func() { atomic.AddInt32(&a, 1) })
	RegisterCleanup(func() { atomic.AddInt32(&b, 1) })

	RunCleanups()
	// A second drain must not replay anything: the list is emptied, not re-run.
	RunCleanups()
	RunCleanups()

	if got := atomic.LoadInt32(&a); got != 1 {
		t.Errorf("first cleanup ran %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&b); got != 1 {
		t.Errorf("second cleanup ran %d times, want 1", got)
	}
}

// A cleanup registered after a drain still has to run — the list is emptied on
// every drain, so a dashboard started later gets its own restore.
func TestRunCleanupsAfterDrain(t *testing.T) {
	var n int32
	RegisterCleanup(func() { atomic.AddInt32(&n, 1) })
	RunCleanups()
	RegisterCleanup(func() { atomic.AddInt32(&n, 10) })
	RunCleanups()
	if got := atomic.LoadInt32(&n); got != 11 {
		t.Errorf("late cleanup did not run exactly once: got %d, want 11", got)
	}
}

// A nil cleanup is ignored rather than queued: RunCleanups has to be safe to
// call from a signal handler, where a nil call would panic at the worst moment.
func TestRegisterCleanupNil(t *testing.T) {
	RegisterCleanup(nil)
	RunCleanups()
}

// exitGrace is the window the tool's own graceful shutdown gets. It has to
// outlast a slow state restore, otherwise the safety net would cut short the
// very shutdown it is meant to back up — the bug that made Ctrl+C in the
// multi-target dashboard skip the teardown and kill the process outright.
func TestExitGraceCoversSlowRestore(t *testing.T) {
	if exitGrace < 5*time.Second {
		t.Errorf("exitGrace = %s, too short to let a restore finish", exitGrace)
	}
}
