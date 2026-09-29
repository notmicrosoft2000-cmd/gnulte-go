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

package tui

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// exitGrace is how long the first interrupt is left to the tool's own graceful
// shutdown (cancel the session, tear the shaping tree down, print the summary)
// before this package ends the process itself. It matches the watchdog gnulte
// arms for the same reason, so the two never disagree about who gives up first.
var exitGrace = 8 * time.Second

// RegisterCleanup queues a terminal-restore action (leaving the alternate
// buffer, undoing raw mode) that runs when the process is interrupted.
//
// The first interrupt only puts the screen back — it does not exit. Every
// GNULTE tool installs its own SIGINT handler (signal.NotifyContext) and the
// first signal reaches it as well, so that is the code that decides how the
// session ends: a monitor returns, the shaping tree is torn down, the summary
// is printed. Exiting here instead would race that shutdown, and in practice
// won, killing the process mid-restore and leaving the terminal in raw mode
// with the network still shaped. This handler is the safety net for the cases
// where the graceful path never finishes: a second interrupt, or a grace period
// that runs out.
func RegisterCleanup(f func()) {
	if f == nil {
		return
	}
	// Each registration runs at most once, so restoring eagerly on the first
	// interrupt cannot double-run an action that the caller also defers.
	var once sync.Once
	wrapped := func() { once.Do(f) }
	mu.Lock()
	cleanups = append(cleanups, wrapped)
	mu.Unlock()
	sigOnce.Do(func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-ch
			RunCleanups()
			select {
			case <-ch:
				// Second interrupt: the shutdown is stuck, and the screen is
				// already sane, so leaving now is the safest option left.
			case <-time.After(exitGrace):
			}
			// Anything registered while the shutdown was in flight (a new
			// dashboard) still has to be undone before the process goes.
			RunCleanups()
			os.Exit(130)
		}()
	})
}

// RunCleanups executes every registered cleanup exactly once. Cleanups may be
// registered again afterwards (a new dashboard session gets fresh state).
func RunCleanups() {
	mu.Lock()
	pending := cleanups
	cleanups = nil
	mu.Unlock()
	for _, f := range pending {
		if f != nil {
			f()
		}
	}
}

var (
	mu       sync.Mutex
	cleanups []func()
	sigOnce  sync.Once
)
