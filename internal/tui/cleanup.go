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
)

// RegisterCleanup queues a terminal-restore action (leaving the alternate
// buffer, undoing raw mode) that runs when the process is interrupted. The
// first registration installs a SIGINT/SIGTERM handler so a Ctrl+C during a
// full-screen view never leaves the user's terminal stranded.
func RegisterCleanup(f func()) {
	mu.Lock()
	cleanups = append(cleanups, f)
	mu.Unlock()
	sigOnce.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-ch
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
