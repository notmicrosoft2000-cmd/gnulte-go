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
	"errors"
	"os"
	"sync"

	"gnulte-go/internal/ux"
)

// ErrNotTerminal is returned by Open when stdin or stdout is not a live
// terminal, so the caller can fall back to plain interactive prompts.
var ErrNotTerminal = errors.New("a real terminal is required")

// One input decoder is shared by every screen in the process. A single read
// can collect several keys, so keeping the stream alive means a key typed just
// as one screen closes is still there when the next one opens. The two simple
// menus in gnulte open back to back. Screens are opened one at a time.
var sharedKeys = newKeyStream(int(os.Stdin.Fd()))

// FlushPending drops any partially decoded key press in the shared stream so
// a menu cannot hand a stray arrow byte to the next screen or child process.
// Platforms without a raw key stream simply have nothing to flush.
func FlushPending() {
	if flusher, ok := any(sharedKeys).(interface{ flushPending() }); ok {
		flusher.flushPending()
	}
}

// Screen is a raw-mode, full-screen terminal for one interactive editor. It
// enters the alternate buffer, switches stdin to non-canonical input, and
// guarantees the terminal is restored on Close or on any signal.
type Screen struct {
	fd      int
	restore func()
	leave   func()
	keys    *keyStream

	// mu guards leave/restore: Close is reachable from the main goroutine
	// and from the signal-cleanup goroutine at the same time. Running the
	// restore callbacks twice would drop a stray alternate-buffer switch into
	// whatever stdout is writing next (commonly the end-of-run report).
	mu sync.Mutex
}

// Open prepares a full-screen interactive editor. It requires a live terminal;
// tools should degrade to their classic prompt flow when this fails.
func Open() (*Screen, error) {
	if !StdinTTY() || !ux.TTY() {
		return nil, ErrNotTerminal
	}
	s := &Screen{fd: int(os.Stdin.Fd())}
	restore, ok := rawTerminal(s.fd)
	if !ok {
		return nil, errors.New("could not switch the terminal to raw input")
	}
	s.restore = restore
	s.keys = sharedKeys
	if leave, ok := EnterView(); ok {
		s.leave = leave
	}
	RegisterCleanup(s.Close)
	return s, nil
}

// Close restores the primary buffer and the original line settings exactly
// once. It is safe to call from the registered signal cleanups and from the
// caller's own defer at the same time.
func (s *Screen) Close() {
	s.mu.Lock()
	leave := s.leave
	s.leave = nil
	restore := s.restore
	s.restore = nil
	s.mu.Unlock()
	if leave != nil {
		leave()
	}
	if restore != nil {
		restore()
	}
}

// Draw repaints the whole editor frame in one flush (no flicker).
func (s *Screen) Draw(lines []string) {
	DrawFrame(os.Stdout, ux.Width(), lines)
}

// Key blocks until a single key press is decoded.
func (s *Screen) Key() (Key, rune) { return s.keys.read() }

// Poll waits up to maxWaitMs for a key press and returns KeyNone on timeout.
// Tick-driven dashboards use it so arrows and toggles can be handled without a
// dedicated input goroutine.
func (s *Screen) Poll(maxWaitMs int64) (Key, rune) { return s.keys.poll(maxWaitMs) }
