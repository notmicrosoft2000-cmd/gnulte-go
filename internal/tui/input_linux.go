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

//go:build linux

package tui

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

// rawTerminal puts the given fd (stdin) into non-canonical, no-echo mode and
// returns a function that restores the original line settings. ok is false
// when the fd cannot be switched (pipe, file, non-Linux).
func rawTerminal(fd int) (restore func(), ok bool) {
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS,
		uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return nil, false
	}
	raw := old
	raw.Iflag &^= syscall.ICRNL | syscall.IXON | syscall.ISTRIP
	raw.Lflag &^= syscall.ICANON | syscall.ECHO
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS,
		uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		return nil, false
	}
	return func() {
		_, _, _ = syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS,
			uintptr(unsafe.Pointer(&old)), 0, 0, 0)
	}, true
}

// keyStream decodes one key press at a time from fd without ever dropping the
// bytes of a queued key sequence. Kept as a struct so partial input (an Escape
// that is about to become an arrow) plus any following keys survive across
// calls — dropping a lone queued arrow was an early flicker in the editor.
type keyStream struct {
	fd      int
	pending []byte
}

func newKeyStream(fd int) *keyStream { return &keyStream{fd: fd} }

// read blocks until a full key press is decoded. A leading ESC is given a short
// grace window so a lone Escape does not wait on an absent arrow sequence.
// ISIG stays enabled, so Ctrl+C still interrupts the process.
func (k *keyStream) read() (Key, rune) {
	buf := make([]byte, 16)
	for {
		// Always start from a filled buffer: parse before reading meant an
		// empty buffer busy-spun on the nothing-more path.
		for len(k.pending) == 0 {
			if nr := readChunk(k.fd, buf, 500); nr > 0 {
				k.pending = append(k.pending, buf[:nr]...)
			}
		}
		key, rn, n, more := parseKey(k.pending)
		if n > 0 {
			k.pending = k.pending[n:]
		} else if !more {
			k.pending = nil
		}
		if key != KeyNone {
			return key, rn
		}
		if !more {
			continue // dropped an ignored control byte; keep reading
		}
		// ESC is waiting to grow into an arrow: give it one beat.
		nr := readChunk(k.fd, buf, 40)
		if nr <= 0 {
			// Nothing arrived: a lone ESC; if the sequence was already
			// malformed ([ ESC), drop it and try again.
			if len(k.pending) == 1 {
				k.pending = nil
				return KeyEsc, 0
			}
			k.pending = nil
			continue
		}
		k.pending = append(k.pending, buf[:nr]...)
	}
}

// poll waits up to maxWaitMs for a full key press and returns KeyNone on
// timeout, so a tick-driven dashboard can fold key handling into its loop
// without ever blocking it. Decoding is identical to read — queued arrow
// sequences are still consumed atomically and a lone ESC is resolved after its
// short grace beat (bounded by the caller's deadline).
func (k *keyStream) poll(maxWaitMs int64) (Key, rune) {
	buf := make([]byte, 16)
	deadline := time.Now().Add(time.Duration(maxWaitMs) * time.Millisecond)
	for {
		for len(k.pending) == 0 {
			rem := time.Until(deadline).Milliseconds()
			if rem <= 0 {
				return KeyNone, 0
			}
			if nr := readChunk(k.fd, buf, rem); nr > 0 {
				k.pending = append(k.pending, buf[:nr]...)
			} else {
				return KeyNone, 0
			}
		}
		key, rn, n, more := parseKey(k.pending)
		if n > 0 {
			k.pending = k.pending[n:]
		} else if !more {
			k.pending = nil
		}
		if key != KeyNone {
			return key, rn
		}
		if !more {
			continue // dropped an ignored control byte; keep draining
		}
		// ESC is waiting to grow into an arrow: one short beat, bounded by
		// the caller's deadline so a lone Escape never stalls the loop.
		wait := int64(40)
		if rem := time.Until(deadline).Milliseconds(); rem < wait {
			wait = rem
			if wait < 1 {
				k.pending = nil
				return KeyEsc, 0
			}
		}
		if nr := readChunk(k.fd, buf, wait); nr > 0 {
			k.pending = append(k.pending, buf[:nr]...)
		} else {
			k.pending = nil
			return KeyEsc, 0
		}
	}
}

// readChunk waits up to timeoutMs for input on fd and returns however many
// bytes arrived (0 on timeout).
func readChunk(fd int, buf []byte, timeoutMs int64) int {
	var rset syscall.FdSet
	el := int(unsafe.Sizeof(rset.Bits[0])) * 8
	rset.Bits[fd/el] |= 1 << uint(fd%el)
	tv := syscall.NsecToTimeval(timeoutMs * 1_000_000)
	n, err := syscall.Select(fd+1, &rset, nil, nil, &tv)
	if err != nil {
		return 0
	}
	if n == 0 {
		return 0
	}
	nr, _ := syscall.Read(fd, buf)
	return nr
}

// StdinTTY reports whether stdin is a real terminal (needed for the editor).
func StdinTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
