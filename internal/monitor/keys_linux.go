// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.
//
// This file is Linux-specific. It toggles the terminal to non-canonical input
// (raw bytes, no echo) and watches for arrow keys so the multi-target monitor
// can pick which host the beeps follow.

package monitor

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// enableKeyboard puts stdin into raw input mode and starts a reader that moves
// *sel with the up/down arrows (and the vim-style j/k) within the target list.
// The returned function restores the terminal and stops the reader; active
// reports whether the terminal was actually switched, so callers can also
// register the restore as a last-resort cleanup. When the terminal cannot be
// switched (piped stdin), the reader forces the selection to target 0 and a
// no-op restore is returned.
func enableKeyboard(targets int, sel *int32) (restore func(), active bool) {
	if targets <= 1 {
		return func() {}, false
	}
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS,
		uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return func() {}, false
	}
	raw := old
	raw.Iflag &^= syscall.ICRNL | syscall.IXON | syscall.ISTRIP
	raw.Lflag &^= syscall.ICANON | syscall.ECHO
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS,
		uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		return func() {}, false
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go keyReader(ctx, fd, sel, targets, done)

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
			_, _, _ = syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS,
				uintptr(unsafe.Pointer(&old)), 0, 0, 0)
		})
	}, true
}

// keyReader polls stdin and translates the up/down arrows (ESC [ A/B) plus the
// j/k keys into selection moves until the context is cancelled.
func keyReader(ctx context.Context, fd int, sel *int32, n int, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 16)
	pending := make([]byte, 0, 16)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var rset syscall.FdSet
		setFD(fd, &rset)
		tv := syscall.NsecToTimeval(100_000 * 1000)
		nfd, err := syscall.Select(fd+1, &rset, nil, nil, &tv)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		if nfd == 0 {
			continue
		}
		nr, err := syscall.Read(fd, buf)
		if err != nil || nr <= 0 {
			return
		}
		pending = append(pending, buf[:nr]...)
		for len(pending) > 0 {
			b := pending[0]
			switch {
			case b == 0x1b:
				if len(pending) < 2 {
					break
				}
				if pending[1] == '[' {
					if len(pending) < 3 {
						break
					}
					switch pending[2] {
					case 'A':
						moveSel(sel, n, -1)
					case 'B':
						moveSel(sel, n, +1)
					}
					pending = pending[3:]
				} else if len(pending) == 1 {
					break
				} else {
					pending = pending[1:]
				}
			case b == 'k':
				moveSel(sel, n, -1)
				pending = pending[1:]
			case b == 'j':
				moveSel(sel, n, +1)
				pending = pending[1:]
			default:
				pending = pending[1:]
			}
		}
	}
}

// setFD sets bit fd in a poll set, portable across FdSet implementations.
func setFD(fd int, set *syscall.FdSet) {
	el := int(unsafe.Sizeof(set.Bits[0])) * 8
	w := fd / el
	set.Bits[w] |= 1 << uint(fd%el)
}

func moveSel(sel *int32, n, d int) {
	if n <= 1 {
		return
	}
	v := int(atomic.LoadInt32(sel)) + d
	v %= n
	if v < 0 {
		v += n
	}
	atomic.StoreInt32(sel, int32(v))
}
