//go:build linux

package tui

import (
	"syscall"
	"unsafe"
)

// armRawForTest switches a terminal to the non-canonical, no-echo input mode
// that gnulte's dashboard uses for its arrow-key reader, and hands back the
// restore. Off Linux there is no tcsetattr path, so the caller skips the check.
func armRawForTest(fd int) (restore func(), ok bool) {
	return rawTerminal(fd)
}

// rawLflag reads the terminal's lflag word, so a test can assert that
// ICANON|ECHO are back after an interrupt. Returned as a plain int to keep the
// portable test file free of syscall details.
func rawLflag(fd int) (int, bool) {
	var t syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS,
		uintptr(unsafe.Pointer(&t)), 0, 0, 0); errno != 0 {
		return 0, false
	}
	return int(t.Lflag), true
}
