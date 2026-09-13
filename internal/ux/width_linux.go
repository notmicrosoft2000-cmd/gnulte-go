//go:build linux

package ux

import (
	"os"
	"syscall"
	"unsafe"
)

var winsize = syscall.TIOCGWINSZ

// Width returns the current terminal width in columns, or 80 when the output
// is not a live terminal (so piped runs never panic on a missing size).
func Width() int {
	if !tty {
		return 80
	}
	var ws struct{ Row, Col, Xpix, Ypix uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(os.Stdout.Fd()), uintptr(winsize), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Col == 0 {
		return 80
	}
	return int(ws.Col)
}
