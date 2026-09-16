//go:build linux

package ux

import (
	"os"
	"syscall"
	"unsafe"
)

var winsize = syscall.TIOCGWINSZ

// Size queries the terminal size once and caches it (Width and Height both use
// it), falling back to 80x24 when stdout is not a live terminal.
var Size = func() (w, h int) {
	if !tty {
		return 80, 24
	}
	var ws struct{ Row, Col, Xpix, Ypix uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(os.Stdout.Fd()), uintptr(winsize), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Col == 0 {
		return 80, 24
	}
	rows := int(ws.Row)
	if rows == 0 {
		rows = 24
	}
	return int(ws.Col), rows
}

// Width returns the current terminal width in columns, or 80 when the output
// is not a live terminal (so piped runs never panic on a missing size).
func Width() int {
	w, _ := Size()
	return w
}

// Height returns the current terminal height in rows, or 24 when the output is
// not a live terminal.
func Height() int {
	_, h := Size()
	return h
}
