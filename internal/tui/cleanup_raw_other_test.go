//go:build !linux

package tui

// armRawForTest and rawLflag are Linux-only; elsewhere a test cannot switch or
// inspect the terminal, so the raw-mode part of the interrupt checks is simply
// unavailable and the caller skips it.
func armRawForTest(fd int) (restore func(), ok bool) { return func() {}, false }

func rawLflag(fd int) (int, bool) { return 0, false }
