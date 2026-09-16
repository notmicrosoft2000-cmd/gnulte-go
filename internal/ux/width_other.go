//go:build !linux

package ux

// Size falls back to 80x24 when ioctl is unavailable.
func Size() (int, int) { return 80, 24 }

// Width returns a conservative 80 columns for non-Linux builds.
func Width() int { return 80 }

// Height returns a conservative 24 rows for non-Linux builds.
func Height() int { return 24 }
