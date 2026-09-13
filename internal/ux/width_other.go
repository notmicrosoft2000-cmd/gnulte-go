//go:build !linux

package ux

// Width falls back to 80 columns when ioctl is unavailable.
func Width() int { return 80 }
