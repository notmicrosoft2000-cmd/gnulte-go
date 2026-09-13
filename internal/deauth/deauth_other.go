// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.
//
// Non-Linux build: frame crafting and parsing are portable, but raw 802.11
// injection through AF_PACKET is not available here.

//go:build !linux

package deauth

import "fmt"

// Injector is unavailable off Linux.
type Injector struct{}

// NewInjector refuses to construct an injector on non-Linux platforms.
func NewInjector(iface string) (*Injector, error) {
	return nil, fmt.Errorf("%w (interface %s not usable)", errNotLinux, iface)
}

// Send always fails.
func (in *Injector) Send(frame []byte) error {
	return errNotLinux
}

// Close is a no-op.
func (in *Injector) Close() error {
	return nil
}
