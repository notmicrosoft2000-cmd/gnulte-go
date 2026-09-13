// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.
//
// This file is Linux-specific: it injects raw frames through an AF_PACKET
// socket, which is how a monitor-mode wireless adapter is driven from user
// space without libpcap.

package deauth

import (
	"fmt"
	"net"
	"syscall"
)

// Injector sends raw 802.11 frames on a monitor-mode interface.
type Injector struct {
	fd      int
	iface   string
	ifindex int
}

// NewInjector opens an AF_PACKET raw socket bound to interface iface. The
// interface must exist, be up, and be in monitor mode (see MonitorMode); the
// process needs root. The socket is left unbound from any specific protocol so
// each Send supplies the destination.
func NewInjector(iface string) (*Injector, error) {
	nif, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	if nif.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %s is down (bring it up before injecting)", iface)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	return &Injector{fd: fd, iface: iface, ifindex: nif.Index}, nil
}

// Send transmits one complete radiotap + 802.11 frame. On a monitor adapter
// the device itself appends the FCS, so no checksum is required.
func (in *Injector) Send(frame []byte) error {
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  in.ifindex,
		Halen:    0, // full 802.11 frame is passed through as-is
	}
	if err := syscall.Sendto(in.fd, frame, 0, sll); err != nil {
		return fmt.Errorf("inject on %s: %w", in.iface, err)
	}
	return nil
}

// Close releases the socket.
func (in *Injector) Close() error {
	return syscall.Close(in.fd)
}

// htons swaps a 16-bit value to network byte order for the socket layers.
func htons(v uint16) uint16 {
	return v<<8&0xff00 | v>>8&0x00ff
}
