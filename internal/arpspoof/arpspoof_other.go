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

//go:build !linux

package arpspoof

import (
	"errors"
	"net"
)

var errOther = errors.New("in-Go ARP needs Linux (AF_PACKET); run without --stealth, or use Linux for raw sockets")

// Spoofer is an inert stub off Linux: stealth mode degrades loudly rather
// than silently pretending to work.
type Spoofer struct{}

func Open(iface string) (*Spoofer, error) { return nil, errOther }

// localMAC backs LocalMAC/IsLocal off Linux. There is no socket, so no address
// of our own exists to report.
func (sp *Spoofer) localMAC() net.HardwareAddr { return nil }

// localIP backs LocalIP off Linux, for the same reason.
func (sp *Spoofer) localIP() net.IP { return nil }

func (sp *Spoofer) SendReply(toMAC net.HardwareAddr, toIP, claimedIP net.IP) error {
	return errOther
}

func (sp *Spoofer) SendRaw(frame []byte) error {
	return errOther
}

func (sp *Spoofer) ReadRequest() (net.HardwareAddr, net.IP, net.IP, bool, error) {
	return nil, nil, nil, false, errOther
}

func (sp *Spoofer) ReadReply() (net.HardwareAddr, net.IP, net.IP, bool, error) {
	return nil, nil, nil, false, errOther
}

func (sp *Spoofer) Close() error { return nil }
