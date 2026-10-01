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

package discover

import (
	"context"
	"errors"
	"net"
	"time"
)

// errNoRawARP is the honest answer off Linux: in-Go ARP needs AF_PACKET, so
// there is nothing to fall back to. The ARP sweep degrades to "no extra hosts"
// and MAC resolution falls back to the kernel's own table.
var errNoRawARP = errors.New("in-Go ARP requires Linux (AF_PACKET)")

func runSweep(ctx context.Context, targets []string, iface string, threads int, report func(completed, alive int)) sweepResult {
	return sweepResult{}
}

func sweep(ctx context.Context, targets []string, iface string, threads, rounds int, report func(completed, alive int)) sweepResult {
	return sweepResult{}
}

func resolveOne(ctx context.Context, iface, ip string) (net.HardwareAddr, error) {
	return nil, errNoRawARP
}

func resolveOn(ctx context.Context, iface, ip string, window time.Duration, rounds int) (net.HardwareAddr, error) {
	return nil, errNoRawARP
}
