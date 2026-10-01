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

package icmp

import (
	"context"
	"errors"
	"time"
)

// errOther is the honest answer off Linux: raw ICMP needs AF_INET raw sockets,
// which this build does not open. Callers treat a non-nil error as "cannot use
// the in-Go path here" and fall back to the system ping.
var errOther = errors.New("in-Go ICMP requires Linux raw sockets")

// Ping is unavailable off Linux.
func Ping(ctx context.Context, ip string, timeout time.Duration) (int, int, bool, error) {
	return -1, 0, false, errOther
}

// TraceProbe is unavailable off Linux: a traceroute needs the same raw ICMP
// socket, so the caller is told the in-Go path cannot run here.
func TraceProbe(ctx context.Context, ip string, ttl int, timeout time.Duration) (int, TraceReply, error) {
	return -1, TraceReply{Kind: NoReply}, errOther
}
