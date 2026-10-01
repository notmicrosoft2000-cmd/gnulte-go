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

//go:build linux

package icmp

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPingLoopbackLive exercises the raw-socket path end to end. It needs root
// (raw ICMP sockets are privileged), so it skips in the sandbox and runs on a
// root box — the same environment the engine runs in.
func TestPingLoopbackLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP needs root; run this on a root box")
	}
	rtt, ttl, ok, err := Ping(context.Background(), "127.0.0.1", time.Second)
	if err != nil {
		t.Fatalf("Ping(loopback) returned an error: %v", err)
	}
	if !ok {
		t.Fatal("Ping(loopback) got no reply from the loopback address")
	}
	if rtt < 0 {
		t.Fatalf("rtt = %d, want >= 0", rtt)
	}
	if ttl == 0 {
		t.Error("loopback reply carried no TTL")
	}
}

// TestPingSilentAddressLive checks the honest failure on the raw path: an
// address that does not answer returns ok=false and a nil error, so a caller
// does not mistake "no reply" for "cannot probe here" and shell out.
func TestPingSilentAddressLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP needs root; run this on a root box")
	}
	// 192.0.2.0/24 is TEST-NET-1: reserved and never routed, the standard
	// black hole for exactly this kind of check.
	_, _, ok, err := Ping(context.Background(), "192.0.2.1", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("Ping(black hole) errored instead of reporting silence: %v", err)
	}
	if ok {
		t.Fatal("Ping(black hole) claimed a reply from an unrouted address")
	}
}

// TestPingRejectsNonIPv4 checks the guard before any socket is opened: a host
// name or an IPv6 literal must not produce a malformed request.
func TestPingRejectsNonIPv4(t *testing.T) {
	if _, _, _, err := Ping(context.Background(), "::1", time.Second); err == nil {
		t.Fatal("Ping accepted an IPv6 address")
	}
	if _, _, _, err := Ping(context.Background(), "not-an-ip", time.Second); err == nil {
		t.Fatal("Ping accepted a non-address")
	}
}
