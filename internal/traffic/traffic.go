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

// Package traffic measures live per-host traffic on an interface. A raw
// AF_PACKET socket (root required) reads every frame and accumulates
// bytes/packets per IPv4 host, so the monitor can show a live down/up counter
// per target — iftop-style — without touching iptables. If the socket cannot
// be opened (not root, unusual interface), the monitor simply runs without
// counters: they are a garnish, not a dependency.
package traffic

// Rate is the traffic a single host moved between two Snapshot calls.
type Rate struct {
	// RXBytes/RXPkts are what the host received (toward it).
	RXBytes int64
	RXPkts  int64
	// TXBytes/TXPkts are what the host sent (away from it).
	TXBytes int64
	TXPkts  int64
}
