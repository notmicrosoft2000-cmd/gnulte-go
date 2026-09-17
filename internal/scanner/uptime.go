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

package scanner

import (
	"fmt"
	"time"
)

// formatUptime renders a seconds count as a compact human duration.
func formatUptime(sec int) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d/(24*time.Hour)), int(d/time.Hour)%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d/time.Hour), int(d/time.Minute)%60)
	default:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
}

// uptimeProbe estimates a host's uptime from TCP timestamp deltas. It requires
// raw sockets (root/CAP_NET_RAW) and an open port; every failure degrades to 0
// so the scan never breaks because this extra could not run.
func uptimeProbe(ip string, port int) int {
	return rawUptime(ip, port)
}