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

package ux

// SparkRTT renders a latency history as a compact block sparkline: the most
// recent maxWidth samples left-aligned (so the history grows rightward), each
// RTT mapped to one of eight height levels, with a middle dot for dropped
// pings. Values over 512ms saturate at the full block. This is the shared
// "history of every ping" glyph used by the live dashboard and the per-target
// traffic windows.
func SparkRTT(samples []int, maxWidth int) string {
	if maxWidth <= 0 || len(samples) == 0 {
		return ""
	}
	start := 0
	if len(samples) > maxWidth {
		start = len(samples) - maxWidth
	}
	out := make([]rune, 0, len(samples)-start)
	for i := start; i < len(samples); i++ {
		out = append(out, sparkLevel(samples[i]))
	}
	return string(out)
}

func sparkLevel(v int) rune {
	switch {
	case v < 0:
		return '·' // drop
	case v < 8:
		return '▁'
	case v < 16:
		return '▂'
	case v < 32:
		return '▃'
	case v < 64:
		return '▄'
	case v < 128:
		return '▅'
	case v < 256:
		return '▆'
	case v < 512:
		return '▇'
	default:
		return '█'
	}
}
