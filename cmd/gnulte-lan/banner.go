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

package main

import (
	"fmt"
	"strings"

	"gnulte-go/internal/ux"
)

// gnultelanLogo is the GNULTE-LAN wordmark, hand-set in the same six-line
// block style as the GNULTE and SCANLTE logos so the whole toolkit reads the
// same at boot. It fits an 80-column terminal.
const gnultelanLogo = `  ██████╗ ███╗   ██╗ ██╗   ██╗ ██╗      ████████╗ ███████╗          ██╗       █████╗  ███╗   ██╗
  ██╔════╝ ████╗  ██║ ██║   ██║ ██║      ╚══██╔══╝ ██╔════╝          ██║      ██╔══██╗ ████╗  ██║
  ██║  ███╗ ██╔██╗ ██║ ██║   ██║ ██║         ██║    █████╗    ███████╗ ██║      ███████║ ██╔██╗ ██║
  ██║   ██║ ██║╚██╗██║ ██║   ██║ ██║         ██║    ██╔══╝    ╚══════╝ ██║      ██╔══██║ ██║╚██╗██║
  ╚██████╔╝ ██║ ╚████║ ╚██████╔╝ ███████╗     ██║    ███████╗          ███████╗  ██║  ██║ ██║ ╚████║
   ╚═════╝ ╚═╝  ╚═══╝  ╚═════╝ ╚══════╝     ╚═╝    ╚══════╝          ╚══════╝  ╚═╝  ╚═╝ ╚═╝  ╚═══╝`

// printBanner shows the wordmark and a width-aware title bar on a live
// terminal. -q skips it. The banner stays in the scrollback once the watch
// takes over the screen.
func printBanner() {
	if !ux.TTY() {
		return
	}
	w := ux.Clamp(ux.Width()-2, 24, 78)
	line := "  " + strings.Repeat("═", w)
	fmt.Println(ux.C(ux.Dim, line))
	for _, r := range strings.Split(gnultelanLogo, "\n") {
		fmt.Println(ux.C(ux.Header, r))
	}
	fmt.Println("  " + ux.C(ux.Bold+ux.Header, "GNULTE-LAN v"+version) +
		ux.C(ux.Dim, "  ·  the live LAN watch — who is here, how fast, who talks to whom"))
	fmt.Println("  " + ux.C(ux.Dim, "passive watch only: counts packets and pings, never shapes or intercepts"))
	fmt.Println("  " + ux.C(ux.Dim, "screens: 1 hosts · 2 talkers · 3 flows (root) · 4 neighbours · each IP keeps one colour"))
	fmt.Println(ux.C(ux.Dim, line))
	fmt.Println()
}

// purpose returns the one-line "what is this for" text used by --help.
func purpose() string {
	return "gnulte-lan is the LAN watch: discover what is online, identify each device\n" +
		"  (MAC, vendor, type, hostname), watch its down/up speed, packet rate and latency\n" +
		"  live, see who is talking to whom (top talkers), and get flagged when a host\n" +
		"  crosses a rate or latency threshold. Run with no -t to watch the whole LAN.\n" +
		"  It is passive — frames are only counted, nothing is shaped or intercepted.\n\n" +
		"  With no arguments it auto-discovers the subnet (your host and the router are\n" +
		"  skipped). It is a four-screen console: 1 hosts · 2 talkers (ranked ↓/↑ with\n" +
		"  bars and peers) · 3 flows (per-pair conversations, needs the root capture\n" +
		"  socket) · 4 ARP neighbours. Keys: ↑↓ host · ⏎ detail · s sort · a alarm-only ·\n" +
		"  o settings · h help · q quit. Every IP keeps one stable colour across screens."
}
