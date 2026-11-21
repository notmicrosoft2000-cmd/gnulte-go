// GNULTE — network testing toolkit (Go).
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

import "gnulte-go/internal/tui"

// The simple front end asks what the operator wants to happen in plain
// language, then reuses the existing device picker, profiles and engine. A
// "no flags in a terminal" launch opens this instead of the twelve-profile
// technical wizard; every documented flag keeps its old behaviour.
type simpleChoice int

const (
	simpleShape simpleChoice = iota
	simpleBlock
	simpleAdvanced
	simpleQuit
)

func simpleMenuChoice() simpleChoice {
	idx, ok := tui.Menu("GNULTE — what do you want to do?", []tui.MenuItem{
		{Label: "Slow down a device", Detail: "pick a device, then pick how slow"},
		{Label: "Block a device", Detail: "cut its network completely"},
		{Label: "I know what I'm doing", Detail: "all the detailed settings"},
		{Label: "Quit", Detail: "start nothing"},
	})
	if !ok || idx == int(simpleQuit) {
		return simpleQuit
	}
	return simpleChoice(idx)
}

// simpleProfileChoice maps a plain "how slow" answer onto one of the existing
// preset profiles. The last row deliberately returns no profile: main then
// runs the full parameter wizard for anyone who wants exact numbers.
func simpleProfileChoice() (string, bool) {
	idx, ok := tui.Menu("How slow should it feel?", []tui.MenuItem{
		{Label: "A little laggy", Detail: "small stutter, still usable"},
		{Label: "Video calls break up", Detail: "choppy voice and picture"},
		{Label: "Web pages crawl", Detail: "slow browsing"},
		{Label: "Almost offline", Detail: "very hard to use"},
		{Label: "Let me choose numbers", Detail: "advanced"},
	})
	if !ok {
		return "", false
	}
	return simpleProfileForIndex(idx), true
}

func simpleProfileForIndex(idx int) string {
	switch idx {
	case 0:
		return "cellular"
	case 1:
		return "voip"
	case 2:
		return "web"
	case 3:
		return "extreme"
	default:
		return ""
	}
}
