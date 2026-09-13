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

package tui

import (
	"errors"
	"os"
)

func rawTerminal(fd int) (func(), bool) { return nil, false }

type keyStream struct{}

func newKeyStream(fd int) *keyStream { return &keyStream{} }

func (k *keyStream) read() (Key, rune) { return KeyNone, 0 }

// StdinTTY is platform-independent terminal detection.
func StdinTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var errNoInput = errors.New("terminal input is not supported here")
