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
	"os"
	"strings"

	"gnulte-go/internal/snapshot"
)

// runCompare diffs two report JSON snapshots and prints a human "what changed"
// listing; with outPath set it also writes an HTML version. It is driven by
// `gnulte --compare A B` (or `--compare A,B`) and the snapshots are the `-j`
// exports of gnulte-scan / gnulte-devices. It needs no network, no root and no
// acceptance gate — it only reads files the operator already has.
func runCompare(aPath string, rest []string, outPath string) error {
	bPath := ""
	if len(rest) > 0 {
		bPath = rest[0]
	} else if i := strings.IndexByte(aPath, ','); i >= 0 {
		aPath, bPath = aPath[:i], aPath[i+1:]
	}
	aPath, bPath = strings.TrimSpace(aPath), strings.TrimSpace(bPath)
	if aPath == "" || bPath == "" {
		return fmt.Errorf("--compare needs two snapshot files: gnulte --compare A.json B.json")
	}

	a, err := snapshot.Load(aPath)
	if err != nil {
		return fmt.Errorf("A: %w", err)
	}
	b, err := snapshot.Load(bPath)
	if err != nil {
		return fmt.Errorf("B: %w", err)
	}
	d := snapshot.Compare(a, b)
	snapshot.Render(os.Stdout, aPath, bPath, d)

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(snapshot.HTML(aPath, bPath, d)), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		fmt.Fprintf(os.Stderr, "GNULTE compare report written to %s\n", outPath)
	}
	return nil
}
