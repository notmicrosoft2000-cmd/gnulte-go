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

// Package reportdir provides the shared "GNULTE Reports" hub where every tool
// files its post-test HTML report. The hub lives in the user's home directory
// and contains two per-tool subfolders so reports from the main toolkit and
// the SCANLTE scanner stay organized:
//
//	~/GNULTE Reports/GNULTE go!/gnulte-go-scan-report-20060102-150405-2.html
//	~/GNULTE Reports/Gnulte-scan/gnulte-scan-report-20060102-150405.html
package reportdir

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SubDir is the tool namespace within the hub.
type SubDir string

const (
	// GNULTEGo is the destination for the main gnulte toolkit.
	GNULTEGo SubDir = "GNULTE go!"
	// GnulteScan is the destination for the gnulte-scan (SCANLTE) reports.
	GnulteScan SubDir = "Gnulte-scan"
)

// Hub returns the hub directory (e.g. ~/GNULTE Reports). It does not create
// anything; fall back to the current directory when the home folder is
// unavailable (non-interactive or unusual processes).
func Hub() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", false
	}
	return filepath.Join(home, "GNULTE Reports"), true
}

// Sub returns the per-tool folder, creating the hub and subfolder as needed.
// A failure returns "". sub is validated against the known names so a typo can
// never create junk directories in the user's home.
func Sub(sub SubDir) (string, error) {
	switch sub {
	case GNULTEGo, GnulteScan:
	default:
		return "", fmt.Errorf("unknown report folder %q", sub)
	}
	base, ok := Hub()
	if !ok {
		return "", fmt.Errorf("could not resolve the home directory")
	}
	dir := filepath.Join(base, string(sub))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// Timestamp formats report filenames as YYYYMMDD-HHMMSS, matching the old
// session/report naming so existing tooling keeps working.
func Timestamp() string {
	return time.Now().Format("20060102-150405")
}

// DefaultPath returns the full path for a tool's auto-named report: the named
// subfolder inside the hub plus "<prefix>-<timestamp>.html". When the home
// directory is unavailable a cwd-relative path is returned instead (and never
// an error), so report generation is the last thing that ever breaks.
func DefaultPath(sub SubDir, prefix string) string {
	dir, err := Sub(sub)
	if err != nil {
		return fmt.Sprintf("%s-%s.html", prefix, Timestamp())
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%s.html", prefix, Timestamp()))
}

// DefaultPathCount is DefaultPath with the number of hosts or targets scanned
// folded into the name: "<prefix>-<timestamp>-<count>.html", so each report
// says what it contains at a glance (e.g. gnulte-go-scan-report-20260928-151204-3.html).
func DefaultPathCount(sub SubDir, prefix string, count int) string {
	dir, err := Sub(sub)
	if err != nil {
		return fmt.Sprintf("%s-%s-%d.html", prefix, Timestamp(), count)
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%s-%d.html", prefix, Timestamp(), count))
}
