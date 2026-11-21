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

// Package update performs the quiet startup update check shared by the GNULTE
// executables. It only prompts in an interactive terminal, only when the user
// has left update checks enabled, and never downloads anything by itself.
package update

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gnulte-go/internal/settings"
	"gnulte-go/internal/tui"
	"gnulte-go/internal/ux"
)

const (
	declineWindow    = 7 * 24 * time.Hour
	installerMissing = "Installer not found. Run: sudo ./update.sh from the GNULTE source tree."
)

var (
	// sourceURL is a var so tests can point the check at a harmless endpoint.
	sourceURL = "https://raw.githubusercontent.com/notmicrosoft2000-cmd/gnulte/main/VERSION"
	// httpClient is overridden in tests with a fake transport (no sockets).
	httpClient = &http.Client{Timeout: 2 * time.Second}
	// findInstaller and runInstaller are overridden in tests to observe
	// install attempts without touching the filesystem or launching bash.
	findInstaller = discoverInstaller
	runInstaller  = launchInstaller
)

// state is the on-disk record of a declined update.
type state struct {
	DeclinedVersion string    `json:"declined_version"`
	DeclinedAt      time.Time `json:"declined_at"`
}

// version is a numeric MAJOR.MINOR pair.
type version struct {
	major int
	minor int
}

func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		s = s[1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return version{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return version{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return version{}, false
	}
	return version{major: major, minor: minor}, true
}

func (v version) String() string { return fmt.Sprintf("%d.%d", v.major, v.minor) }

func (v version) newer(other version) bool {
	if v.major != other.major {
		return v.major > other.major
	}
	return v.minor > other.minor
}

// compareVersions reports whether latest is newer than current. Malformed
// versions are never treated as newer.
func compareVersions(current, latest string) bool {
	cur, ok := parseVersion(current)
	if !ok {
		return false
	}
	got, ok := parseVersion(latest)
	if !ok {
		return false
	}
	return got.newer(cur)
}

// fetchLatest reads the first non-empty, non-comment line of the published
// VERSION file. Any failure is reported as "no update" to the caller.
func fetchLatest() (string, bool) {
	resp, err := httpClient.Get(sourceURL)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		v, ok := parseVersion(line)
		if !ok {
			return "", false
		}
		return v.String(), true
	}
	return "", false
}

func loadState(path string) state {
	data, err := os.ReadFile(path)
	if err != nil {
		return state{}
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return state{}
	}
	return s
}

func saveState(path, latest string) error {
	data, err := json.MarshalIndent(state{
		DeclinedVersion: latest,
		DeclinedAt:      time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func discoverInstaller() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		path := filepath.Join(filepath.Dir(exe), "update.sh")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	if info, err := os.Stat("update.sh"); err == nil && !info.IsDir() {
		if abs, err := filepath.Abs("update.sh"); err == nil {
			return abs
		}
		return "update.sh"
	}
	return ""
}

func launchInstaller(path string) error {
	cmd := exec.Command("bash", path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// maybeCheck contains the whole check behind injectable output, input and
// state path so it can be tested without a terminal or a network connection.
// It returns the normalized latest version and whether the user accepted.
func maybeCheck(current string, args []string, out io.Writer, in io.Reader, statePath string) (string, bool) {
	if os.Getenv("GNULTE_NO_UPDATE") != "" {
		return "", false
	}
	for _, arg := range args {
		switch arg {
		case "-v", "--version", "-version", "version", "-h", "--help", "help", "--no-update-check":
			return "", false
		}
	}

	latest, ok := fetchLatest()
	if !ok || !compareVersions(current, latest) {
		return "", false
	}

	s := loadState(statePath)
	if s.DeclinedVersion == latest && time.Since(s.DeclinedAt) < declineWindow {
		return "", false
	}

	fmt.Fprintf(out, "\nGNULTE v%s — update available: v%s. Install now? [y/N] ", current, latest)
	answer, _ := bufio.NewReader(in).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	accepted := answer == "y" || answer == "yes"

	if !accepted {
		_ = saveState(statePath, latest)
		return latest, false
	}

	if path := findInstaller(); path != "" {
		if err := runInstaller(path); err != nil {
			fmt.Fprintf(out, "Update failed: %v\n", err)
		}
	} else {
		fmt.Fprintln(out, installerMissing)
	}
	return latest, true
}

// MaybeCheck offers an update at startup when running interactively and the
// user has not disabled checks. It returns silently on every skip or error.
func MaybeCheck(current string, args []string) {
	if os.Getenv("GNULTE_NO_UPDATE") != "" {
		return
	}
	if !ux.TTY() || !tui.StdinTTY() {
		return
	}
	cfg, err := settings.Load()
	if err != nil || !cfg.AutoUpdate {
		return
	}
	statePath := filepath.Join(filepath.Dir(settings.Path()), "update-state.json")
	_, _ = maybeCheck(current, args, os.Stdout, os.Stdin, statePath)
}
