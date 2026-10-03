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

// Package profiles stores user-defined impairment presets as small JSON files
// under ~/.config/gnulte-go/profiles, so a tuned set of values can be saved
// once and reused by name — the built-in presets stay compiled in and take
// precedence, these are the operator's own.
package profiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gnulte-go/internal/engine"
)

// nameRE keeps a profile name from escaping the folder (no "/", no "..").
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Dir is the user profiles folder, beside the settings and device files.
func Dir() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "gnulte-go/profiles"
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "gnulte-go", "profiles")
}

// Path is the file backing a named profile.
func Path(name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("invalid profile name %q (letters, digits, dot, dash, underscore)", name)
	}
	return filepath.Join(Dir(), name+".json"), nil
}

// Parse decodes and validates one profile document. The file is the same flat
// impairment shape the --per-target overrides use.
func Parse(data []byte) (engine.Impairment, error) {
	var p engine.Impairment
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return engine.Impairment{}, fmt.Errorf("profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return engine.Impairment{}, err
	}
	return p, nil
}

// Load reads a named profile. A missing file returns an os.IsNotExist error so
// the caller can fall back to the built-ins.
func Load(name string) (engine.Impairment, error) {
	path, err := Path(name)
	if err != nil {
		return engine.Impairment{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return engine.Impairment{}, err
	}
	p, err := Parse(data)
	if err != nil {
		return engine.Impairment{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Save writes a named profile and returns the file it created.
func Save(name string, p engine.Impairment) (string, error) {
	if err := p.Validate(); err != nil {
		return "", fmt.Errorf("cannot save profile: %w", err)
	}
	path, err := Path(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// List returns the saved profile names, sorted, ignoring anything that is not
// a .json file.
func List() ([]string, error) {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		if nameRE.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}
