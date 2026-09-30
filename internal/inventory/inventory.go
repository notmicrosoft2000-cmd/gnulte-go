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

// Package inventory is the shared cross-tool device store of GNULTE 15
// "Live Interconnection": one JSON file under the user's config directory
// that every tool feeds and reads.
//
//	gnulte-lan    writes the live watch list (key x, and on a clean quit)
//	gnulte        offers "from last LAN watch" in the target picker
//	gnulte-scan   cross-references its -T table against the known inventory
//
// A device is keyed by IP address; re-seeing the same IP refreshes LastSeen
// instead of creating a duplicate.
package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Record is one device in the shared store.
type Record struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Host     string `json:"host,omitempty"`
	Kind     string `json:"kind,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"` // RFC3339
	LastSeen string `json:"last_seen,omitempty"`   // RFC3339
	IsSelf   bool   `json:"is_self,omitempty"`
}

// Path is the shared device file, e.g. ~/.config/gnulte-go/devices.json.
// It lives beside the settings file so all tools agree on the location.
func Path() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "gnulte-go/devices.json"
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "gnulte-go", "devices.json")
}

// Load reads the shared device store, returning an empty list (not an error)
// when the file does not exist yet.
func Load() ([]Record, error) { return LoadFrom(Path()) }

// LoadFrom reads the store from an explicit path (tests use this).
func LoadFrom(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var recs []Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("malformed device store %s: %w", path, err)
	}
	return recs, nil
}

// Save writes the store, creating its directory. Records are sorted by IP so
// the file is stable across runs.
func Save(recs []Record) error { return SaveTo(Path(), recs) }

// SaveTo writes the store to an explicit path (tests use this).
func SaveTo(path string, recs []Record) error {
	sort.Slice(recs, func(i, j int) bool { return recs[i].IP < recs[j].IP })
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Write-then-rename: a direct WriteFile truncates the target first, so a
	// second Ctrl+C (the v16 hard-kill) landing mid-write left the shared
	// device store as invalid JSON that every tool then refuses to read.
	// The temp file is created in the same directory so the rename is atomic
	// (never a cross-device copy).
	tmp, err := os.CreateTemp(dirOrDot(path), ".gnulte-store-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func dirOrDot(path string) string {
	if dir := filepath.Dir(path); dir != "" {
		return dir
	}
	return "."
}

// Update merges a sighting into the store: existing IPs refresh their detail
// and LastSeen in place, new IPs are appended, and the result is saved.
// devices is a display name used in the returned count message.
func Update(recs []Record, sighting Record, devices string) ([]Record, string, error) {
	return UpdateTo(recs, sighting, Path(), devices)
}

// UpdateTo is Update with an explicit store path (tests use this).
func UpdateTo(recs []Record, sighting Record, path, devices string) ([]Record, string, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	fresh := sighting
	fresh.LastSeen = now
	if fresh.FirstSeen == "" {
		fresh.FirstSeen = now
	}
	n := 0
	for i := range recs {
		if recs[i].IP == fresh.IP {
			if recs[i].FirstSeen == "" {
				recs[i].FirstSeen = fresh.FirstSeen
			}
			recs[i].MAC = fresh.MAC
			recs[i].Vendor = fresh.Vendor
			recs[i].Host = fresh.Host
			if fresh.Kind != "" {
				recs[i].Kind = fresh.Kind
			}
			recs[i].IsSelf = fresh.IsSelf
			recs[i].LastSeen = fresh.LastSeen
			n++
			break
		}
	}
	if n == 0 {
		recs = append(recs, fresh)
	}
	if err := SaveTo(path, recs); err != nil {
		return recs, "", err
	}
	return recs, fmt.Sprintf("live devices saved to %s (%d %s)", path, len(recs), devices),
		nil
}

// MergeList merges many sightings in one pass and saves once — the bulk
// counterpart of Update, used by gnulte-lan's "save the watch" and the
// auto-save on quit. It returns the merged store and how many records are new.
func MergeList(recs []Record, sightings []Record) ([]Record, int, error) {
	return MergeListTo(recs, Path(), sightings)
}

// MergeListTo is MergeList with an explicit store path (tests use this).
func MergeListTo(recs []Record, path string, sightings []Record) ([]Record, int, error) {
	fresh := make([]Record, 0, len(sightings))
	for _, s := range sightings {
		now := time.Now().UTC().Format(time.RFC3339)
		s.LastSeen = now
		if s.FirstSeen == "" {
			s.FirstSeen = now
		}
		fresh = append(fresh, s)
	}
	added := 0
	for _, f := range fresh {
		n := 0
		for i := range recs {
			if recs[i].IP == f.IP {
				if recs[i].FirstSeen == "" {
					recs[i].FirstSeen = f.FirstSeen
				}
				recs[i].MAC = f.MAC
				recs[i].Vendor = f.Vendor
				recs[i].Host = f.Host
				if f.Kind != "" {
					recs[i].Kind = f.Kind
				}
				recs[i].IsSelf = f.IsSelf
				recs[i].LastSeen = f.LastSeen
				n++
				break
			}
		}
		if n == 0 {
			recs = append(recs, f)
			added++
		}
	}
	if err := SaveTo(path, recs); err != nil {
		return recs, 0, err
	}
	return recs, added, nil
}

// Kinds returns the unique non-empty device kinds in the store, sorted — a
// one-word summary a picker can show ("router, phone, this host").
func Kinds(recs []Record) string {
	seen := map[string]bool{}
	var out []string
	for _, r := range recs {
		k := strings.TrimSpace(r.Kind)
		if k == "" {
			continue
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Summary renders a compact one-line description of the store.
func Summary(recs []Record) string {
	if len(recs) == 0 {
		return "no saved devices yet"
	}
	k := Kinds(recs)
	if k == "" {
		return fmt.Sprintf("%d device(s) saved", len(recs))
	}
	return fmt.Sprintf("%d device(s) — %s", len(recs), k)
}