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

	// The fields below are the "sweeper memory": what the last deep scan saw
	// and how long the host has been reachable across sweeps.
	Ports     []int    `json:"ports,omitempty"`     // last deep-scan TCP ports
	Banners   []string `json:"banners,omitempty"`   // last deep-scan banners
	OS        string   `json:"os,omitempty"`        // last OS guess
	Sightings int      `json:"sightings,omitempty"` // sweeps that saw this host
	AwakeSec  int      `json:"awake_sec,omitempty"` // accumulated reachable seconds
}

// MaxAwakeGap is the longest gap between sightings still credited as awake
// time. A host seen again within this window is treated as continuously up; a
// longer absence (or a first sighting) credits nothing, so a device that
// sleeps overnight is not reported as having been up all night.
const MaxAwakeGap = 10 * time.Minute

// PortChange is the port churn observed for one host between two sweeps.
type PortChange struct {
	IP       string
	Host     string
	Appeared []int
	Closed   []int
}

// Empty reports whether the change carries no port movement.
func (c PortChange) Empty() bool { return len(c.Appeared) == 0 && len(c.Closed) == 0 }

// PortDelta returns the ports present in cur but not prev (appeared) and those
// present in prev but not cur (closed), each ascending and duplicate-free.
func PortDelta(prev, cur []int) (appeared, closed []int) {
	p, c := intSet(prev), intSet(cur)
	for n := range c {
		if !p[n] {
			appeared = append(appeared, n)
		}
	}
	for n := range p {
		if !c[n] {
			closed = append(closed, n)
		}
	}
	sort.Ints(appeared)
	sort.Ints(closed)
	return appeared, closed
}

func intSet(ns []int) map[int]bool {
	m := make(map[int]bool, len(ns))
	for _, n := range ns {
		m[n] = true
	}
	return m
}

func sortedUnique(ns []int) []int {
	cp := append([]int(nil), ns...)
	sort.Ints(cp)
	if len(cp) == 0 {
		return []int{}
	}
	out := cp[:1]
	for _, n := range cp[1:] {
		if n != out[len(out)-1] {
			out = append(out, n)
		}
	}
	return out
}

// Sighting is one scan observation of a host: the identity fields of a Record
// plus the deep-scan detail (ports, banners, OS) the store remembers.
type Sighting struct {
	Record
	Ports   []int
	Banners []string
	OS      string
}

// RememberTo folds a batch of sightings into the store and saves once. For
// each host it counts the sighting, credits awake time for a plausible gap
// since the previous one, refreshes the remembered ports/banners/OS, and
// returns the port churn since the host's previous deep scan. A host whose
// previous record carried no port set establishes a baseline silently; only a
// movement against a known baseline is reported.
func RememberTo(path string, recs []Record, sightings []Sighting, now time.Time) ([]Record, []PortChange, error) {
	ts := now.UTC().Format(time.RFC3339)
	index := make(map[string]int, len(recs))
	for i := range recs {
		index[recs[i].IP] = i
	}
	var changes []PortChange
	for _, s := range sightings {
		i, ok := index[s.IP]
		if !ok {
			rec := s.Record
			rec.FirstSeen = ts
			rec.LastSeen = ts
			rec.Sightings = 1
			if s.Ports != nil {
				rec.Ports = sortedUnique(s.Ports)
			}
			rec.Banners = append([]string(nil), s.Banners...)
			if s.OS != "" {
				rec.OS = s.OS
			}
			recs = append(recs, rec)
			index[s.IP] = len(recs) - 1
			continue
		}
		rec := &recs[i]
		if rec.FirstSeen == "" {
			rec.FirstSeen = ts
		}
		if last, err := time.Parse(time.RFC3339, rec.LastSeen); err == nil {
			if gap := now.Sub(last); gap > 0 && gap <= MaxAwakeGap {
				rec.AwakeSec += int(gap / time.Second)
			}
		}
		rec.Sightings++
		if s.MAC != "" {
			rec.MAC = s.MAC
		}
		if s.Vendor != "" {
			rec.Vendor = s.Vendor
		}
		if s.Host != "" {
			rec.Host = s.Host
		}
		if s.Kind != "" {
			rec.Kind = s.Kind
		}
		rec.IsSelf = s.IsSelf
		if s.Ports != nil {
			appeared, closed := PortDelta(rec.Ports, s.Ports)
			if rec.Ports != nil && (len(appeared) > 0 || len(closed) > 0) {
				changes = append(changes, PortChange{IP: rec.IP, Host: rec.Host, Appeared: appeared, Closed: closed})
			}
			rec.Ports = sortedUnique(s.Ports)
		}
		if s.Banners != nil {
			rec.Banners = append([]string(nil), s.Banners...)
		}
		if s.OS != "" {
			rec.OS = s.OS
		}
		rec.LastSeen = ts
	}
	if err := SaveTo(path, recs); err != nil {
		return recs, nil, err
	}
	return recs, changes, nil
}

// FormatAwake renders accumulated awake seconds as "6h12m" (or "45m", "3d2h");
// an empty string means the host has not been seen twice in quick succession.
func FormatAwake(sec int) string {
	if sec <= 0 {
		return ""
	}
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd%dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
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