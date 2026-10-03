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

package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gnulte-go/internal/engine"
)

func TestSaveLoadListRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	want := engine.Impairment{LatencyMS: 120, JitterMS: 30, LossPct: 4, BandwidthKbps: 2048}
	path, err := Save("my-tuned", want)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("gnulte-go", "profiles", "my-tuned.json")) {
		t.Fatalf("unexpected profile path %q", path)
	}
	got, err := Load("my-tuned")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}
	names, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "my-tuned" {
		t.Fatalf("List = %v, want [my-tuned]", names)
	}
}

func TestListIgnoresNonProfiles(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	dir := Dir()
	if err := os.MkdirAll(filepath.Join(dir, "sub.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Save("b", engine.Impairment{LatencyMS: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Save("a", engine.Impairment{LatencyMS: 2}); err != nil {
		t.Fatal(err)
	}
	names, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("List = %v, want [a b]", names)
	}
}

func TestPathRejectsTraversal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, bad := range []string{"", "../escape", "a/b", ".hidden", "has space"} {
		if _, err := Path(bad); err == nil {
			t.Errorf("Path(%q) should be rejected", bad)
		}
	}
}

func TestLoadMissingIsNotExist(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := Load("nope"); !os.IsNotExist(err) {
		t.Fatalf("Load(missing) = %v, want an IsNotExist error", err)
	}
}

func TestParseRejectsBadProfiles(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field": `{"latancy":5}`,
		"negative":      `{"latency":-1}`,
		"loss over 100": `{"loss":60,"dup":50}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
	if p, err := Parse([]byte(`{"latency":10,"loss":2}`)); err != nil || p.LossPct != 2 {
		t.Fatalf("Parse(valid) = %+v, %v", p, err)
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := Save("bad", engine.Impairment{LossPct: 60, DupPct: 50}); err == nil {
		t.Fatal("Save should refuse an invalid impairment")
	}
	if _, err := Save("../escape", engine.Impairment{LatencyMS: 1}); err == nil {
		t.Fatal("Save should refuse a traversal name")
	}
}
