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

package update

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeSource serves a canned VERSION text through a fake transport: the test
// opens no sockets and still exercises the real fetch and parse code.
func fakeSource(t *testing.T, body string) {
	t.Helper()
	oldURL, oldClient := sourceURL, httpClient
	t.Cleanup(func() { sourceURL, httpClient = oldURL, oldClient })
	sourceURL = "https://example.invalid/VERSION"
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})}
}

// fakeInstaller counts installer launches without running bash or depending
// on where the test binary happens to live.
func fakeInstaller(t *testing.T) *int {
	t.Helper()
	oldFind, oldRun := findInstaller, runInstaller
	attempts := 0
	t.Cleanup(func() { findInstaller, runInstaller = oldFind, oldRun })
	findInstaller = func() string { return "/nonexistent/update.sh" }
	runInstaller = func(string) error { attempts++; return nil }
	return &attempts
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{"equal", "17.0", "17.0", false},
		{"older", "17.1", "17.0", false},
		{"newer minor", "17.0", "17.1", true},
		{"newer major", "17.9", "18.0", true},
		{"leading v on latest", "17.0", "v17.1", true},
		{"leading v on current", "v17.0", "17.1", true},
		{"leading v equal", "v17.0", "17.0", false},
		{"malformed latest", "17.0", "banana", false},
		{"malformed current", "banana", "17.1", false},
		{"three parts", "17.0", "17.1.2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := compareVersions(tc.current, tc.latest); got != tc.want {
				t.Fatalf("compareVersions(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

func TestMaybeCheckSkipsFlagsAndEnv(t *testing.T) {
	flags := [][]string{
		{"-v"}, {"--version"}, {"-version"}, {"version"},
		{"-h"}, {"--help"}, {"help"}, {"--no-update-check"},
	}
	for _, args := range flags {
		t.Run(strings.Join(args, ","), func(t *testing.T) {
			t.Setenv("GNULTE_NO_UPDATE", "")
			fakeSource(t, "17.1\n")
			attempts := fakeInstaller(t)
			var out bytes.Buffer
			latest, accepted := maybeCheck("17.0", args, &out, strings.NewReader("y\n"), filepath.Join(t.TempDir(), "state.json"))
			if latest != "" || accepted {
				t.Fatalf("got (%q, %v), want empty/false", latest, accepted)
			}
			if *attempts != 0 {
				t.Fatalf("installer attempted %d times, want 0", *attempts)
			}
			if out.Len() != 0 {
				t.Fatalf("unexpected output %q", out.String())
			}
		})
	}

	t.Run("env", func(t *testing.T) {
		t.Setenv("GNULTE_NO_UPDATE", "1")
		fakeSource(t, "17.1\n")
		attempts := fakeInstaller(t)
		var out bytes.Buffer
		latest, accepted := maybeCheck("17.0", nil, &out, strings.NewReader("y\n"), filepath.Join(t.TempDir(), "state.json"))
		if latest != "" || accepted || *attempts != 0 || out.Len() != 0 {
			t.Fatalf("got (%q, %v, attempts=%d, output=%q), want all empty", latest, accepted, *attempts, out.String())
		}
	})
}

func TestMaybeCheckPrompt(t *testing.T) {
	t.Run("yes installs", func(t *testing.T) {
		t.Setenv("GNULTE_NO_UPDATE", "")
		fakeSource(t, "# release\n\nv17.1\n")
		attempts := fakeInstaller(t)
		var out bytes.Buffer
		latest, accepted := maybeCheck("17.0", nil, &out, strings.NewReader(" YES \n"), filepath.Join(t.TempDir(), "state.json"))
		if latest != "17.1" || !accepted {
			t.Fatalf("got (%q, %v), want (17.1, true)", latest, accepted)
		}
		if *attempts != 1 {
			t.Fatalf("installer attempted %d times, want 1", *attempts)
		}
		want := "\nGNULTE v17.0 — update available: v17.1. Install now? [y/N] "
		if out.String() != want {
			t.Fatalf("prompt %q, want %q", out.String(), want)
		}
	})

	t.Run("no declines", func(t *testing.T) {
		t.Setenv("GNULTE_NO_UPDATE", "")
		fakeSource(t, "17.1\n")
		attempts := fakeInstaller(t)
		path := filepath.Join(t.TempDir(), "state.json")
		var out bytes.Buffer
		latest, accepted := maybeCheck("17.0", nil, &out, strings.NewReader("\n"), path)
		if latest != "17.1" || accepted {
			t.Fatalf("got (%q, %v), want (17.1, false)", latest, accepted)
		}
		if *attempts != 0 {
			t.Fatalf("installer attempted %d times, want 0", *attempts)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var s state
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatal(err)
		}
		if s.DeclinedVersion != "17.1" || time.Since(s.DeclinedAt) > time.Minute {
			t.Fatalf("bad declined state: %+v", s)
		}
	})
}

func TestDeclinedCache(t *testing.T) {
	cases := []struct {
		name      string
		declined  time.Time
		wantTries int
	}{
		{"recent", time.Now().Add(-24 * time.Hour), 0},
		{"expired", time.Now().Add(-8 * 24 * time.Hour), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GNULTE_NO_UPDATE", "")
			fakeSource(t, "17.1\n")
			attempts := fakeInstaller(t)
			path := filepath.Join(t.TempDir(), "update-state.json")
			data, err := json.Marshal(state{DeclinedVersion: "17.1", DeclinedAt: tc.declined})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			latest, accepted := maybeCheck("17.0", nil, &out, strings.NewReader("y\n"), path)
			if *attempts != tc.wantTries {
				t.Fatalf("installer attempted %d times, want %d", *attempts, tc.wantTries)
			}
			if tc.wantTries == 0 {
				if latest != "" || accepted {
					t.Fatalf("got (%q, %v), want empty/false", latest, accepted)
				}
				if out.Len() != 0 {
					t.Fatalf("unexpected output %q", out.String())
				}
				return
			}
			if latest != "17.1" || !accepted {
				t.Fatalf("got (%q, %v), want (17.1, true)", latest, accepted)
			}
		})
	}
}
