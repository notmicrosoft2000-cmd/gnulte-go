// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.

package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gnulte-go/internal/snapshot"
)

func TestParseName(t *testing.T) {
	cases := []struct {
		base              string
		tool, stamp, kind string
		count             int
		ok                bool
	}{
		{"gnulte-go-scan-report-20260928-151204-3.html", "gnulte-go-scan", "20260928-151204", "html", 3, true},
		{"gnulte-scan-report-20260912-160312.html", "gnulte-scan", "20260912-160312", "html", 0, true},
		{"gnulte-watch-report-20261001-120000-5.json", "gnulte-watch", "20261001-120000", "json", 5, true},
		{"before.json", "", "", "", 0, false},
		{"gnulte-report-20260912-160312", "", "", "", 0, false},
		{"gnulte-scan-report-bad.html", "", "", "", 0, false},
	}
	for _, c := range cases {
		tool, stamp, count, kind, ok := parseName(c.base)
		if ok != c.ok || tool != c.tool || stamp != c.stamp || count != c.count || kind != c.kind {
			t.Errorf("parseName(%q) = %q,%q,%d,%q,%v; want %q,%q,%d,%q,%v",
				c.base, tool, stamp, count, kind, ok, c.tool, c.stamp, c.count, c.kind, c.ok)
		}
	}
}

func TestDiscoverSortsAndIgnores(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"gnulte-scan-report-20260101-010101.html",
		"gnulte-watch-report-20260303-030303-4.html",
		"gnulte-go-scan-report-20260202-020202-2.json",
		"notes.txt",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := Discover(dir, filepath.Join(dir, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}
	want := []string{"gnulte-watch", "gnulte-go-scan", "gnulte-scan"}
	for i, tool := range want {
		if entries[i].Tool != tool {
			t.Errorf("entry %d tool = %q, want %q", i, entries[i].Tool, tool)
		}
	}
	if entries[0].Count != 4 || entries[0].Kind != "html" {
		t.Errorf("first entry = %+v, want count 4 html", entries[0])
	}
}

func writeSnapshot(t *testing.T, path, payload string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMergeFillsGapsAndCombinesBanners(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	writeSnapshot(t, a, `[
		{"ip":"10.0.0.1","hostname":"printer","banners":["SSH-2.0-OpenSSH"],"ports":"22/open/tcp/ssh"},
		{"ip":"10.0.0.2","vendor":"Acme"}
	]`)
	writeSnapshot(t, b, `[
		{"ip":"10.0.0.1","vendor":"Canon","banners":["HTTP/1.1 200","SSH-2.0-OpenSSH"],"ports":"80/open/tcp/http"},
		{"ip":"10.0.0.3","hostname":"nas"}
	]`)

	got, err := Merge([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d devices, want 3: %+v", len(got), got)
	}
	// IPs sorted lexically.
	if got[0].IP != "10.0.0.1" || got[1].IP != "10.0.0.2" || got[2].IP != "10.0.0.3" {
		t.Fatalf("unexpected order: %+v", got)
	}
	first := got[0]
	if first.Hostname != "printer" || first.Vendor != "Canon" {
		t.Errorf("merge lost a field: %+v", first)
	}
	if first.Ports != "80/open/tcp/http" {
		t.Errorf("later ports should win, got %q", first.Ports)
	}
	if len(first.Banners) != 2 || first.Banners[0] != "SSH-2.0-OpenSSH" || first.Banners[1] != "HTTP/1.1 200" {
		t.Errorf("banners should union without dupes, got %v", first.Banners)
	}
	if got[1].Vendor != "Acme" {
		t.Errorf("earlier-only device damaged: %+v", got[1])
	}
}

func TestMergeEmptyAndBadFile(t *testing.T) {
	if _, err := Merge(nil); err == nil {
		t.Error("Merge(nil) should fail")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	writeSnapshot(t, bad, `not json`)
	if _, err := Merge([]string{bad}); err == nil {
		t.Error("Merge with malformed JSON should fail")
	}
}

func TestWriteJSONRoundTripsThroughSnapshot(t *testing.T) {
	devices := []snapshot.Device{{IP: "10.0.0.9", Hostname: "cam", Ports: "80/open/tcp/http"}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, devices); err != nil {
		t.Fatal(err)
	}
	back, err := snapshot.Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("snapshot.Parse(WriteJSON(...)): %v", err)
	}
	if len(back) != 1 || back[0].IP != "10.0.0.9" || back[0].Hostname != "cam" {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestArchiveUsesStampAndAvoidsOverwrite(t *testing.T) {
	root := t.TempDir()
	src := t.TempDir()
	f1 := filepath.Join(src, "gnulte-scan-report-20261118-093000.html")
	f2 := filepath.Join(src, "custom.html")
	writeSnapshot(t, f1, "one")
	writeSnapshot(t, f2, "two")

	got, err := Archive(root, f1, f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d paths, want 3", len(got))
	}
	if !strings.Contains(got[0], filepath.Join("2026", "11")) {
		t.Errorf("stamp date not used: %s", got[0])
	}
	if got[1] == got[0] || !strings.Contains(got[1], "-2") {
		t.Errorf("duplicate should get a -2 suffix: %s", got[1])
	}
	data, err := os.ReadFile(got[0])
	if err != nil || string(data) != "one" {
		t.Fatalf("archived content wrong: %q, %v", data, err)
	}
	// custom.html has no stamp, so it falls back to mtime (this year).
	if !strings.Contains(got[2], filepath.Join("custom.html")) {
		t.Errorf("custom file name not kept: %s", got[2])
	}
}

func TestDateOfRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "2026", "2026XX18-093000", "20261318-093000"} {
		if got := dateOf(bad); got != "" {
			t.Errorf("dateOf(%q) = %q, want empty", bad, got)
		}
	}
	if got := dateOf("20261118-093000"); got != "2026/11" {
		t.Errorf("dateOf = %q", got)
	}
}

func TestIndexEscapesAndGroups(t *testing.T) {
	entries := []Entry{
		{Path: `/tmp/a&b/report.html`, Tool: "gnulte-scan", Stamp: "20261118-093000", Count: 4, Kind: "html"},
		{Path: "old.json", Tool: "gnulte-watch", Stamp: "20260101-010101", Kind: "json"},
	}
	page := Index(entries)
	for _, want := range []string{"gnulte-scan", "gnulte-watch", "2026-11-18 09:30:00", "a&amp;b", "4", "2 report(s)"} {
		if !strings.Contains(page, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if !strings.Contains(page, "gnulte-scan") || strings.Index(page, "gnulte-scan") > strings.Index(page, "gnulte-watch") {
		t.Error("tools should be sorted alphabetically")
	}
	if empty := Index(nil); !strings.Contains(empty, "none") {
		t.Error("empty index should say none")
	}
}
