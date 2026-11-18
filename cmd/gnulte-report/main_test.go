// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions. Licensed under the GPLv3.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVersionAndHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"-version"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "v17.0") {
		t.Errorf("version output wrong: %q", out.String())
	}
	out.Reset()
	if err := run([]string{"help"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "gnulte-report merge") {
		t.Errorf("help missing subcommands: %q", out.String())
	}
	out.Reset()
	if err := run([]string{"list", "-h"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "gnulte-report merge") {
		t.Errorf("subcommand -h should print usage: err=%v out=%q", err, out.String())
	}
	if err := run([]string{"bogus"}, &out, &errOut); err == nil {
		t.Error("unknown subcommand should fail")
	}
	if err := run(nil, &out, &errOut); err == nil {
		t.Error("no subcommand should fail")
	}
}

func TestListAndIndex(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "gnulte-scan-report-20261118-093000-3.html"), "x")
	writeFile(t, filepath.Join(dir, "ignore.txt"), "x")

	var out, errOut bytes.Buffer
	if err := run([]string{"list", dir}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "gnulte-scan") || !strings.Contains(out.String(), "2026-11-18 09:30:00") {
		t.Errorf("list output wrong: %q", out.String())
	}
	if strings.Contains(out.String(), "ignore.txt") {
		t.Error("list should skip non-report files")
	}

	idxPath := filepath.Join(dir, "index.html")
	out.Reset()
	if err := run([]string{"index", "-o", idxPath, dir}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<h1>GNULTE report index</h1>") {
		t.Errorf("index file wrong: %q", data)
	}
}

func TestMergeAndCompareRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	writeFile(t, a, `[{"ip":"10.0.0.1","hostname":"before"}]`)
	writeFile(t, b, `[{"ip":"10.0.0.1","hostname":"after"},{"ip":"10.0.0.2"}]`)

	var out, errOut bytes.Buffer
	merged := filepath.Join(dir, "merged.json")
	if err := run([]string{"merge", "-o", merged, a, b}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"hostname": "after"`) {
		t.Errorf("merge should keep later hostname: %q", data)
	}

	// compare merged against a must show the added host and the rename.
	out.Reset()
	if err := run([]string{"compare", merged, a}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "GNULTE compare") || !strings.Contains(got, "10.0.0.2") || !strings.Contains(got, "hostname") {
		t.Errorf("compare output wrong: %q", got)
	}

	// comma form and -html both work.
	out.Reset()
	htmlPath := filepath.Join(dir, "diff.html")
	if err := run([]string{"compare", "-html", htmlPath, merged + "," + a}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(htmlPath); err != nil {
		t.Errorf("compare -html did not write file: %v", err)
	}
}

func TestArchiveSubcommand(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "gnulte-watch-report-20261001-120000.html")
	writeFile(t, src, "report body")
	root := filepath.Join(dir, "archive")

	var out, errOut bytes.Buffer
	if err := run([]string{"archive", "-dest", root, src}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSpace(out.String())
	if !strings.Contains(path, filepath.Join("2026", "10")) {
		t.Errorf("archive output path wrong: %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "report body" {
		t.Errorf("archived content wrong: %q, %v", data, err)
	}
}

func TestFlagsAfterFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	writeFile(t, a, `[{"ip":"10.0.0.1"}]`)

	var out, errOut bytes.Buffer
	merged := filepath.Join(dir, "merged.json")
	// -o after the positional file name used to be mistaken for a filename.
	if err := run([]string{"merge", a, "-o", merged}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(merged); err != nil {
		t.Errorf("merge with trailing -o did not write %s: %v", merged, err)
	}

	src := filepath.Join(dir, "gnulte-scan-report-20261118-090000.html")
	writeFile(t, src, "body")
	root := filepath.Join(dir, "archive")
	out.Reset()
	if err := run([]string{"archive", src, "-dest", root}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2026") {
		t.Errorf("archive with trailing -dest failed: %q", out.String())
	}
}

func TestArgumentErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{"merge"},
		{"compare"},
		{"archive"},
		{"compare", "only-one.json"},
	} {
		if err := run(args, &out, &errOut); err == nil {
			t.Errorf("run(%v) should fail", args)
		}
	}
}
