package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestActions(t *testing.T) {
	list := actions()
	if len(list) < 8 {
		t.Fatalf("only %d menu actions", len(list))
	}
	if list[len(list)-1].Binary != "" {
		t.Fatal("the last action must be Quit")
	}
	want := map[string]bool{
		"gnulte": false, "gnulte-quicksum": false, "gnulte-scan": false,
		"gnulte-inventory": false, "gnulte-watch": false, "gnulte-wifi": false,
		"gnulte-report": false,
	}
	for _, a := range list {
		if a.Binary == "" {
			continue
		}
		if _, ok := want[a.Binary]; !ok {
			t.Errorf("unexpected binary %q in menu", a.Binary)
		}
		want[a.Binary] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("menu has no action for %s", name)
		}
	}
}

func TestFindBinaryPrefersSibling(t *testing.T) {
	sibling := t.TempDir()
	onPath := t.TempDir()
	for _, dir := range []string{sibling, onPath} {
		if err := os.WriteFile(filepath.Join(dir, "gnulte"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", onPath)
	got := findBinary(sibling, "gnulte")
	if want := filepath.Join(sibling, "gnulte"); got != want {
		t.Errorf("findBinary = %q, want sibling %q", got, want)
	}
}

func TestFindBinaryFallsBackToPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gnulte-scan"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got := findBinary(t.TempDir(), "gnulte-scan")
	if want := filepath.Join(dir, "gnulte-scan"); got != want {
		t.Errorf("findBinary = %q, want PATH result %q", got, want)
	}
	if got := findBinary(t.TempDir(), "no-such-tool"); got != "" {
		t.Errorf("findBinary for missing tool = %q, want empty", got)
	}
}

func TestMenuItemsMarkMissing(t *testing.T) {
	list := actions()
	available := make([]bool, len(list))
	for i := range available {
		available[i] = true
	}
	available[0] = false
	items := menuItems(list, available)
	if items[0].Detail != "not installed" {
		t.Errorf("missing tool detail = %q", items[0].Detail)
	}
	if items[1].Detail != list[1].Detail {
		t.Errorf("available tool detail = %q, want %q", items[1].Detail, list[1].Detail)
	}
}
