package ident

import (
	"os"
	"path/filepath"
	"testing"
)

// resetOverride clears the --oui-file layer so one test cannot leak into
// another (Vendor consults it before the embedded table).
func resetOverride() {
	ouiOverrideMu.Lock()
	ouiOverride = nil
	ouiOverrideMu.Unlock()
}

func TestLoadOUIFileCSV(t *testing.T) {
	defer resetOverride()
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.csv")
	body := "prefix,vendor\nB8:27:EB,Acme Custom Pi\nAA-BB-CC;Contoso Labs\nnot-a-prefix,Ignored\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadOUIFile(p)
	if err != nil {
		t.Fatalf("LoadOUIFile: %v", err)
	}
	if n != 2 {
		t.Fatalf("loaded %d entries, want 2", n)
	}
	if got := Vendor("B8:27:EB:00:00:01"); got != "Acme Custom Pi" {
		t.Errorf("comma override not applied: %q", got)
	}
	if got := Vendor("aa:bb:cc:11:22:33"); got != "Contoso Labs" {
		t.Errorf("semicolon override not applied: %q", got)
	}
	// The override layer must not disturb the built-in registry.
	if got := Vendor("AC:BC:32:00:00:01"); got != "Apple, Inc." {
		t.Errorf("built-in fallback broken: %q", got)
	}
	// A prefix with no override and no built-in entry still misses.
	if got := Vendor("02:00:00:00:00:01"); got != "" {
		t.Errorf("unregistered prefix = %q, want empty", got)
	}
}

func TestLoadOUIFileTextFormat(t *testing.T) {
	defer resetOverride()
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.txt")
	if err := os.WriteFile(p, []byte("00-00-2E   (hex)\t\tCISCO SYSTEMS\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadOUIFile(p)
	if err != nil || n != 1 {
		t.Fatalf("LoadOUIFile = %d, %v; want 1, nil", n, err)
	}
	if got := Vendor("00:00:2E:AA:BB:CC"); got != "CISCO SYSTEMS" {
		t.Errorf("IEEE text override: %q", got)
	}
}

func TestLoadOUIFileRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.csv")
	if err := os.WriteFile(p, []byte("just some prose, nothing usable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOUIFile(p); err == nil {
		t.Errorf("a file with no OUI entries should be rejected")
	}
	if _, err := LoadOUIFile(filepath.Join(dir, "missing.csv")); err == nil {
		t.Errorf("a missing file should error")
	}
}
