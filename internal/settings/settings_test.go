package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.Interface = "wlan0"
	c.IntervalSec = 2
	c.TimeoutMs = 1500
	c.Beeps = false
	c.ScanThreads = 128
	c.WifiCount = 32
	c.WifiDelaySec = 9
	c.TrafficSec = 5
	if err := SaveTo(c, path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
}

func TestLoadMissingGivesDefaults(t *testing.T) {
	c, err := LoadFrom(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c != Default() {
		t.Fatalf("expected defaults, got %+v", c)
	}
}

func TestSanitizeClampsOutOfRange(t *testing.T) {
	if err := os.WriteFile(filepath.Join(t.TempDir(), "x"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.IntervalSec = 999
	c.TimeoutMs = 1
	c.ScanThreads = -5
	c.TrafficSec = 0
	c.History = 5
	c.Sanitize()
	if c.IntervalSec != 60 || c.TimeoutMs != 100 || c.ScanThreads != 1 || c.TrafficSec != 1 {
		t.Fatalf("clamping failed: %+v", c)
	}
	if c.History != 10 {
		t.Fatalf("History not clamped to 10, got %d", c.History)
	}
	c.History = 999
	c.Sanitize()
	if c.History != 240 {
		t.Fatalf("History not clamped to 240, got %d", c.History)
	}
}

func TestV13UXDefaults(t *testing.T) {
	// New UX toggles should not silently ship disabled.
	d := Default()
	if !d.Advanced || !d.Typing || !d.ServiceDiscovery {
		t.Fatalf("new UX toggles default off: %+v", d)
	}
	if d.History != 60 {
		t.Fatalf("History default = %d, want 60", d.History)
	}
}

func TestV13UXFieldsRoundTrip(t *testing.T) {
	// Non-default v13 values survive a save/load (guards against a forgotten
	// JSON tag or a load path that skips the new fields).
	c := Default()
	c.Advanced = false
	c.Typing = false
	c.ServiceDiscovery = false
	c.History = 120
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveTo(c, path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	path := filepath.Join(dir, "config.json")
	if err := SaveTo(Default(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
