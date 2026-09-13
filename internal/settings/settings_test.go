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
	c.Sanitize()
	if c.IntervalSec != 60 || c.TimeoutMs != 100 || c.ScanThreads != 1 || c.TrafficSec != 1 {
		t.Fatalf("clamping failed: %+v", c)
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
