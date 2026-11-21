package settings

import (
	"encoding/json"
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

// TestSanitizeClampsWifiCount: the settings UI and config comment advertise
// 1-256 frames per burst, so a crafted config must clamp to the same range.
func TestSanitizeClampsWifiCount(t *testing.T) {
	c := Default()
	c.WifiCount = 0
	c.Sanitize()
	if c.WifiCount != 1 {
		t.Fatalf("WifiCount = %d, want clamped up to 1", c.WifiCount)
	}
	c.WifiCount = 100000
	c.Sanitize()
	if c.WifiCount != 256 {
		t.Fatalf("WifiCount = %d, want clamped down to 256", c.WifiCount)
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

func TestV17SurfaceDefaults(t *testing.T) {
	d := Default()
	if d.HubDetailed {
		t.Fatalf("HubDetailed default = true, want false")
	}
	if !d.TopologyAnimation {
		t.Fatalf("TopologyAnimation default = false, want true")
	}
	if !d.Advanced {
		t.Fatalf("Advanced default changed: %+v", d)
	}
}

func TestV17JSONKeysAndOldKeyCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"hub_detailed":true,"topology_animation":false,"advanced":false,"history":120}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HubDetailed || got.TopologyAnimation || got.Advanced || got.History != 120 {
		t.Fatalf("v17 keys did not load as written: %+v", got)
	}

	if err := SaveTo(got, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"interface", "interval_sec", "timeout_ms", "beeps", "html_report",
		"scan_threads", "wifi_count", "wifi_delay_sec", "traffic_sec",
		"alarm_rate_kbps", "alarm_latency_ms", "probe_retries", "os_confidence",
		"uptime_guess", "rogue_flag", "arp_sweep", "stealth_arp",
		"wifi_jitter_ms", "wifi_mix_reasons", "wifi_hop", "wifi_channels",
		"advanced", "typing", "history", "service_discovery",
		"hub_detailed", "topology_animation", "auto_update",
	}
	for _, k := range wantKeys {
		if _, ok := keys[k]; !ok {
			t.Errorf("saved config is missing JSON key %q", k)
		}
	}
	if len(keys) != len(wantKeys) {
		t.Errorf("saved config has %d keys, want %d: %s", len(keys), len(wantKeys), raw)
	}
}

func TestV17KeysDefaultWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"interface":"auto"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.HubDetailed != Default().HubDetailed || got.TopologyAnimation != Default().TopologyAnimation {
		t.Fatalf("missing v17 keys did not use defaults: %+v", got)
	}
}

func TestAutoUpdateDefaultsTrueAndRoundTrips(t *testing.T) {
	if !Default().AutoUpdate {
		t.Fatal("AutoUpdate default = false, want true")
	}
	c := Default()
	c.AutoUpdate = false
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveTo(c, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if v, ok := saved["auto_update"]; !ok || v != false {
		t.Fatalf("saved auto_update = %v (present=%v), want false:\n%s", v, ok, data)
	}
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
	if got.AutoUpdate {
		t.Fatal("AutoUpdate = true after round trip, want false")
	}
}
