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

// Package settings stores the GNULTE tools' persisted defaults in the user's
// config directory and renders them in a small full-screen terminal editor
// (see ui.go). Every binary reads the same file, so one settings screen
// covers the whole toolkit.
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the merged default set shared by the GNULTE tools.
type Config struct {
	Interface    string `json:"interface"`      // preferred NIC (auto-detect when empty)
	IntervalSec  int    `json:"interval_sec"`   // monitor + traffic refresh, 1-60
	TimeoutMs    int    `json:"timeout_ms"`     // per-ping timeout, 100-60000
	Beeps        bool   `json:"beeps"`          // latency-pitched ping beeps
	HTMLReport   bool   `json:"html_report"`    // write the post-test HTML report
	ScanThreads  int    `json:"scan_threads"`   // parallel ping workers, 1-512
	WifiCount    int    `json:"wifi_count"`     // 802.11 frames per burst, 1-256
	WifiDelaySec int    `json:"wifi_delay_sec"` // seconds between bursts, 1-60
	TrafficSec   int    `json:"traffic_sec"`    // gnulte-traffic update interval, 1-10

	// SCANLTE technical tuning (v12).
	ProbeRetries int  `json:"probe_retries"` // deep-scan retries per open port, 1-5
	OSConfidence bool `json:"os_confidence"` // show a confidence % beside OS guesses
	UptimeGuess  bool `json:"uptime_guess"`  // estimate host uptime from TCP timestamps
	RogueFlag    bool `json:"rogue_flag"`    // flag ICMP-alive hosts with no ARP record
	ArpSweep     bool `json:"arp_sweep"`     // find hosts via ARP sweep when running privileged
	StealthArp   bool `json:"stealth_arp"`   // gnulte: in-Go on-demand ARP spoofing (discreet)

	// GNULTE-WIFI tuning (v13).
	WifiJitterMs   int    `json:"wifi_jitter_ms"`   // random 0-N ms delay between frames, 0-100
	WifiMixReasons bool   `json:"wifi_mix_reasons"` // rotate deauth reason codes per burst
	WifiHop        bool   `json:"wifi_hop"`         // hop channels between bursts
	WifiChannels   string `json:"wifi_channels"`    // comma-separated hop list, e.g. "1,6,11"

	// Toolkit session UX (v13).
	Advanced         bool `json:"advanced"`          // echo the exact command lines gnulte runs as they run
	Typing           bool `json:"typing"`            // typewriter animation for the interactive confirmation
	History          int  `json:"history"`           // ping samples kept per target in the monitors (10-240)
	ServiceDiscovery bool `json:"service_discovery"` // gnulte-scan: mDNS/DNS-SD service discovery (Avahi-style)
}

// Default returns the built-in defaults, used when no config file exists.
func Default() Config {
	return Config{
		Interface:    "",
		IntervalSec:  1,
		TimeoutMs:    1000,
		Beeps:        true,
		HTMLReport:   true,
		ScanThreads:  64,
		WifiCount:    64,
		WifiDelaySec: 5,
		TrafficSec:   1,

		ProbeRetries: 1,
		OSConfidence: true,
		UptimeGuess:  true,
		RogueFlag:    true,
		ArpSweep:     true,
		StealthArp:   false,

		WifiJitterMs:   2,
		WifiMixReasons: true,
		WifiHop:        false,
		WifiChannels:   "1,6,11",

		Advanced:         true, // the command transcript stays visible unless asked to switch off
		Typing:           true,
		History:          60,
		ServiceDiscovery: true,
	}
}

// Path is the per-user settings file, e.g. ~/.config/gnulte-go/config.json.
func Path() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "gnulte-go/config.json"
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "gnulte-go", "config.json")
}

// Load reads the config file, or returns the defaults when it is missing.
func Load() (Config, error) { return LoadFrom(Path()) }

// LoadFrom reads a config file from an explicit path (tests use this).
func LoadFrom(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("malformed settings file %s: %w", path, err)
	}
	c.Sanitize()
	return c, nil
}

// Save writes the config file, creating its directory.
func Save(c Config) error { return SaveTo(c, Path()) }

// SaveTo writes a config file to an explicit path (tests use this).
func SaveTo(c Config, path string) error {
	c.Sanitize()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Sanitize clamps every field into its documented range so a hand-edited file
// cannot feed a nonsense value to the tools.
func (c *Config) Sanitize() {
	c.IntervalSec = clamp(c.IntervalSec, 1, 60)
	c.TimeoutMs = clamp(c.TimeoutMs, 100, 60000)
	c.ScanThreads = clamp(c.ScanThreads, 1, 512)
	c.WifiCount = clamp(c.WifiCount, 1, 256)
	c.WifiDelaySec = clamp(c.WifiDelaySec, 1, 60)
	c.TrafficSec = clamp(c.TrafficSec, 1, 10)
	c.ProbeRetries = clamp(c.ProbeRetries, 1, 5)
	c.WifiJitterMs = clamp(c.WifiJitterMs, 0, 100)
	c.History = clamp(c.History, 10, 240)
	if strings.TrimSpace(c.WifiChannels) == "" {
		c.WifiChannels = "1,6,11"
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
